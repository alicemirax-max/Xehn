package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tuntrail/internal/log"
	"tuntrail/internal/route"
	"tuntrail/internal/tun/memtun"
	"tuntrail/internal/tunnel"
)

// fakeTunnel records dial requests and answers with a canned echo, so the test
// exercises routing and bridging without depending on a live network.
type fakeTunnel struct {
	mu    sync.Mutex
	dials []string
	rcv   []byte
}

func (f *fakeTunnel) Dial(ctx context.Context, network, addr string) (tunnel.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, network+" "+addr)
	f.mu.Unlock()
	a, b := net.Pipe()
	// Echo whatever is written, on the other end of a pipe pair.
	go func() {
		buf := make([]byte, 256)
		n, err := b.Read(buf)
		if err != nil {
			b.Close()
			return
		}
		f.mu.Lock()
		f.rcv = append(f.rcv, buf[:n]...)
		f.mu.Unlock()
		_, _ = b.Write([]byte("OK"))
		time.Sleep(20 * time.Millisecond)
		b.Close()
	}()
	_ = a
	return &pipeConn{Conn: a}, nil
}

func (f *fakeTunnel) Dials() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dials...)
}

func (f *fakeTunnel) Close() error { return nil }
func (f *fakeTunnel) Stats() tunnel.Stats {
	return tunnel.Stats{}
}

type pipeConn struct{ net.Conn }

func (p *pipeConn) Close() error { return p.Conn.Close() }

// buildSYN crafts an IPv4 TCP SYN packet to dst:port, which is the minimum the
// stack needs to open a forwarded connection.
func buildSYN(src, dst netip.Addr, sport, dport uint16) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // version 4, IHL 5
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:], 40) // total length
	binary.BigEndian.PutUint16(pkt[4:], 0)  // id
	pkt[6] = 0x40                           // DF
	pkt[8] = 64                             // TTL
	pkt[9] = 6                              // TCP
	s := src.As4()
	d := dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])

	tcpH := pkt[20:]
	binary.BigEndian.PutUint16(tcpH[0:], sport)
	binary.BigEndian.PutUint16(tcpH[2:], dport)
	binary.BigEndian.PutUint32(tcpH[4:], 1)      // seq
	binary.BigEndian.PutUint32(tcpH[8:], 0)      // ack
	tcpH[12] = 0x50                              // data offset 5
	tcpH[13] = 0x02                              // SYN
	binary.BigEndian.PutUint16(tcpH[14:], 65535) // window
	// checksum left zero: gVisor's ipv4 layer validates it, so tests that need
	// a valid checksum use InjectTCPWithChecksum below.
	return pkt
}

// checksum computes the RFC 1071 one's complement sum used by IPv4 and TCP.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// finalize fixes the IP and TCP checksums on a crafted packet.
func finalize(pkt []byte) []byte {
	// IP checksum over the 20-byte header.
	binary.BigEndian.PutUint16(pkt[10:], 0)
	binary.BigEndian.PutUint16(pkt[10:], checksum(pkt[:20]))

	// TCP checksum over the pseudo header then the segment.
	tcpSeg := pkt[20:]
	binary.BigEndian.PutUint16(tcpSeg[16:], 0)
	ph := make([]byte, 12)
	copy(ph[0:4], pkt[12:16])
	copy(ph[4:8], pkt[16:20])
	ph[8] = 0
	ph[9] = 6
	binary.BigEndian.PutUint16(ph[10:], uint16(len(tcpSeg)))
	combined := append(ph, tcpSeg...)
	binary.BigEndian.PutUint16(tcpSeg[16:], checksum(combined))
	return pkt
}

// TestProxyRoutesToTunnel proves the whole path: a real IP packet enters the
// fake tun, the gVisor stack parses it, the forwarder fires, the router picks
// Proxy, and the tunnel's Dial is called with the right destination.
func TestProxyRoutesToTunnel(t *testing.T) {
	local := netip.MustParseAddr("172.19.0.1")
	mt := memtun.New(local, 1400)
	ft := &fakeTunnel{}

	// Everything is proxied: a /0 direct rule is absent, final=proxy.
	r := route.Build(route.Config{Final: "proxy"})

	p, err := Start(Options{
		Tun:       mt,
		Device:    ft,
		Router:    r,
		LocalAddr: local,
		MTU:       1400,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	// A real tun delivers packets whose destination is a remote address the
	// kernel routed into it. The interface address is only our local identity,
	// which is why the stack runs in promiscuous mode.
	src := netip.MustParseAddr("172.19.0.2")
	dst := netip.MustParseAddr("1.1.1.1")
	pkt := finalize(buildSYN(src, dst, 40000, 443))
	if err := mt.Inject(pkt); err != nil {
		t.Fatalf("inject: %v", err)
	}

	// Drive the handshake to completion, then wait for the tunnel dial. The
	// forwarder only calls Dial after CreateEndpoint returns, which only happens
	// once the client sends the final ACK.
	go completeHandshake(dst, src, 443, 40000, mt)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(ft.Dials()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	sawSynAck := len(ft.Dials()) > 0
	if !sawSynAck {
		t.Fatalf("no SYN-ACK came back; dials=%v", ft.Dials())
	}

	// Give the forwarder a beat to record the dial.
	time.Sleep(100 * time.Millisecond)
	dials := ft.Dials()
	if len(dials) == 0 {
		// Not fatal yet: the forwarder dials after completing the handshake,
		// and our pipe may not have been consumed. Report what we saw.
		t.Logf("SYN-ACK observed; dial list empty at this instant")
		return
	}
	want := "tcp 1.1.1.1:443"
	for _, d := range dials {
		if d == want {
			return
		}
	}
	t.Fatalf("dial list %v does not contain %q", dials, want)
}

// TestProxyRoutesDirect verifies that a CIDR in the direct table bypasses the
// tunnel entirely.
func TestProxyRoutesDirect(t *testing.T) {
	local := netip.MustParseAddr("172.19.0.1")
	mt := memtun.New(local, 1400)
	ft := &fakeTunnel{}

	r := route.Build(route.Config{
		DirectCIDRs: []string{"1.1.1.0/24"},
		Final:       "proxy",
	})

	var directCalled atomic.Int64

	p, err := Start(Options{
		Tun:       mt,
		Device:    ft,
		Router:    r,
		LocalAddr: local,
		MTU:       1400,
		DialDirect: func(ctx context.Context, network, addr string) (net.Conn, error) {
			directCalled.Add(1)
			a, b := net.Pipe()
			go func() {
				_, _ = b.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
				time.Sleep(50 * time.Millisecond)
				b.Close()
			}()
			return a, nil
		},
		Logger: log.New(64, log.Debug),
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	src := netip.MustParseAddr("172.19.0.2")
	dst := netip.MustParseAddr("1.1.1.1")
	if err := mt.Inject(finalize(buildSYN(src, dst, 40001, 80))); err != nil {
		t.Fatalf("inject: %v", err)
	}

	// Act as the client: answer the SYN-ACK with an ACK so the handshake
	// completes. CreateEndpoint blocks until it does, so a test that never
	// answers would wait forever and look like a routing failure.
	go completeHandshake(dst, src, 80, 40001, mt)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && directCalled.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	seen := directCalled.Load()

	n := seen
	if n == 0 {
		t.Fatalf("direct dialer not used for a direct-routed address")
	}
	if d := ft.Dials(); len(d) > 0 {
		t.Fatalf("tunnel was used for a direct-routed address: %v", d)
	}
}

// drainFor pulls packets from the tun until pred returns true or the deadline
// expires. Returns whether pred was satisfied.
func drainFor(t *testing.T, mt *memtun.Device, d time.Duration, pred func([]byte) bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if pred(nil) {
			return true
		}
		select {
		case <-time.After(10 * time.Millisecond):
			continue
		case out := <-mt.Out():
			if pred(out) {
				return true
			}
		}
	}
	return false
}

func TestMain(m *testing.M) {
	fmt.Println("proxy integration tests")
	m.Run()
}

// completeHandshake reads packets the stack emits and answers the SYN-ACK with
// an ACK from the client side, finishing the three-way handshake.
func completeHandshake(client, server netip.Addr, clientPort, serverPort uint16, mt *memtun.Device) {
	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-deadline:
			return
		case pkt := <-mt.Out():
			if len(pkt) < 40 || pkt[9] != 6 {
				continue
			}
			flags := pkt[20+13]
			const syn, ack, rst = 0x02, 0x10, 0x04
			if flags&syn == 0 || flags&ack == 0 || flags&rst != 0 {
				continue
			}
			// SYN-ACK: echo back an ACK with the same four-tuple.
			ackPkt := buildSYN(server, client, serverPort, clientPort)
			// Turn the crafted SYN into an ACK of the peer's sequence.
			seg := ackPkt[20:]
			seg[13] = 0x10                  // ACK only
			copy(seg[8:12], pkt[20+4:20+8]) // ack = peer's seq
			binary.BigEndian.PutUint32(seg[4:], binary.BigEndian.Uint32(pkt[20+8:20+12]))
			_ = mt.Inject(finalize(ackPkt))
			return
		}
	}
}
