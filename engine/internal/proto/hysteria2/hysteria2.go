// Package hysteria2 wraps the sing-quic Hysteria2 client as a tunnel.Device.
//
// Hysteria2 is QUIC with Brutal congestion control: instead of inferring
// bandwidth from loss, the client declares its up/down BPS and the sender paces
// to it. On a lossy mobile link that is the difference between 8 Mbit/s and
// 60 Mbit/s, because loss-based CC reads radio jitter as a congestion signal.
//
// This package deliberately delegates the protocol to sing-quic rather than
// reimplementing it: Brutal, salamander obfuscation and port hopping are each
// subtle enough that a hand-rolled version would look right and perform badly.
package hysteria2

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"tuntrail/internal/config"
	"tuntrail/internal/tunnel"
)

// Minimum speeds Brutal will accept. Below this the protocol refuses to start,
// because a tiny declared rate produces a pacer that cannot fill an MSS.
const minBPS = 8 * 1024

// Device is a live Hysteria2 client.
type Device struct {
	client *hysteria.Client

	rx          atomic.Uint64
	tx          atomic.Uint64
	handshakeMS atomic.Uint32

	closeOnce sync.Once
	closed    chan struct{}
}

// New builds the QUIC session options from a profile.
//
// The speed hints matter: they are what Brutal paces against, so they should be
// roughly the real link capacity. Too low wastes the connection, too high makes
// the pacer overshoot into loss.
func New(ctx context.Context, p *config.Profile, protect func(fd int) bool) (*Device, error) {
	if p.Hysteria2 == nil {
		return nil, errors.New("hysteria2: profile has no hysteria2 block")
	}
	h := p.Hysteria2

	if h.Server == "" {
		return nil, errors.New("hysteria2: server is required")
	}
	if h.Password == "" {
		return nil, errors.New("hysteria2: password is required")
	}
	port := h.Port
	if port == 0 {
		port = 443
	}

	upMbps := h.UpMbps
	downMbps := h.DownMbps
	if upMbps <= 0 {
		upMbps = 50
	}
	if downMbps <= 0 {
		downMbps = 200
	}
	sendBPS := uint64(upMbps) * 1000 * 1000 / 8
	recvBPS := uint64(downMbps) * 1000 * 1000 / 8
	if sendBPS < minBPS {
		sendBPS = minBPS
	}
	if recvBPS < minBPS {
		recvBPS = minBPS
	}

	sni := h.SNI
	if sni == "" {
		sni = h.Server
	}

	tlsConf := &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: h.Insecure,
	}

	// The sing aTLS.Config wrapper is what the library expects; it adds the
	// methods Hysteria2 needs (Client, ServerName, NextProtos).
	cfg := &tlsConfig{cfg: tlsConf}

	dialer := &protectedDialer{protect: protect, timeout: 10 * time.Second}

	serverAddr := M.ParseSocksaddrHostPortStr(h.Server, strconv.Itoa(int(port)))

	client, err := hysteria.NewClient(hysteria.ClientOptions{
		Context:       ctx,
		Dialer:        dialer,
		Logger:        logger.NOP(),
		ServerAddress: serverAddr,
		Password:      h.Password,
		SendBPS:       sendBPS,
		ReceiveBPS:    recvBPS,
		TLSConfig:     cfg,
		QUICOptions: qtls.QUICOptions{
			// A larger initial packet size fills the first flight better on a
			// high-RTT link; PMTU discovery then raises it from here.
			InitialPacketSize:       1350,
			DisablePathMTUDiscovery: false,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}

	return &Device{
		client: client,
		closed: make(chan struct{}),
	}, nil
}

// Dial opens one QUIC stream to addr.
func (d *Device) Dial(ctx context.Context, network, addr string) (tunnel.Conn, error) {
	select {
	case <-d.closed:
		return nil, tunnel.ErrClosed
	default:
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: split %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("hysteria2: bad port in %q", addr)
	}

	dest := M.ParseSocksaddrHostPortStr(host, strconv.Itoa(port))

	start := time.Now()
	c, err := d.client.DialConn(ctx, dest)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: %v", tunnel.ErrUnreachable, err)
		}
		return nil, fmt.Errorf("hysteria2: dial %s: %w", addr, err)
	}
	d.handshakeMS.Store(uint32(time.Since(start).Milliseconds()))

	return &countingConn{Conn: c, rx: &d.rx, tx: &d.tx}, nil
}

// Stats reports counters.
func (d *Device) Stats() tunnel.Stats {
	return tunnel.Stats{
		RxBytes:     d.rx.Load(),
		TxBytes:     d.tx.Load(),
		HandshakeMS: d.handshakeMS.Load(),
	}
}

// Close tears the QUIC session down.
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		_ = d.client.CloseWithError(nil)
	})
	return nil
}

type countingConn struct {
	tunnel.Conn
	rx *atomic.Uint64
	tx *atomic.Uint64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.rx.Add(uint64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.tx.Add(uint64(n))
	return n, err
}

// CloseWrite propagates half-close so a download can finish after the request
// side is done.
func (c *countingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// protectedDialer opens UDP sockets that Android's VpnService will not capture.
//
// This is the single most important Android integration point for Hysteria2: the
// QUIC socket carries the tunnel's own traffic, so if it enters the tun it feeds
// itself and deadlocks. VpnService.protect() on the fd breaks that loop.
type protectedDialer struct {
	protect func(fd int) bool
	timeout time.Duration
}

func (d *protectedDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	nd := &net.Dialer{Timeout: d.timeout}
	conn, err := nd.DialContext(ctx, network, destination.String())
	if err != nil {
		return nil, err
	}
	if err := d.applyProtect(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (d *protectedDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	lc := &net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp", "")
	if err != nil {
		return nil, err
	}
	if err := d.applyProtect(pc); err != nil {
		_ = pc.Close()
		return nil, err
	}
	return pc, nil
}

// applyProtect exempts the socket from the VPN it feeds. Without this the QUIC
// packets re-enter our own tun and the handshake loops forever.
func (d *protectedDialer) applyProtect(c any) error {
	if d.protect == nil {
		return nil
	}
	type syscallConner interface {
		SyscallConn() (interface {
			Control(func(fd uintptr)) error
		}, error)
	}
	sc, ok := c.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return nil
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return nil
	}
	var protectErr error
	_ = rc.Control(func(fd uintptr) {
		if !d.protect(int(fd)) {
			protectErr = errors.New("hysteria2: protect(fd) failed")
		}
	})
	return protectErr
}

var _ N.Dialer = (*protectedDialer)(nil)
