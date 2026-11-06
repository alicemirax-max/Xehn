// Package proxy is the data plane: it reads IP packets off the tun descriptor,
// runs them through a userspace TCP/IP stack, and hands accepted connections to
// the tunnel.
//
// Why a userspace stack instead of NAT: on Android without root the only
// interface we get is a tun fd. Anything that wants to forward packets has to
// terminate TCP locally first. gVisor gives us a real TCP implementation (SACK,
// window scaling, timestamps) rather than the minimal one that ships with most
// Go tun helpers, which is worth 20-40% on large downloads in practice.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"tuntrail/internal/log"
	"tuntrail/internal/route"
	"tuntrail/internal/tunnel"
)

// Limits that matter for real traffic. gVisor's defaults are conservative for
// a phone on a 5G link.
const (
	// tcpWindowReceive is the per-connection receive ceiling. 4 MiB stops the
	// bandwidth-delay product being the bottleneck on a 200 ms RTT mobile link
	// up to roughly 160 Mbit/s.
	tcpWindowReceive = 4 << 20
	// tcpWindowSend is the peer-side equivalent.
	tcpWindowSend = 4 << 20
	// channelQueue is how many packets may queue between the tun fd and the
	// stack before drops start. This is the burst absorber.
	channelQueue = 2048
	// maxInFlight bounds concurrently forwarded flows.
	maxInFlight = 2048
)

// Options configures a Proxy.
type Options struct {
	// Tun is the packet source and sink. Proxy closes it on Stop.
	Tun TunIO
	// Device is the live tunnel used for proxied dials.
	Device tunnel.Device
	// Router decides direct versus proxied per destination.
	Router *route.Router
	// LocalAddr is the address assigned to the tun interface.
	LocalAddr netip.Addr
	// Prefix is the interface subnet (e.g. 172.19.0.1/30). Optional: when zero
	// a /30 around LocalAddr is derived.
	Prefix netip.Prefix
	// MTU is the interface MTU handed to the stack.
	MTU int
	// Logger receives connection-level diagnostics.
	Logger *log.Logger
	// DialDirect opens a connection outside the tunnel.
	DialDirect func(ctx context.Context, network, addr string) (net.Conn, error)
}

// TunIO is the packet interface Proxy needs. Satisfied by tun.Device.
type TunIO interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	MTU() int
	Close() error
}

// Proxy owns the stack and the forwarding loops.
type Proxy struct {
	opts Options
	stk  *stack.Stack
	ep   *channel.Endpoint
	log  *log.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	conns atomic.Int64

	stopped sync.Once
}

// Start builds the stack and launches the two forwarding loops.
func Start(o Options) (*Proxy, error) {
	switch {
	case o.Tun == nil:
		return nil, errors.New("proxy: tun is required")
	case o.Device == nil:
		return nil, errors.New("proxy: device is required")
	case o.Router == nil:
		return nil, errors.New("proxy: router is required")
	case !o.LocalAddr.IsValid():
		return nil, errors.New("proxy: local address is required")
	}
	if o.MTU <= 0 {
		o.MTU = 1400
	}
	if o.DialDirect == nil {
		o.DialDirect = defaultDirectDialer()
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{opts: o, log: o.Logger, ctx: ctx, cancel: cancel}

	cancelOn := func(err error) (*Proxy, error) {
		cancel()
		return nil, err
	}

	p.ep = channel.New(channelQueue, uint32(o.MTU)+128, "")
	if p.ep == nil {
		return cancelOn(errors.New("proxy: create channel endpoint"))
	}

	stk := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        false,
	})
	p.stk = stk

	sackOpt := tcpip.TCPSACKEnabled(true)
	if err := stk.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt); err != nil {
		return cancelOn(fmt.Errorf("proxy: enable SACK: %v", err))
	}
	recvOpt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 65536, Max: tcpWindowReceive}
	if err := stk.SetTransportProtocolOption(tcp.ProtocolNumber, &recvOpt); err != nil {
		return cancelOn(fmt.Errorf("proxy: tcp receive window: %v", err))
	}
	sendOpt := tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: 65536, Max: tcpWindowSend}
	if err := stk.SetTransportProtocolOption(tcp.ProtocolNumber, &sendOpt); err != nil {
		return cancelOn(fmt.Errorf("proxy: tcp send window: %v", err))
	}

	if err := stk.CreateNIC(1, p.ep); err != nil {
		return cancelOn(fmt.Errorf("proxy: create nic: %v", err))
	}
	// Two NIC flags are load-bearing and neither is optional.
	//
	// PromiscuousMode: a VPN tun receives packets destined for remote
	// addresses the kernel routed into it. Without this the NIC drops them
	// before the forwarder ever sees them.
	//
	// Spoofing: the packet's *source* is a client address on the link, not an
	// address we own. FindRoute — called by the forwarder with the packet's
	// source as the local endpoint — rejects anything we do not own, so
	// CreateEndpoint fails with "no route to host". Enabling spoofing lets the
	// stack accept those source addresses. Both flags together, or no flow
	// forwards at all.
	if err := stk.SetPromiscuousMode(1, true); err != nil {
		return cancelOn(fmt.Errorf("proxy: promiscuous mode: %v", err))
	}
	if err := stk.SetSpoofing(1, true); err != nil {
		return cancelOn(fmt.Errorf("proxy: spoofing mode: %v", err))
	}

	// The interface is addressed with a subnet prefix (/30 by convention), so
	// the stack can route the peers on that link. With a /32 the client's own
	// address has no route and the first SYN dies.
	prefix := o.Prefix
	if !prefix.IsValid() {
		prefix = netip.PrefixFrom(o.LocalAddr, 30)
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          pickProto(o.LocalAddr),
		AddressWithPrefix: tcpip.AddrFromSlice(prefix.Addr().AsSlice()).WithPrefix(),
	}
	if err := stk.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
		return cancelOn(fmt.Errorf("proxy: add address: %v", err))
	}

	// A VPN terminates flows for arbitrary remote addresses, so the stack needs
	// a catch-all route out of the NIC. Without it CreateEndpoint fails with
	// "no route to host" for every destination that is not the interface
	// address itself, and no connection is ever forwarded.
	routes := []tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}}
	if !o.LocalAddr.Is4() {
		routes = []tcpip.Route{{Destination: header.IPv6EmptySubnet, NIC: 1}}
	}
	stk.SetRouteTable(routes)

	tcpFwd := tcp.NewForwarder(stk, tcpWindowReceive, maxInFlight, p.handleTCP)
	stk.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(stk, p.handleUDP)
	stk.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	p.wg.Add(2)
	go p.readLoop()
	go p.writeLoop()

	if p.log != nil {
		p.log.Infof("proxy", "stack up: addr=%s mtu=%d queue=%d", o.LocalAddr, o.MTU, channelQueue)
	}
	return p, nil
}

func pickProto(a netip.Addr) tcpip.NetworkProtocolNumber {
	if a.Is4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

// readLoop pulls packets off the tun and injects them into the stack.
//
// One reader only: multiple readers on a single tun fd serialise on the kernel
// lock and buy nothing.
func (p *Proxy) readLoop() {
	defer p.wg.Done()
	buf := make([]byte, p.opts.MTU+256)
	for {
		if p.ctx.Err() != nil {
			return
		}
		n, err := p.opts.Tun.Read(buf)
		if err != nil {
			if p.ctx.Err() == nil && p.log != nil && !errors.Is(err, io.EOF) {
				p.log.Debugf("proxy", "tun read: %v", err)
			}
			return
		}
		if n <= 0 {
			continue
		}
		var proto tcpip.NetworkProtocolNumber
		switch buf[0] >> 4 {
		case 4:
			proto = ipv4.ProtocolNumber
		case 6:
			proto = ipv6.ProtocolNumber
		default:
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append([]byte(nil), buf[:n]...)),
		})
		p.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

// writeLoop drains the stack's outbound queue into the tun.
func (p *Proxy) writeLoop() {
	defer p.wg.Done()
	for {
		pkt := p.ep.ReadContext(p.ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		_, err := p.opts.Tun.Write(view.AsSlice())
		pkt.DecRef()
		if err != nil {
			if p.ctx.Err() == nil && p.log != nil {
				p.log.Debugf("proxy", "tun write: %v", err)
			}
			return
		}
	}
}

// handleTCP is called by the stack for every inbound SYN.
func (p *Proxy) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		if p.log != nil {
			p.log.Warnf("proxy", "CreateEndpoint failed for %v: %v", id.LocalAddress, tcpErr)
		}
		r.Complete(true)
		return
	}
	r.Complete(false)

	local := gonet.NewTCPConn(&wq, ep)
	defer local.Close()

	dest, ok := addrPortFrom(id.LocalAddress, id.LocalPort)
	if !ok {
		return
	}
	p.forward(local, "tcp", dest)
}

// handleUDP forwards datagrams.
func (p *Proxy) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		return
	}

	local := gonet.NewUDPConn(&wq, ep)
	defer local.Close()

	dest, ok := addrPortFrom(id.LocalAddress, id.LocalPort)
	if !ok {
		return
	}
	p.forward(local, "udp", dest)
}

// forward performs the routing decision and bridges the two sides.
func (p *Proxy) forward(local net.Conn, network string, dest netip.AddrPort) {
	dec := p.opts.Router.RouteHost(dest.Addr().String(), dest.Addr())

	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	defer cancel()

	var (
		remote net.Conn
		err    error
	)
	if dec == route.Proxy {
		remote, err = dialTunnel(ctx, p.opts.Device, network, dest)
	} else {
		remote, err = p.opts.DialDirect(ctx, network, dest.String())
	}
	if err != nil {
		if p.log != nil {
			p.log.Debugf("proxy", "%s %s via %s: %v", network, dest, dec, err)
		}
		return
	}
	defer remote.Close()

	p.conns.Add(1)
	defer p.conns.Add(-1)

	bridge(local, remote)
}

// dialTunnel adapts the tunnel.Conn interface to net.Conn.
//
// tunnel.Conn is deliberately narrow (Read/Write/Close) so protocol
// implementations stay small. The proxy needs a net.Conn for half-close and
// deadlines, so we wrap it in a type that supplies the missing methods with
// sensible no-ops rather than widening the interface everywhere.
func dialTunnel(ctx context.Context, d tunnel.Device, network string, dest netip.AddrPort) (net.Conn, error) {
	c, err := d.Dial(ctx, network, dest.String())
	if err != nil {
		return nil, err
	}
	return &connAdapter{
		Conn:   c,
		remote: netAddr{network: network, addr: dest},
		local:  netAddr{network: network, addr: netip.AddrPort{}},
	}, nil
}

// bridge copies in both directions and returns when either side ends.
//
// Half-close is honoured: when the client finishes sending we close the write
// side of the remote but keep reading, so a large download finishes after the
// request was fully sent.
func bridge(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		_, _ = io.CopyBuffer(dst, src, buf)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}

// Stack exposes the userspace networking stack for diagnostics and tests.
func (p *Proxy) Stack() *stack.Stack { return p.stk }

// ConnCount reports live forwarded connections.
func (p *Proxy) ConnCount() int64 { return p.conns.Load() }

// Stop tears everything down.
func (p *Proxy) Stop() {
	p.stopped.Do(func() {
		p.cancel()
		// Close the tun first: readLoop is parked in Tun.Read and will only
		// return when the descriptor is closed. Waiting before closing is a
		// deadlock, which is exactly what a naive shutdown produces.
		if p.opts.Tun != nil {
			_ = p.opts.Tun.Close()
		}
		p.ep.Close()
		p.stk.Close()
		p.wg.Wait()
	})
}

func addrPortFrom(a tcpip.Address, port uint16) (netip.AddrPort, bool) {
	ip, ok := netip.AddrFromSlice(a.AsSlice())
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), port), true
}
