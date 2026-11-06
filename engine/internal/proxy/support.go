package proxy

import (
	"context"
	"net"
	"net/netip"
	"time"

	"tuntrail/internal/tunnel"
)

// defaultDirectDialer returns a dialer for traffic we deliberately keep out of
// the tunnel.
//
// The Android subtlety: while the VPN is up, an ordinary net.Dial is captured
// by the tun we are filling, which loops. The Kotlin layer calls
// VpnService.protect() on our sockets through SocketProtector before this
// dialer is installed, so by the time we get here the socket is already exempt.
// If protection was not installed the dial simply times out instead of hanging
// forever, which makes the misconfiguration visible in the log.
func defaultDirectDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 10 * time.Second}
		if deadline, ok := ctx.Deadline(); ok {
			d.Deadline = deadline
		}
		return d.DialContext(ctx, network, addr)
	}
}

// connAdapter gives a tunnel.Conn the net.Conn surface the bridge needs.
//
// tunnel.Conn is narrow on purpose: every protocol implementation gets smaller
// if it only has to provide Read, Write and Close. The adapter supplies
// LocalAddr, RemoteAddr and the deadline methods. Deadlines are accepted but
// not enforced because the owning tunnel already applies its own timeouts; the
// bridge never sets one.
type connAdapter struct {
	tunnel.Conn
	local  net.Addr
	remote net.Addr
}

func (c *connAdapter) LocalAddr() net.Addr  { return c.local }
func (c *connAdapter) RemoteAddr() net.Addr { return c.remote }

func (c *connAdapter) SetDeadline(t time.Time) error      { return nil }
func (c *connAdapter) SetReadDeadline(t time.Time) error  { return nil }
func (c *connAdapter) SetWriteDeadline(t time.Time) error { return nil }

// netAddr presents a netip.AddrPort as a net.Addr so the bridge and any
// per-connection display do not need to know which protocol produced it.
type netAddr struct {
	network string
	addr    netip.AddrPort
}

func (a netAddr) Network() string { return a.network }
func (a netAddr) String() string  { return a.addr.String() }
