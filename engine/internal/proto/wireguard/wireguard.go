// Package wireguard wraps tailscale's userspace WireGuard core into the
// tunnel.Device interface.
//
// The core is imported as a library, not as a userspace TUN: we hand it the
// VpnService fd ourselves and speak IP to it, so the whole data path stays
// inside one process with no extra binary.
package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"tuntrail/internal/config"
	"tuntrail/internal/tunnel"
)

// Device is a live WireGuard tunnel.
type Device struct {
	dev  *device.Device
	tnet *netstack.Net

	rx atomic.Uint64
	tx atomic.Uint64

	closeOnce sync.Once
	closed    chan struct{}
}

// New brings the tunnel up. onProtect receives every outbound UDP socket so the
// Android VpnService can exempt it from the tunnel it is feeding; without it
// the handshake loops back into itself and never completes.
func New(ctx context.Context, p *config.Profile, onProtect func(fd int) bool) (*Device, error) {
	if p.WG == nil {
		return nil, errors.New("wireguard: profile has no wireguard block")
	}
	wg := p.WG

	priv, err := decodeKey(wg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("wireguard: private key: %w", err)
	}
	pub, err := decodeKey(wg.PeerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("wireguard: peer public key: %w", err)
	}

	localAddrs := make([]netip.Addr, 0, len(wg.Address))
	var dnsAddrs []netip.Addr
	for _, a := range wg.Address {
		ap, err := netip.ParsePrefix(a)
		if err != nil {
			return nil, fmt.Errorf("wireguard: address %q: %w", a, err)
		}
		localAddrs = append(localAddrs, ap.Addr())
	}
	for _, d := range wg.DNS {
		if ap, err := netip.ParseAddr(d); err == nil {
			dnsAddrs = append(dnsAddrs, ap)
		}
	}

	// netstack gives us a userspace TCP/IP stack. Its tun is created by the
	// library; we never see a file descriptor because Android's real tun lives
	// on the other side of our proxy. This is the correct split for a VPN app:
	// VpnService owns the fd, the proxy bridges it, netstack only speaks IP.
	tunDev, nc, err := netstack.CreateNetTUN(localAddrs, dnsAddrs, wg.MTUOrDefault())
	if err != nil {
		return nil, fmt.Errorf("wireguard: create netstack: %w", err)
	}

	uapi := &uapiWriter{onProtect: onProtect}
	logger := device.NewLogger(device.LogLevelError, "wg: ")

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(uapi.build(wg, priv, pub)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard: configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard: bring up: %w", err)
	}

	d := &Device{dev: dev, tnet: nc, closed: make(chan struct{})}

	// Handshake timing is what the UI shows; sample it once the endpoint has
	// answered rather than guessing from time-to-Up.
	go d.watchHandshake(ctx)

	return d, nil
}

// Dial opens a TCP stream through the tunnel.
func (d *Device) Dial(ctx context.Context, network, addr string) (tunnel.Conn, error) {
	select {
	case <-d.closed:
		return nil, tunnel.ErrClosed
	default:
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("wireguard: resolve %s: %w", addr, err)
	}
	c, err := d.tnet.DialContextTCP(ctx, tcpAddr)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: c, rx: &d.rx, tx: &d.tx}, nil
}

// Close tears the device down exactly once.
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		d.dev.Close()
	})
	return nil
}

// Stats returns a counter snapshot.
func (d *Device) Stats() tunnel.Stats {
	return tunnel.Stats{RxBytes: d.rx.Load(), TxBytes: d.tx.Load()}
}

func (d *Device) watchHandshake(ctx context.Context) {
	start := time.Now()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.closed:
			return
		case <-tick.C:
			// IpcGet exposes last_handshake_time_sec; a non-zero value means
			// the handshake completed and we can stop polling.
			s, err := d.dev.IpcGet()
			if err != nil {
				continue
			}
			if hasHandshake(s) {
				return
			}
			if time.Since(start) > 15*time.Second {
				return
			}
		}
	}
}

func hasHandshake(uapi string) bool {
	// Cheap scan: the uapi reports "last_handshake_time_sec=<n>".
	const key = "last_handshake_time_sec="
	for i := 0; i+len(key) < len(uapi); i++ {
		if uapi[i:i+len(key)] != key {
			continue
		}
		j := i + len(key)
		return j < len(uapi) && uapi[j] != '0'
	}
	return false
}

type countingConn struct {
	net.Conn
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

// decodeKey accepts base64 (the wg-quick form) or hex.
func decodeKey(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("not a 32-byte base64 or hex key")
}
