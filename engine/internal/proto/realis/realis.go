// Package realis implements Reality + VLESS as a tunnel.Device: one packet
// goes in, one proxied stream comes out.
//
// Reality is a per-connection handshake, not a multiplexed tunnel, so the device
// keeps no long-lived session. That is a deliberate property: a fresh TLS
// handshake per flow has the same traffic shape as ordinary browsing, which is
// the entire reason Reality exists.
package realis

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"tuntrail/internal/config"
	"tuntrail/internal/proto/reality"
	"tuntrail/internal/proto/vless"
	"tuntrail/internal/tunnel"
)

// Device dials VLESS+Reality streams on demand.
type Device struct {
	cfg    config.RealityProfile
	uuid   [16]byte
	rc     *reality.Client
	dialer *net.Dialer

	rx atomic.Uint64
	tx atomic.Uint64

	// handshakeMS is the most recent successful handshake duration, in
	// milliseconds. Reported to the UI so the connect screen can show it.
	handshakeMS atomic.Uint32

	closeOnce sync.Once
	closed    chan struct{}
}

// New validates the profile and returns a ready device.
func New(p *config.Profile) (*Device, error) {
	if p.Reality == nil {
		return nil, errors.New("reality: profile has no reality block")
	}
	r := p.Reality

	uuid, err := vless.ParseUUID(r.UUID)
	if err != nil {
		return nil, fmt.Errorf("reality: %w", err)
	}

	rc, err := reality.New(r.PublicKey, r.ShortID, r.ServerName, r.Fingerprint)
	if err != nil {
		return nil, err
	}

	if r.Port <= 0 || r.Port > 65535 {
		return nil, fmt.Errorf("reality: port %d out of range", r.Port)
	}

	return &Device{
		cfg:    *r,
		uuid:   uuid,
		rc:     rc,
		dialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
		closed: make(chan struct{}),
	}, nil
}

// Dial opens one proxied stream.
func (d *Device) Dial(ctx context.Context, network, addr string) (tunnel.Conn, error) {
	select {
	case <-d.closed:
		return nil, tunnel.ErrClosed
	default:
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("reality: split %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("reality: bad port in %q", addr)
	}

	// The handshake must not outlive the caller's context; the deadline on the
	// raw socket is the backstop for a hung peer.
	server := net.JoinHostPort(d.cfg.Server, strconv.Itoa(d.cfg.Port))
	raw, err := d.dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", tunnel.ErrUnreachable, err)
	}

	rc, err := d.rc.Handshake(ctx, raw)
	if err != nil {
		_ = raw.Close()
		if errors.Is(err, reality.ErrNoVerification) {
			// The camouflage site answered instead of our server. That is a
			// credential problem, not a network one, so retrying is pointless.
			return nil, fmt.Errorf("%w: reality verification failed", tunnel.ErrAuth)
		}
		return nil, err
	}
	if !rc.Verified {
		_ = rc.Close()
		return nil, fmt.Errorf("%w: server did not authenticate", tunnel.ErrAuth)
	}
	d.handshakeMS.Store(rc.HandshakeMS)

	stream, err := vless.Dial(rc, d.uuid, host, uint16(port))
	if err != nil {
		_ = rc.Close()
		return nil, fmt.Errorf("reality: vless dial %s: %w", addr, err)
	}

	return &countingConn{Conn: stream, rx: &d.rx, tx: &d.tx}, nil
}

// Probe measures one handshake without sending a VLESS request, which is what
// the node tester uses to rank servers.
func (d *Device) Probe(ctx context.Context) tunnel.ProbeResult {
	start := time.Now()
	server := net.JoinHostPort(d.cfg.Server, strconv.Itoa(d.cfg.Port))
	raw, err := d.dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return tunnel.ProbeResult{Err: err}
	}
	rc, err := d.rc.Handshake(ctx, raw)
	if err != nil {
		_ = raw.Close()
		return tunnel.ProbeResult{Err: err, HandshakeMS: uint32(time.Since(start).Milliseconds())}
	}
	_ = rc.Close()
	return tunnel.ProbeResult{HandshakeMS: uint32(time.Since(start).Milliseconds())}
}

// Stats reports counters.
func (d *Device) Stats() tunnel.Stats {
	return tunnel.Stats{
		RxBytes:     d.rx.Load(),
		TxBytes:     d.tx.Load(),
		HandshakeMS: d.handshakeMS.Load(),
		MTU:         0, // the tun decides; Reality does not constrain it
	}
}

// Close marks the device closed. In-flight streams are owned by their callers.
func (d *Device) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
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

// CloseWrite propagates half-close to the VLESS stream.
func (c *countingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}
