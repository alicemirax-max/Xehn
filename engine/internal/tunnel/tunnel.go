// Package tunnel defines the one interface every protocol implements.
//
// The proxy layer never imports a concrete protocol; it speaks Device. Adding
// a protocol means adding a constructor, not touching the data path.
package tunnel

import (
	"context"
	"errors"
	"net/netip"
)

// Sentinel errors the UI layer maps to user-facing text.
var (
	// ErrAuth means the credential was rejected. Retrying is pointless.
	ErrAuth = errors.New("tunnel: authentication rejected")
	// ErrUnreachable means no route to the endpoint. Try another node.
	ErrUnreachable = errors.New("tunnel: endpoint unreachable")
	// ErrClosed means the device was shut down underneath the caller.
	ErrClosed = errors.New("tunnel: device closed")
)

// Device is a live tunnel. Dial returns a stream carrying TCP-payload bytes;
// the caller is responsible for framing (there is none — a stream is a stream).
type Device interface {
	// Dial opens a connection to host:port through the tunnel.
	Dial(ctx context.Context, network, addr string) (Conn, error)

	// Close tears the tunnel down. Safe to call more than once.
	Close() error

	// Stats reports counters for the UI. Cheap: reads atomics.
	Stats() Stats
}

// Conn is a proxied stream. Implementations must honour ctx deadlines via the
// embedded interfaces; Close unblocks any in-flight Read or Write.
type Conn interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// Stats is the live counter snapshot shown on the connect screen.
type Stats struct {
	// RxBytes counts payload received from the tunnel.
	RxBytes uint64
	// TxBytes counts payload written into the tunnel.
	TxBytes uint64
	// HandshakeMS is the last measured handshake duration (0 = never).
	HandshakeMS uint32
	// MTU is the negotiated path MTU, or the configured value when the probe
	// is disabled.
	MTU int
	// ExitIP is the observed egress address, empty until resolved.
	ExitIP netip.Addr
}

// ProbeResult is one node's reachability measurement.
type ProbeResult struct {
	ID          string
	HandshakeMS uint32
	Err         error
}

// Prober is implemented by devices that can be measured before connecting.
// Kept separate from Device so protocols that cannot cheaply probe (Hysteria2
// over QUIC costs a full handshake anyway) need not fake it.
type Prober interface {
	Probe(ctx context.Context) ProbeResult
}
