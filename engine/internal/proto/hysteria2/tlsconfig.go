package hysteria2

import (
	"crypto/tls"
	"net"
	"time"

	aTLS "github.com/sagernet/sing/common/tls"
)

// tlsConfig adapts crypto/tls.Config to the sing aTLS.Config interface.
//
// The library insists on its own interface because sing-box multiplexes several
// TLS backends (stdlib, uTLS, Reality). We only need the stdlib behaviour, so
// this implements the narrow surface Hysteria2 actually touches. Methods sing
// never calls on the client path still have to exist to satisfy the interface,
// and each one here does something honest rather than panicking.
type tlsConfig struct {
	cfg *tls.Config
	// timeout is the handshake deadline reported to sing. Zero means the
	// library's own default.
	timeout time.Duration
}

var _ aTLS.Config = (*tlsConfig)(nil)

func (c *tlsConfig) ServerName() string { return c.cfg.ServerName }

func (c *tlsConfig) SetServerName(name string) { c.cfg.ServerName = name }

func (c *tlsConfig) NextProtos() []string { return c.cfg.NextProtos }

func (c *tlsConfig) SetNextProtos(protos []string) { c.cfg.NextProtos = protos }

// HandshakeTimeout reports the handshake deadline sing uses to bound its
// wrapper. Hysteria2 sets its own QUIC handshake timeout; returning a sensible
// non-zero value keeps sing from treating us as unlimited.
func (c *tlsConfig) HandshakeTimeout() time.Duration {
	if c.timeout > 0 {
		return c.timeout
	}
	return 10 * time.Second
}

func (c *tlsConfig) SetHandshakeTimeout(d time.Duration) { c.timeout = d }

// STDConfig returns the underlying *tls.Config. Hysteria2 needs it to build its
// QUIC transport; returning an error would abort the handshake.
func (c *tlsConfig) STDConfig() (*aTLS.STDConfig, error) {
	return c.cfg, nil
}

// Client performs a TLS handshake over conn.
func (c *tlsConfig) Client(conn net.Conn) (aTLS.Conn, error) {
	return tls.Client(conn, c.cfg.Clone()), nil
}

// Clone returns an independent copy, which the library uses when it needs a
// per-connection server name.
func (c *tlsConfig) Clone() aTLS.Config {
	return &tlsConfig{cfg: c.cfg.Clone(), timeout: c.timeout}
}
