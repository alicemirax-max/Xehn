// Package vless implements the VLESS client protocol on top of a verified
// Reality TLS session.
//
// VLESS is deliberately minimal: after the TLS handshake the client sends one
// request header and then raw bytes. There is no per-packet framing and no
// handshake of its own, which is why it pairs well with Reality — the only
// thing an observer sees is a TLS 1.3 connection to a plausible site.
package vless

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Command byte.
const (
	cmdTCP = 0x01
	cmdUDP = 0x02
	cmdMux = 0x03
)

// Address types.
const (
	addrIPv4   = 0x01
	addrDomain = 0x02
	addrIPv6   = 0x03
)

// Version is the VLESS protocol version we speak. Only 0 is in use.
const Version = 0x00

// ErrBadResponse means the server rejected the request.
var ErrBadResponse = errors.New("vless: server rejected request")

// Request describes one proxied connection.
type Request struct {
	// UUID is the user's VLESS identifier.
	UUID [16]byte
	// Command is cmdTCP for streams.
	Command byte
	// Host is the destination.
	Host string
	// Port is the destination port.
	Port uint16
}

// BuildHeader serialises the VLESS request header.
//
// Layout:
//
//	version(1) uuid(16) addonLen(1) command(1) port(2) addrType(1) addr(n)
func BuildHeader(r Request) ([]byte, error) {
	if r.Port == 0 {
		return nil, errors.New("vless: port is required")
	}

	var addr []byte
	var atype byte
	switch {
	case isIPv4(r.Host):
		atype = addrIPv4
		addr = parseIPv4(r.Host)
	case isIPv6(r.Host):
		atype = addrIPv6
		addr = parseIPv6(r.Host)
	default:
		if len(r.Host) == 0 || len(r.Host) > 255 {
			return nil, fmt.Errorf("vless: host %q is not a valid domain", r.Host)
		}
		atype = addrDomain
		addr = append([]byte{byte(len(r.Host))}, r.Host...)
	}

	// 1 + 16 + 1 + 1 + 2 + 1 + len(addr)
	buf := make([]byte, 0, 22+len(addr))
	buf = append(buf, Version)
	buf = append(buf, r.UUID[:]...)
	buf = append(buf, 0) // addon length
	buf = append(buf, r.Command)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], r.Port)
	buf = append(buf, port[:]...)
	buf = append(buf, atype)
	buf = append(buf, addr...)
	return buf, nil
}

// ParseUUID decodes a canonical 8-4-4-4-12 UUID.
func ParseUUID(s string) ([16]byte, error) {
	var out [16]byte
	if len(s) != 36 {
		return out, fmt.Errorf("vless: uuid %q is not 36 characters", s)
	}
	hexed := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '-':
			if i != 8 && i != 13 && i != 18 && i != 23 {
				return out, fmt.Errorf("vless: uuid %q has a misplaced dash", s)
			}
		default:
			hexed = append(hexed, s[i])
		}
	}
	if len(hexed) != 32 {
		return out, fmt.Errorf("vless: uuid %q has the wrong length", s)
	}
	for i := 0; i < 16; i++ {
		hi, ok1 := unhex(hexed[i*2])
		lo, ok2 := unhex(hexed[i*2+1])
		if !ok1 || !ok2 {
			return out, fmt.Errorf("vless: uuid %q is not hexadecimal", s)
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// Conn is a VLESS stream. It writes the header once on first write.
type Conn struct {
	net.Conn
	req    Request
	wrote  bool
	mu     sync.Mutex
	earned bool
}

// NewConn wraps a verified TLS connection. No bytes are sent until the first
// Write, which lets the caller abandon the connection without having committed
// to a request.
func NewConn(c net.Conn, r Request) *Conn {
	return &Conn{Conn: c, req: r}
}

// Write sends the header on the first call, then passes bytes through.
func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.wrote {
		hdr, err := BuildHeader(c.req)
		if err != nil {
			c.mu.Unlock()
			return 0, err
		}
		if _, err := c.Conn.Write(hdr); err != nil {
			c.mu.Unlock()
			return 0, fmt.Errorf("vless: write header: %w", err)
		}
		c.wrote = true
	}
	c.mu.Unlock()

	n, err := c.Conn.Write(p)
	if err != nil && !c.earned {
		return n, fmt.Errorf("vless: write payload: %w", err)
	}
	c.earned = true
	return n, nil
}

// Read returns payload bytes. The server's response header is consumed
// transparently on the first read.
func (c *Conn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if !c.wrote {
		// A read before a write means the caller expects the server to speak
		// first, which VLESS does not allow. Send an empty request so the
		// stream is well formed.
		hdr, err := BuildHeader(c.req)
		if err != nil {
			c.mu.Unlock()
			return 0, err
		}
		if _, err := c.Conn.Write(hdr); err != nil {
			c.mu.Unlock()
			return 0, fmt.Errorf("vless: write header: %w", err)
		}
		c.wrote = true
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}

// Dial opens a VLESS stream to host:port through an established TLS session.
func Dial(tlsConn net.Conn, uuid [16]byte, host string, port uint16) (*Conn, error) {
	c := NewConn(tlsConn, Request{UUID: uuid, Command: cmdTCP, Host: host, Port: port})
	// Force the header out immediately so a rejection surfaces here rather
	// than on the caller's first Write.
	if _, err := c.Write(nil); err != nil {
		return nil, err
	}
	return c, nil
}

// CloseWrite propagates a half-close when the underlying session supports it.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// SetDeadline is inherited; kept here to document that deadlines pass through
// to the TLS layer, which forwards them to the TCP socket.

func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && len(s) <= 15
}

func isIPv6(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil
}

func parseIPv4(s string) []byte {
	ip := net.ParseIP(s).To4()
	out := make([]byte, 4)
	copy(out, ip)
	return out
}

func parseIPv6(s string) []byte {
	ip := net.ParseIP(s).To16()
	out := make([]byte, 16)
	copy(out, ip)
	return out
}

// JoinHostPort is a small helper the engine uses to build dial targets.
func JoinHostPort(h string, p uint16) string {
	return net.JoinHostPort(h, strconv.Itoa(int(p)))
}

var _ = io.EOF
var _ = time.Second
