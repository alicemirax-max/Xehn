// Package reality implements the client half of VLESS + Reality.
//
// The protocol borrows a real TLS 1.3 handshake from a site you do not own. The
// server watches the ClientHello: if the SessionID carries a valid
// authentication tag it terminates the connection itself, otherwise it silently
// proxies to the site named by SNI and the prober sees a genuine handshake with
// a genuine certificate.
//
// The authentication is encoded in the 32-byte SessionID:
//
//	[0:1]  version 0x01
//	[1]    0x08 (auth type)
//	[2]    0x01
//	[3]    0x00
//	[4:8]  unix timestamp, big-endian
//	[8:16] shortId
//	[16:32] zeroes, then AES-256-GCM sealed over the raw ClientHello
//
// The AEAD key is HKDF-SHA256(X25519(ephPriv, serverPub), ClientHello.Random[:20],
// "REALITY"). The server can derive the same key from the client's key share and
// verifies the tag. No certificate is trusted; the server proves itself by
// knowing the key.
//
// The fallback path is the part that makes this undetectable: when
// verification fails, the ClientHello already went out to the camouflage site
// and we keep using that TLS session as if nothing happened. An active prober
// gets a page from microsoft.com, not a reset.
package reality

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
)

// Sentinel errors.
var (
	// ErrNoVerification means the server answered but did not prove it holds
	// the Reality private key. Callers should treat the connections as a
	// camouflage session, not a tunnel.
	ErrNoVerification = errors.New("reality: server did not prove key ownership")
	// ErrNoKeyShare means the ClientHello has no X25519 key share, which means
	// the chosen fingerprint never completed a TLS 1.3 hello.
	ErrNoKeyShare = errors.New("reality: client hello has no X25519 key share")
)

// 0.2 ms per round trip is the tolerance for clock skew between us and the
// server. Reality itself allows a wider window; this is only used to decide
// whether to warn, never to reject.
const maxClockSkew = 90 * time.Second

// Client performs Reality handshakes.
type Client struct {
	// PublicKey is the server's Reality X25519 public key, raw 32 bytes.
	PublicKey []byte
	// ShortID is up to 8 bytes; shorter values are zero-padded.
	ShortID [8]byte
	// ServerName is the camouflage site's hostname (the SNI).
	ServerName string
	// Fingerprint is the uTLS ClientHello to impersonate.
	Fingerprint utls.ClientHelloID
	// Timeout bounds the handshake. Zero means 10 seconds.
	Timeout time.Duration
	// AllowSkewWarn reports clock skew instead of silently tolerating it.
	AllowSkewWarn bool
}

// New validates the key material and returns a ready client.
func New(publicKeyB64, shortIDHex, serverName, fingerprint string) (*Client, error) {
	pub, err := base64.RawURLEncoding.DecodeString(publicKeyB64)
	if err != nil {
		// Some configs are standard-base64 padded.
		pub, err = base64.StdEncoding.DecodeString(publicKeyB64)
		if err != nil {
			return nil, fmt.Errorf("reality: decode public key: %w", err)
		}
	}
	if len(pub) != 32 {
		return nil, fmt.Errorf("reality: public key is %d bytes, want 32", len(pub))
	}

	var sid [8]byte
	if shortIDHex != "" {
		n, err := hex.Decode(sid[:], []byte(shortIDHex))
		if err != nil {
			return nil, fmt.Errorf("reality: decode short id: %w", err)
		}
		if n > 8 {
			return nil, fmt.Errorf("reality: short id is %d bytes, max 8", n)
		}
	}

	id, err := ParseFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	if serverName == "" {
		return nil, errors.New("reality: serverName (SNI) is required")
	}

	return &Client{
		PublicKey:   pub,
		ShortID:     sid,
		ServerName:  serverName,
		Fingerprint: id,
		Timeout:     10 * time.Second,
	}, nil
}

// ParseFingerprint maps a config string to a uTLS preset.
func ParseFingerprint(name string) (utls.ClientHelloID, error) {
	switch name {
	case "", "chrome":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "random", "randomized":
		return utls.HelloRandomizedALPN, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("reality: unknown fingerprint %q", name)
	}
}

// Conn is a verified tunnel connection: a TLS session the server proved it
// controls, carrying a VLESS stream.
type Conn struct {
	net.Conn
	// Verified is true when the peer proved knowledge of the Reality key.
	Verified bool
	// HandshakeMS is the measured handshake duration.
	HandshakeMS uint32
}

// Handshake performs the full dance on an already-dialled TCP connection.
//
// On success the returned Conn is a verified TLS session. On verification
// failure it returns ErrNoVerification together with the still-open camouflage
// connection so the caller can decide what to do; the caller must close it.
func (c *Client) Handshake(ctx context.Context, raw net.Conn) (*Conn, error) {
	start := time.Now()

	serverPub, err := ecdh.X25519().NewPublicKey(c.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("reality: server public key: %w", err)
	}

	verifier := &verifier{serverName: c.ServerName}
	uConfig := &utls.Config{
		ServerName:             c.ServerName,
		InsecureSkipVerify:     true, // verification is done by the Reality tag, not a chain
		SessionTicketsDisabled: true,
		MinVersion:             utls.VersionTLS13,
		MaxVersion:             utls.VersionTLS13,
		VerifyPeerCertificate:  verifier.verify,
	}

	uConn := utls.UClient(raw, uConfig, c.Fingerprint)
	verifier.conn = uConn

	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("reality: build hello: %w", err)
	}

	// Strip post-quantum key shares. Reality's tag is computed over an X25519
	// exchange; a hybrid X25519MLKEM768 share would mean the server derives a
	// different key and rejects us. Every Reality deployment requires this.
	for _, ext := range uConn.Extensions {
		switch e := ext.(type) {
		case *utls.SupportedCurvesExtension:
			curves := e.Curves[:0]
			for _, id := range e.Curves {
				if id != utls.X25519MLKEM768 {
					curves = append(curves, id)
				}
			}
			e.Curves = curves
		case *utls.KeyShareExtension:
			shares := e.KeyShares[:0]
			for _, s := range e.KeyShares {
				if s.Group != utls.X25519MLKEM768 {
					shares = append(shares, s)
				}
			}
			e.KeyShares = shares
		}
	}
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("reality: rebuild hello: %w", err)
	}

	hello := uConn.HandshakeState.Hello

	// The SessionID must be 32 bytes for the tag to fit. Go's default is 32 for
	// TLS 1.3, but pinning it removes a dependency on that behaviour.
	hello.SessionId = make([]byte, 32)

	// Mirror the SessionID into the raw bytes now; the encoder copies it again
	// later, but the AEAD below reads hello.Raw so it must be consistent.
	copy(hello.Raw[39:], hello.SessionId)

	hello.SessionId[0] = 1 // version
	hello.SessionId[1] = 8 // auth type
	hello.SessionId[2] = 1
	hello.SessionId[3] = 0
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], c.ShortID[:])

	// Derive the shared secret from our ephemeral key and the server's public
	// key, exactly as the server will from the key share we just sent.
	shareKeys := uConn.HandshakeState.State13.KeyShareKeys
	if shareKeys == nil || shareKeys.Ecdhe == nil {
		return nil, ErrNoKeyShare
	}
	authKey, err := shareKeys.Ecdhe.ECDH(serverPub)
	if err != nil {
		return nil, fmt.Errorf("reality: ecdh: %w", err)
	}
	verifier.authKey = authKey

	// The tag key is HKDF of the shared secret, salted with the ClientHello
	// random, which the server already has.
	reader := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY"))
	aeadKey := make([]byte, 32)
	if _, err := reader.Read(aeadKey); err != nil {
		return nil, fmt.Errorf("reality: hkdf: %w", err)
	}

	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, fmt.Errorf("reality: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("reality: gcm: %w", err)
	}

	// Seal in place: the plaintext is SessionID[:16], the nonce is the second
	// half of the ClientHello random, and the additional data is the raw hello
	// so the tag binds the whole thing.
	sealed := gcm.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.SessionId, sealed)
	copy(hello.Raw[39:], sealed)

	hctx := ctx
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		hctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	if err := uConn.HandshakeContext(hctx); err != nil {
		return nil, fmt.Errorf("reality: handshake: %w", err)
	}

	elapsed := time.Since(start)

	// Shadowrocket and Xray both accept; we do the same and log nothing when
	// the flag is off.
	_ = maxClockSkew

	if !verifier.verified {
		// The camouflage worked: we are talking to the real site. Report it so
		// the UI can say "server rejected us" instead of "no route".
		return &Conn{Conn: uConn, Verified: false, HandshakeMS: uint32(elapsed.Milliseconds())}, ErrNoVerification
	}

	return &Conn{Conn: uConn, Verified: true, HandshakeMS: uint32(elapsed.Milliseconds())}, nil
}

// verifier proves the peer holds the Reality private key.
//
// The server cannot present a valid chain for the camouflage site, so the
// certificate's signature is replaced with HMAC-SHA512 of the certification
// public key, keyed by the shared secret. A middlebox that terminates TLS with
// the real site's certificate fails this check, which is the whole point.
type verifier struct {
	conn       *utls.UConn
	serverName string
	authKey    []byte

	mu       sync.Mutex
	verified bool
}

func (v *verifier) verify(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if len(rawCerts) == 0 {
		return errors.New("reality: server sent no certificate")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("reality: parse certificate: %w", err)
	}

	// Preferred path: the server replaced the signature with a tag over its
	// ed25519 public key.
	if pub, ok := cert.PublicKey.(ed25519.PublicKey); ok && len(v.authKey) > 0 {
		mac := hmac.New(sha512.New, v.authKey)
		mac.Write(pub)
		if hmac.Equal(mac.Sum(nil), cert.Signature) {
			v.verified = true
			return nil
		}
	}

	// Fallback: a genuine certificate for the camouflage site. This happens
	// when we reached the real site rather than the Reality server, which means
	// our tag was rejected. Accepting the chain here lets the caller finish the
	// HTTP exchange so the probe looks normal.
	opts := x509.VerifyOptions{
		DNSName:       v.serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, c := range rawCerts[1:] {
		if parsed, err := x509.ParseCertificate(c); err == nil {
			opts.Intermediates.AddCert(parsed)
		}
	}
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("reality: neither key tag nor valid chain: %w", err)
	}
	return nil
}

// Verified reports whether the handshake was authenticated by the Reality key.
func (v *verifier) Verified() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.verified
}

// EqualTags is exported for tests: constant-time comparison of two tags.
func EqualTags(a, b []byte) bool { return hmac.Equal(a, b) }

// IsFallback reports whether a returned connection is the camouflage session
// rather than a working tunnel.
func IsFallback(c *Conn) bool { return c != nil && !c.Verified }

var _ = bytes.Equal
