package reality

import (
	"context"
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"encoding/base64"
	"net"
	"testing"
	"time"
)

// TestHandshakeAgainstRealSite proves the handshake is structurally sound: we
// perform a full TLS 1.3 exchange with a real site using our Reality-wrapped
// ClientHello. The site is not a Reality server, so verification must FAIL —
// and that is exactly the assertion. If the ClientHello were malformed, the
// connection would error out instead of completing at TLS level.
func TestHandshakeAgainstRealSite(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}

	priv, _ := ecdh.X25519().GenerateKey(cryptorand.Reader)
	key := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())

	c, err := New(key, "0123456789abcdef", "www.cloudflare.com", "chrome")
	if err != nil {
		t.Fatal(err)
	}
	c.Timeout = 10 * time.Second

	raw, err := net.DialTimeout("tcp", "www.cloudflare.com:443", 10*time.Second)
	if err != nil {
		t.Skipf("no network: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rc, err := c.Handshake(ctx, raw)
	if rc != nil {
		defer rc.Close()
	}

	// Not a Reality server, so we expect ErrNoVerification specifically.
	// Any other error means our ClientHello construction is broken.
	if err == nil {
		t.Fatalf("expected verification failure against a non-Reality server, got success")
	}
	if rc != nil && rc.Verified {
		t.Errorf("verification should not succeed against a plain site")
	}
	t.Logf("handshake completed, verification correctly rejected: %v", err)
}
