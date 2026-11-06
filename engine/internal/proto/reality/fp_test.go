package reality

import (
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestFingerprints(t *testing.T) {
	for _, name := range []string{"chrome", "firefox", "safari", "ios", "android", "edge", "random"} {
		id, err := ParseFingerprint(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		fmt.Printf("  %-8s %s\n", name, id.Str())
	}
}

func TestNewValidates(t *testing.T) {
	// A real X25519 public key: 32 raw bytes, base64url without padding.
	priv, _ := ecdh.X25519().GenerateKey(cryptorand.Reader)
	key := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	if _, err := New(key, "ab", "www.microsoft.com", "chrome"); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if _, err := New("short", "ab", "x.com", "chrome"); err == nil {
		t.Error("short key should be rejected")
	}
	if _, err := New(key, "ab", "", "chrome"); err == nil {
		t.Error("empty SNI should be rejected")
	}
	if _, err := New(key, "ab", "x.com", "nonsense"); err == nil {
		t.Error("unknown fingerprint should be rejected")
	}
	if _, err := New(key, "zz", "x.com", "chrome"); err == nil {
		t.Error("non-hex shortId should be rejected")
	}
}
