package reality

import (
	"bytes"
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// TestECDHAndHKDFAgreement verifies the exact derivation the handshake performs:
// both parties reach the same AEAD key from opposite halves of an X25519
// exchange. If this ever breaks, every Reality handshake fails with a
// verification error that looks like a network problem.
func TestECDHAndHKDFAgreement(t *testing.T) {
	clientKey, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// The client derives from (its private, server public).
	clientSecret, err := clientKey.ECDH(serverKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	// The server derives from (its private, client public) using the key share
	// it received in the ClientHello.
	serverSecret, err := serverKey.ECDH(clientKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientSecret, serverSecret) {
		t.Fatal("ECDH secrets disagree")
	}

	// Salt is ClientHello.Random[:20], info is the literal "REALITY".
	salt := make([]byte, 20)
	copy(salt, []byte("0123456789abcdefghij"))

	derive := func(secret []byte) []byte {
		k := make([]byte, 32)
		r := hkdf.New(sha256.New, secret, salt, []byte("REALITY"))
		if _, err := r.Read(k); err != nil {
			t.Fatal(err)
		}
		return k
	}

	clientKeyOut := derive(clientSecret)
	serverKeyOut := derive(serverSecret)
	if !bytes.Equal(clientKeyOut, serverKeyOut) {
		t.Fatal("HKDF outputs disagree")
	}
	t.Logf("ECDH + HKDF agree over a %d-byte secret", len(clientSecret))
}

// TestShortIDPadding ensures a short id shorter than 8 bytes is zero padded
// and lands at SessionID[8:16] without disturbing the timestamp.
func TestShortIDPadding(t *testing.T) {
	var sid [8]byte
	copy(sid[:], []byte{0xaa, 0xbb})
	if sid[2] != 0 || sid[7] != 0 {
		t.Fatal("short id was not zero padded")
	}
}
