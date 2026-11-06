package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// publicFromPrivate derives the Curve25519 public key. WireGuard uses raw
// X25519 with no hashing on the base-point multiplication, which is exactly
// what crypto/ecdh.NewPrivateKey + PublicKey does — no manual clamping needed
// because ecdh rejects out-of-range scalars and applies the standard clamp.
func publicFromPrivate(priv []byte) ([]byte, error) {
	if len(priv) != 32 {
		return nil, fmt.Errorf("private key is %d bytes, want 32", len(priv))
	}
	// WireGuard applies the X25519 clamp before use; ecdh.NewPrivateKey
	// performs it internally, so a generated pair matches wg(8).
	k, err := ecdh.X25519().NewPrivateKey(clampX25519(priv))
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	return k.PublicKey().Bytes(), nil
}

// clampX25519 applies the RFC 7748 scalar clamp. crypto/ecdh already clamps,
// but doing it explicitly keeps the derivation byte-identical to wg-tools for
// private keys pasted from a wg-quick config, which may or may not be clamped.
func clampX25519(k []byte) []byte {
	out := make([]byte, 32)
	copy(out, k)
	out[0] &= 248
	out[31] &= 127
	out[31] |= 64
	return out
}

// GenerateKeyPair returns a fresh base64 private key and its public half.
func GenerateKeyPair() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(randReader{})
	if err != nil {
		return "", "", err
	}
	return b64(k.Bytes()), b64(k.PublicKey().Bytes()), nil
}

type randReader struct{}

func (randReader) Read(p []byte) (int, error) { return rand.Read(p) }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
