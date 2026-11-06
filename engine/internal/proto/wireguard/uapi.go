package wireguard

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"

	"tuntrail/internal/config"
)

// uapiWriter renders the wg UAPI document the device expects from IpcSet.
//
// Format is line oriented and order sensitive: the private_key line opens a
// device section, each public_key line opens a peer section, and an empty line
// closes the current section. Getting the trailing blank line wrong makes the
// device silently ignore the peer, so it is emitted explicitly.
type uapiWriter struct {
	onProtect func(fd int) bool
}

func (u *uapiWriter) build(wg *config.WireGuardProfile, priv, peerPub []byte) string {
	var b strings.Builder

	b.WriteString("private_key=")
	b.WriteString(hex32(priv))
	b.WriteByte('\n')

	b.WriteString("public_key=")
	b.WriteString(hex32(peerPub))
	b.WriteByte('\n')

	if wg.PeerPresharedKey != "" {
		if psk, err := decodeKey(wg.PeerPresharedKey); err == nil {
			b.WriteString("preshared_key=")
			b.WriteString(hex32(psk))
			b.WriteByte('\n')
		}
	}

	b.WriteString("endpoint=")
	b.WriteString(normalizeEndpoint(wg.Endpoint))
	b.WriteByte('\n')

	// persistent_keepalive_interval is in seconds; 25 keeps CGNAT mappings open.
	if ka := wg.Keepalive(); ka > 0 {
		b.WriteString("persistent_keepalive_interval=")
		b.WriteString(strconv.Itoa(int(ka.Seconds())))
		b.WriteByte('\n')
	}

	allowed := wg.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	for _, cidr := range allowed {
		b.WriteString("allowed_ip=")
		b.WriteString(cidr)
		b.WriteByte('\n')
	}

	// Close the peer section.
	b.WriteByte('\n')
	return b.String()
}

// normalizeEndpoint strips brackets so the UAPI sees host:port for both
// address families; it also resolves a bare hostname once here rather than on
// every rekey.
func normalizeEndpoint(ep string) string {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return ep
	}
	return net.JoinHostPort(host, port)
}

// hex32 renders a key the way the UAPI wants it: lowercase hex, 64 chars.
func hex32(k []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(k)*2)
	for _, c := range k {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// KeyPairFromBase64 is exposed for the UI's "generate keypair" button.
func KeyPairFromBase64(privB64 string) (priv, pub string, err error) {
	privRaw, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return "", "", fmt.Errorf("private key is not base64: %w", err)
	}
	if len(privRaw) != 32 {
		return "", "", fmt.Errorf("private key is %d bytes, want 32", len(privRaw))
	}
	pubRaw, err := publicFromPrivate(privRaw)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(privRaw),
		base64.StdEncoding.EncodeToString(pubRaw), nil
}
