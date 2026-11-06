package config

import "testing"

const sampleWG = `[Interface]
PrivateKey = aGVsbG8gd29ybGQgdGhpcyBpcyBhIGtleSE=
Address = 172.16.0.2/32, fd00::2/128
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280

[Peer]
PublicKey = d29ybGQgaGVsbG8gdGhpcyBpcyBhIGtleSE=
PresharedKey = cHNrMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=
Endpoint = engage.cloudflareclient.com:2408
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

func TestParseWGQuick(t *testing.T) {
	got, err := ParseWGQuick(sampleWG)
	if err != nil {
		t.Fatalf("ParseWGQuick: %v", err)
	}
	if got.PrivateKey != "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGtleSE=" {
		t.Errorf("private key: %q", got.PrivateKey)
	}
	if len(got.Address) != 2 || got.Address[0] != "172.16.0.2/32" {
		t.Errorf("address: %v", got.Address)
	}
	if len(got.DNS) != 2 || got.DNS[1] != "8.8.8.8" {
		t.Errorf("dns: %v", got.DNS)
	}
	if got.MTU != 1280 {
		t.Errorf("mtu: %d", got.MTU)
	}
	if got.Endpoint != "engage.cloudflareclient.com:2408" {
		t.Errorf("endpoint: %q", got.Endpoint)
	}
	if got.PersistentKeepalive != 25 {
		t.Errorf("keepalive: %d", got.PersistentKeepalive)
	}
	if len(got.AllowedIPs) != 2 {
		t.Errorf("allowed ips: %v", got.AllowedIPs)
	}
}

func TestParseWGQuickTolerance(t *testing.T) {
	// Comments, blank lines, unknown keys and lower-case keys must all survive.
	doc := `# a comment
[interface]
privatekey = KEY
address = 10.0.0.2/32
postup = iptables -A FORWARD -j ACCEPT
table = off

[peer]
publickey = PUBKEY
endpoint = 1.2.3.4:51820
allowedips = 0.0.0.0/0
`
	got, err := ParseWGQuick(doc)
	if err != nil {
		t.Fatalf("tolerant parse failed: %v", err)
	}
	if got.PrivateKey != "KEY" || got.PeerPublicKey != "PUBKEY" {
		t.Errorf("keys not read: %+v", got)
	}
	if len(got.AllowedIPs) != 1 {
		t.Errorf("allowed ips: %v", got.AllowedIPs)
	}
}

func TestParseWGQuickDefaultsAllowedIPs(t *testing.T) {
	doc := `[Interface]
PrivateKey = K
Address = 10.0.0.2/32

[Peer]
PublicKey = P
Endpoint = 1.2.3.4:51820
`
	got, err := ParseWGQuick(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.AllowedIPs) != 2 {
		t.Fatalf("AllowedIPs should default to the full tunnel, got %v", got.AllowedIPs)
	}
}

func TestParseWGQuickRejects(t *testing.T) {
	cases := map[string]string{
		"no interface": "[Peer]\nPublicKey=P\nEndpoint=1.1.1.1:1\n",
		"no peer":      "[Interface]\nPrivateKey=K\nAddress=10.0.0.2/32\n",
		"no key":       "[Interface]\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=P\nEndpoint=1.1.1.1:1\n",
		"no endpoint":  "[Interface]\nPrivateKey=K\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=P\n",
		"bad mtu":      "[Interface]\nPrivateKey=K\nAddress=10.0.0.2/32\nMTU=abc\n[Peer]\nPublicKey=P\nEndpoint=1.1.1.1:1\n",
		"stray key":    "PrivateKey=K\n",
	}
	for name, doc := range cases {
		if _, err := ParseWGQuick(doc); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
