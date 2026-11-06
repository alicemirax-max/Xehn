// Package config defines the wire format the Kotlin layer pushes into the
// engine over JNI. Every field is plain JSON — the UI parses nothing, it
// serialises its state model directly so the two sides cannot drift.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Mode selects how the tun interface decides what enters the tunnel.
type Mode string

const (
	// ModeGlobal sends everything through the proxy.
	ModeGlobal Mode = "global"
	// ModeRule consults the rule engine, default-direct.
	ModeRule Mode = "rule"
	// ModeAppOnly tunnels only the packages in SplitApps (VpnService.Builder
	// addAllowedApplication), bypassing the rule engine entirely.
	ModeAppOnly Mode = "app"
)

// Protocol names accepted in Profile.Protocol.
const (
	ProtoWireGuard   = "wg"
	ProtoReality     = "reality"
	ProtoHysteria2   = "hysteria2"
	ProtoShadowsocks = "ss"
)

// Profile is one node. Only the fields relevant to Protocol are read; the rest
// are ignored so a subscription can carry a heterogeneous list.
type Profile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`

	// WireGuard
	WG *WireGuardProfile `json:"wireguard,omitempty"`

	// VLESS + Reality
	Reality *RealityProfile `json:"reality,omitempty"`

	// Hysteria2
	Hysteria2 *Hysteria2Profile `json:"hysteria2,omitempty"`

	// Shadowsocks 2022 (aead-2022-blake3-aes-128-gcm and friends)
	Shadowsocks *ShadowsocksProfile `json:"shadowsocks,omitempty"`
}

// WireGuardProfile mirrors wg-quick syntax so pasted configs map 1:1.
type WireGuardProfile struct {
	PrivateKey          string   `json:"privateKey"`
	Address             []string `json:"address"` // e.g. ["172.16.0.2/32"]
	DNS                 []string `json:"dns,omitempty"`
	MTU                 int      `json:"mtu,omitempty"` // 0 = auto (see tun.ProbeMTU)
	PeerPublicKey       string   `json:"peerPublicKey"`
	PeerPresharedKey    string   `json:"peerPresharedKey,omitempty"`
	Endpoint            string   `json:"endpoint"`   // host:port
	AllowedIPs          []string `json:"allowedIPs"` // default 0.0.0.0/0, ::/0
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"`
	// AmneziaWG obfuscation. Zero value = plain WireGuard.
	Amnezia *AmneziaParams `json:"amnezia,omitempty"`
}

// AmneziaParams are the junk-packet knobs AmneziaWG adds to the handshake.
// They must match the server byte for byte or the handshake is dropped.
type AmneziaParams struct {
	JC   int   `json:"jc"`   // junk packet count
	JMin int   `json:"jmin"` // junk size min
	JMax int   `json:"jmax"` // junk size max
	S1   int   `json:"s1"`
	S2   int   `json:"s2"`
	H1   int64 `json:"h1"`
	H2   int64 `json:"h2"`
	H3   int64 `json:"h3"`
	H4   int64 `json:"h4"`
}

// RealityProfile is VLESS over a real TLS handshake borrowed from a real site.
type RealityProfile struct {
	Server      string `json:"server"`
	Port        int    `json:"port"`
	UUID        string `json:"uuid"`
	Flow        string `json:"flow,omitempty"` // xtls-rprx-vision
	ServerName  string `json:"serverName"`     // SNI, a real site you don't own
	PublicKey   string `json:"publicKey"`      // reality shortId peer key
	ShortID     string `json:"shortId"`
	Fingerprint string `json:"fingerprint,omitempty"` // chrome|firefox|safari|random
}

// Hysteria2Profile is QUIC with a fake-HTTP/3 masquerade and Brutal CC.
type Hysteria2Profile struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	SNI      string `json:"sni,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
	UpMbps   int    `json:"upMbps,omitempty"` // Brutal: 0 = BBR
	DownMbps int    `json:"downMbps,omitempty"`
	ObfsType string `json:"obfsType,omitempty"` // salamander
	ObfsPass string `json:"obfsPassword,omitempty"`
}

// ShadowsocksProfile covers the 2022 AEAD methods.
type ShadowsocksProfile struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
}

// DNSSettings controls resolver behaviour inside the tunnel.
type DNSSettings struct {
	// Servers are tried in order. "https://" and "tls://" prefixes select DoH
	// and DoT respectively; a bare address means plain UDP:53, which leaks and
	// is only honoured when AllowPlaintext is set.
	Servers []string `json:"servers"`
	// FakeIP hands out 198.18.0.0/15 addresses and resolves on first packet,
	// which removes a DNS round-trip from every new connection.
	FakeIP  bool   `json:"fakeIp"`
	DoHPath string `json:"dohPath,omitempty"`
}

// RuleSet is the split-routing configuration. Evaluation is first-match-wins.
type RuleSet struct {
	// DirectCIDRs bypass the tunnel. Populated by the UI from the bundled
	// CN prefix table, but any CIDR works.
	DirectCIDRs []string `json:"directCidrs,omitempty"`
	// ProxyCIDRs force into the tunnel even if a later Direct rule matches.
	ProxyCIDRs []string `json:"proxyCidrs,omitempty"`
	// DirectDomains match by suffix: "cn" hits "baidu.cn" and "www.baidu.cn".
	DirectDomains []string `json:"directDomains,omitempty"`
	ProxyDomains  []string `json:"proxyDomains,omitempty"`
	// Final is "direct" or "proxy".
	Final string `json:"final"`
}

// EngineConfig is the single object the UI pushes. It is replaced wholesale on
// every connect; there is no partial update path to get out of sync.
type EngineConfig struct {
	Mode      Mode        `json:"mode"`
	Profile   Profile     `json:"profile"`
	DNS       DNSSettings `json:"dns"`
	Rules     RuleSet     `json:"rules"`
	SplitApps []string    `json:"splitApps,omitempty"`

	// TunAddress is the local interface address, e.g. "172.19.0.1/30".
	TunAddress string `json:"tunAddress"`
	TunMTU     int    `json:"tunMtu"`

	// SocksListen enables a loopback SOCKS5 listener for debugging.
	SocksListen string `json:"socksListen,omitempty"`

	// MTUProbe enables the post-connect path-MTU search. Costs ~200 ms and one
	// ICMP burst; turn it off on already-tuned setups.
	MTUProbe bool `json:"mtuProbe"`

	LogLevel string `json:"logLevel"`
}

// Validate rejects configurations that would fail confusingly at runtime.
func (c *EngineConfig) Validate() error {
	if c.TunAddress == "" {
		return errors.New("tunAddress is required")
	}
	if _, err := netip.ParsePrefix(c.TunAddress); err != nil {
		return fmt.Errorf("tunAddress %q: %w", c.TunAddress, err)
	}
	if c.TunMTU == 0 {
		c.TunMTU = 1400
	}
	if c.TunMTU < 1280 || c.TunMTU > 9000 {
		return fmt.Errorf("tunMtu %d outside [1280, 9000]", c.TunMTU)
	}
	switch c.Mode {
	case ModeGlobal, ModeRule, ModeAppOnly:
	case "":
		c.Mode = ModeGlobal
	default:
		return fmt.Errorf("unknown mode %q", c.Mode)
	}
	if c.Mode == ModeAppOnly && len(c.SplitApps) == 0 {
		return errors.New("mode=app requires at least one package")
	}
	for i, s := range c.Rules.DirectCIDRs {
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("rules.directCidrs[%d] %q: %w", i, s, err)
		}
	}
	for i, s := range c.Rules.ProxyCIDRs {
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("rules.proxyCidrs[%d] %q: %w", i, s, err)
		}
	}
	if c.Rules.Final == "" {
		c.Rules.Final = "proxy"
	}
	if c.Rules.Final != "proxy" && c.Rules.Final != "direct" {
		return fmt.Errorf("rules.final must be proxy or direct, got %q", c.Rules.Final)
	}
	return c.Profile.validate()
}

func (p *Profile) validate() error {
	if p.ID == "" {
		return errors.New("profile.id is required")
	}
	switch p.Protocol {
	case ProtoWireGuard:
		if p.WG == nil {
			return errors.New("protocol wg requires the wireguard block")
		}
		if p.WG.Endpoint == "" {
			return errors.New("wireguard.endpoint is required")
		}
		if _, _, err := net.SplitHostPort(p.WG.Endpoint); err != nil {
			return fmt.Errorf("wireguard.endpoint %q: %w", p.WG.Endpoint, err)
		}
		if p.WG.PrivateKey == "" || p.WG.PeerPublicKey == "" {
			return errors.New("wireguard keys are required")
		}
		if len(p.WG.Address) == 0 {
			return errors.New("wireguard.address is required")
		}
	case ProtoReality:
		if p.Reality == nil || p.Reality.Server == "" || p.Reality.UUID == "" ||
			p.Reality.ServerName == "" || p.Reality.PublicKey == "" {
			return errors.New("reality requires server, uuid, serverName and publicKey")
		}
	case ProtoHysteria2:
		if p.Hysteria2 == nil || p.Hysteria2.Server == "" || p.Hysteria2.Password == "" {
			return errors.New("hysteria2 requires server and password")
		}
	case ProtoShadowsocks:
		if p.Shadowsocks == nil || p.Shadowsocks.Server == "" || p.Shadowsocks.Method == "" {
			return errors.New("shadowsocks requires server and method")
		}
	default:
		return fmt.Errorf("unknown protocol %q", p.Protocol)
	}
	return nil
}

// Parse decodes and validates a config document.
func Parse(b []byte) (*EngineConfig, error) {
	var c EngineConfig
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// MTUOrDefault returns the configured MTU, or 1420 when unset. 1420 is the
// wg-quick default: 1500 minus 80 bytes of WireGuard overhead.
func (w *WireGuardProfile) MTUOrDefault() int {
	if w.MTU > 0 {
		return w.MTU
	}
	return 1420
}

// Keepalive returns the WireGuard keepalive interval, defaulting to 25s which
// is what keeps NAT mappings alive on carrier-grade NAT.
func (w *WireGuardProfile) Keepalive() time.Duration {
	if w.PersistentKeepalive <= 0 {
		return 25 * time.Second
	}
	return time.Duration(w.PersistentKeepalive) * time.Second
}
