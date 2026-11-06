package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// WGQuick is the subset of a wg-quick config the importer needs.
//
// The mobile UI parses pasted configs so the user can drop in a .conf from any
// WireGuard tool. Parsing lives here rather than in mobile/ so the same code is
// unit-tested on the host.
type WGQuick struct {
	PrivateKey          string   `json:"privateKey"`
	Address             []string `json:"address"`
	DNS                 []string `json:"dns"`
	MTU                 int      `json:"mtu,omitempty"`
	PeerPublicKey       string   `json:"publicKey"`
	PeerPresharedKey    string   `json:"presharedKey,omitempty"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowedIPs"`
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"`
}

// ParseWGQuick reads a wg-quick style document.
//
// The format is INI with two sections, [Interface] and [Peer], and keys are
// case-insensitive. Unknown keys are ignored on purpose: configs in the wild
// carry Table, PreUp, PostUp and similar that we have no use for and should not
// reject.
func ParseWGQuick(text string) (*WGQuick, error) {
	var (
		out      WGQuick
		section  string
		sawIface bool
		sawPeer  bool
	)

	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			switch section {
			case "interface":
				sawIface = true
			case "peer":
				sawPeer = true
			}
			continue
		}

		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: missing '='", i+1)
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				out.PrivateKey = val
			case "address":
				out.Address = append(out.Address, splitList(val)...)
			case "dns":
				out.DNS = append(out.DNS, splitList(val)...)
			case "mtu":
				n, err := strconv.Atoi(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: mtu %q is not a number", i+1, val)
				}
				out.MTU = n
			}
		case "peer":
			switch key {
			case "publickey":
				out.PeerPublicKey = val
			case "presharedkey":
				out.PeerPresharedKey = val
			case "endpoint":
				out.Endpoint = val
			case "allowedips":
				out.AllowedIPs = append(out.AllowedIPs, splitList(val)...)
			case "persistentkeepalive":
				n, err := strconv.Atoi(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: keepalive %q is not a number", i+1, val)
				}
				out.PersistentKeepalive = n
			}
		default:
			return nil, fmt.Errorf("line %d: key outside any section", i+1)
		}
	}

	switch {
	case !sawIface:
		return nil, errors.New("no [Interface] section")
	case !sawPeer:
		return nil, errors.New("no [Peer] section")
	case out.PrivateKey == "":
		return nil, errors.New("[Interface] is missing PrivateKey")
	case out.PeerPublicKey == "":
		return nil, errors.New("[Peer] is missing PublicKey")
	case out.Endpoint == "":
		return nil, errors.New("[Peer] is missing Endpoint")
	case len(out.Address) == 0:
		return nil, errors.New("[Interface] is missing Address")
	}

	if len(out.AllowedIPs) == 0 {
		out.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	return &out, nil
}

func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
