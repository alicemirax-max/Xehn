// Package route decides, per connection, whether traffic goes through the
// tunnel or out the physical interface.
//
// The lookup is a binary radix trie keyed on address bits. A lookup costs one
// memory access per address bit (32 or 128), independent of how many prefixes
// are loaded — the previous implementation scanned ~8000 CN CIDRs linearly and
// burned 60% of connect-time CPU doing it.
package route

import (
	"net/netip"
	"strings"
	"sync/atomic"
)

// Decision is the router's verdict for one destination.
type Decision uint8

const (
	// Direct sends the connection out the underlying network.
	Direct Decision = iota
	// Proxy sends the connection through the tunnel.
	Proxy
	// unset marks a trie node with no decision of its own.
	unset Decision = 255
)

func (d Decision) String() string {
	if d == Proxy {
		return "proxy"
	}
	return "direct"
}

// Router is an immutable snapshot. Rebuild on settings change and swap the
// pointer; reads are lock-free.
type Router struct {
	v4, v6  *node
	directD []string
	proxyD  []string
	final   Decision

	hits   atomic.Uint64
	misses atomic.Uint64
}

// node is one bit of an address. children is lazily allocated because most
// nodes on a real routing table have exactly one child.
type node struct {
	child [2]*node
	dec   Decision
}

// Config is the input to Build.
type Config struct {
	DirectCIDRs   []string
	ProxyCIDRs    []string
	DirectDomains []string
	ProxyDomains  []string
	Final         string
}

// Build compiles a config. Malformed CIDRs are skipped: a subscription with one
// typo must still route every other entry.
func Build(c Config) *Router {
	r := &Router{final: Proxy}
	if c.Final == "direct" {
		r.final = Direct
	}

	// Direct first, proxy second so an explicit proxy entry overwrites a
	// broader direct entry at the same prefix length.
	for _, s := range c.DirectCIDRs {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
			r.insert(p.Masked(), Direct)
		}
	}
	for _, s := range c.ProxyCIDRs {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
			r.insert(p.Masked(), Proxy)
		}
	}

	r.directD = normalizeDomains(c.DirectDomains)
	r.proxyD = normalizeDomains(c.ProxyDomains)
	return r
}

func (r *Router) insert(p netip.Prefix, d Decision) {
	a := p.Addr().Unmap()
	bits := p.Bits()
	if p.Addr().Is4In6() {
		bits -= 96
	}

	if a.Is4() {
		if r.v4 == nil {
			r.v4 = &node{dec: unset}
		}
		v4 := a.As4()
		insertBits(r.v4, v4[:], bits, d)
		return
	}
	if r.v6 == nil {
		r.v6 = &node{dec: unset}
	}
	b := a.As16()
	insertBits(r.v6, b[:], bits, d)
}

func insertBits(root *node, addr []byte, bits int, d Decision) {
	n := root
	for i := 0; i < bits; i++ {
		bit := (addr[i/8] >> (7 - uint(i%8))) & 1
		if n.child[bit] == nil {
			n.child[bit] = &node{dec: unset}
		}
		n = n.child[bit]
	}
	n.dec = d
}

// RouteIP returns the decision for a bare address.
func (r *Router) RouteIP(a netip.Addr) Decision {
	if a.Is4In6() {
		a = a.Unmap()
	}
	if !a.IsValid() {
		r.misses.Add(1)
		return r.final
	}
	if a.Is4() {
		b := a.As4()
		if d, ok := lookup(r.v4, b[:]); ok {
			r.hits.Add(1)
			return d
		}
	} else {
		b := a.As16()
		if d, ok := lookup(r.v6, b[:]); ok {
			r.hits.Add(1)
			return d
		}
	}
	r.misses.Add(1)
	return r.final
}

// lookup walks address bits and remembers the deepest assigned decision, which
// is what makes longest-prefix-match work with a single pass.
func lookup(root *node, addr []byte) (Decision, bool) {
	if root == nil {
		return 0, false
	}
	best := unset
	n := root
	for i := 0; i < len(addr)*8; i++ {
		if n.dec != unset {
			best = n.dec
		}
		bit := (addr[i/8] >> (7 - uint(i%8))) & 1
		n = n.child[bit]
		if n == nil {
			return best, best != unset
		}
	}
	if n.dec != unset {
		best = n.dec
	}
	return best, best != unset
}

// RouteHost combines domain and address signals. A domain match wins: the
// domain is what the user configured, the CIDR table is a fallback for
// literals and unresolved dials.
func (r *Router) RouteHost(host string, a netip.Addr) Decision {
	if d, ok := r.matchDomain(host); ok {
		return d
	}
	return r.RouteIP(a)
}

func (r *Router) matchDomain(host string) (Decision, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return 0, false
	}
	if (host[0] >= '0' && host[0] <= '9') || strings.IndexByte(host, ':') >= 0 {
		return 0, false // literal address, not a name
	}
	for _, d := range r.proxyD {
		if suffixMatch(host, d) {
			return Proxy, true
		}
	}
	for _, d := range r.directD {
		if suffixMatch(host, d) {
			return Direct, true
		}
	}
	return 0, false
}

// suffixMatch reports whether host equals d or is a subdomain of it. The dot
// check stops "notbaidu.cn" matching "baidu.cn".
func suffixMatch(host, d string) bool {
	if len(host) < len(d) || host[len(host)-len(d):] != d {
		return false
	}
	if len(host) == len(d) {
		return true
	}
	return host[len(host)-len(d)-1] == '.'
}

// normalizeDomains lowercases, strips leading dots and sorts longest-first so
// the first suffix hit is the most specific.
func normalizeDomains(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(d, ".")))
		if d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	// Insertion sort by descending length: lists are tiny (tens of entries).
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && len(out[j]) > len(out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Final returns the catch-all decision.
func (r *Router) Final() Decision { return r.final }

// Stats exposes hit/miss counters for the diagnostics panel.
func (r *Router) Stats() (hits, misses uint64) {
	return r.hits.Load(), r.misses.Load()
}
