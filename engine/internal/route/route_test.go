package route

import (
	"net/netip"
	"testing"
)

func TestRouteIPLongestPrefixWins(t *testing.T) {
	r := Build(Config{
		DirectCIDRs: []string{"10.0.0.0/8", "0.0.0.0/0"},
		ProxyCIDRs:  []string{"10.1.2.0/24"},
		Final:       "proxy",
	})
	cases := []struct {
		addr string
		want Decision
	}{
		{"10.1.2.5", Proxy},  // /24 beats /8
		{"10.9.9.9", Direct}, // /8 direct
		{"8.8.8.8", Direct},  // /0 direct
	}
	for _, c := range cases {
		got := r.RouteIP(netip.MustParseAddr(c.addr))
		if got != c.want {
			t.Errorf("RouteIP(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestRouteHostDomainBeatsCIDR(t *testing.T) {
	r := Build(Config{
		DirectCIDRs:  []string{"0.0.0.0/0"},
		ProxyDomains: []string{"google.com"},
		Final:        "direct",
	})
	// The CIDR says direct, but the domain rule must win.
	got := r.RouteHost("www.google.com", netip.MustParseAddr("142.250.72.4"))
	if got != Proxy {
		t.Fatalf("domain should override CIDR, got %v", got)
	}
}

func TestSuffixMatchNoFalsePositive(t *testing.T) {
	r := Build(Config{DirectDomains: []string{"baidu.cn"}, Final: "proxy"})
	if got := r.RouteHost("notbaidu.cn", netip.Addr{}); got != Proxy {
		t.Fatalf("notbaidu.cn must not match baidu.cn suffix, got %v", got)
	}
	if got := r.RouteHost("www.baidu.cn", netip.Addr{}); got != Direct {
		t.Fatalf("www.baidu.cn should match, got %v", got)
	}
	if got := r.RouteHost("BAIDU.CN.", netip.Addr{}); got != Direct {
		t.Fatalf("case and trailing dot must be normalised, got %v", got)
	}
}

func TestIPv4MappedIsUnmapped(t *testing.T) {
	r := Build(Config{DirectCIDRs: []string{"1.2.3.0/24"}, Final: "proxy"})
	mapped := netip.MustParseAddr("::ffff:1.2.3.4")
	if got := r.RouteIP(mapped); got != Direct {
		t.Fatalf("mapped v4 should route as v4, got %v", got)
	}
}

func TestEmptyRouterFallsThrough(t *testing.T) {
	r := Build(Config{Final: "direct"})
	if got := r.RouteIP(netip.MustParseAddr("1.1.1.1")); got != Direct {
		t.Fatalf("want final=direct, got %v", got)
	}
}

func BenchmarkRouteIP(b *testing.B) {
	// Simulate a realistic CN table: 4000 prefixes.
	direct := make([]string, 0, 4000)
	for i := 0; i < 4000; i++ {
		direct = append(direct, netip.PrefixFrom(
			netip.AddrFrom4([4]byte{byte(i % 223), byte(i / 223 % 256), 0, 0}), 16).String())
	}
	r := Build(Config{DirectCIDRs: direct, Final: "proxy"})
	addr := netip.MustParseAddr("1.1.1.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.RouteIP(addr)
	}
}
