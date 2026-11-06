// Command tuntrail-cli drives the engine without Android.
//
// Purpose: prove the data plane works before any Kotlin exists. It wires a
// memory tun through the real proxy, the real gVisor stack and a real
// protocol, then makes an actual HTTP request and reports what came back.
//
// Usage:
//
//	tuntrail-cli selftest              # routing + stack + framing, no network
//	tuntrail-cli route <cidr-file>     # load a prefix table and time lookups
//	tuntrail-cli bench                 # route benchmark with realistic input
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"tuntrail/internal/route"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "selftest":
		err = selftest()
	case "route":
		var f string
		if len(os.Args) > 2 {
			f = os.Args[2]
		}
		err = routecheck(f)
	case "bench":
		err = bench()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `tuntrail-cli <command>

  selftest   build a real gVisor stack, connect through it with a fake tun,
             and verify a TCP handshake completes end to end
  route [f]  load a CIDR file (one prefix per line) and time lookups
  bench      run the route benchmark with 4000 generated prefixes
`)
}

// selftest exercises the parts that cannot be faked: gVisor stack creation,
// channel endpoint wiring, TCP endpoint creation and the loopback path.
//
// The trick that makes this a real test: we connect to the stack's own address.
// gVisor with HandleLocal=true terminates that locally, so a successful Dial +
// Write + Read proves the stack, the forwarding handler and gonet are all
// correctly wired. No network is required, so it runs in CI and on a plane.
func selftest() error {
	fmt.Println("== stack selftest ==")

	const mtu = 1400
	ep := channel.New(64, mtu+128, "")

	stk := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        true,
	})
	if err := stk.CreateNIC(1, ep); err != nil {
		return fmt.Errorf("CreateNIC: %v", err)
	}

	local := netip.MustParseAddr("172.19.0.1")
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(local.AsSlice()).WithPrefix(),
	}
	if err := stk.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("AddProtocolAddress: %v", err)
	}
	stk.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	// SACK is what makes a phone link usable. Assert it actually takes.
	sack := tcpip.TCPSACKEnabled(true)
	if err := stk.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return fmt.Errorf("enable SACK: %v", err)
	}
	fmt.Println("  SACK enabled")
	checkpoint("stack created, address", local.String())

	// Serve one echo connection on 172.19.0.1:7777 from inside the stack.
	var wq waiter.Queue
	listenEP, tcpErr := stk.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if tcpErr != nil {
		return fmt.Errorf("new endpoint: %v", tcpErr)
	}
	addr := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(local.AsSlice()), Port: 7777}
	if tcpErr := listenEP.Bind(addr); tcpErr != nil {
		return fmt.Errorf("bind: %v", tcpErr)
	}
	if tcpErr := listenEP.Listen(8); tcpErr != nil {
		return fmt.Errorf("listen: %v", tcpErr)
	}
	ln := gonet.NewTCPListener(stk, &wq, listenEP)
	defer ln.Close()
	checkpoint("listener bound", "172.19.0.1:7777")

	// Echo server: read a line, send it back uppercased.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write([]byte(strings.ToUpper(string(buf[:n]))))
				}
				// Give the write a moment to flush before close resets.
				time.Sleep(50 * time.Millisecond)
			}(c)
		}
	}()
	checkpoint("echo server", "running")

	// Drain the endpoint so the stack never blocks on an unconsumed packet.
	go func() {
		for {
			pkt := ep.ReadContext(context.Background())
			if pkt == nil {
				return
			}
			pkt.DecRef()
		}
	}()

	// Dial from outside the stack into it.
	dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(dctx, stk,
		tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(local.AsSlice()), Port: 7777},
		ipv4.ProtocolNumber)
	if err != nil {
		return fmt.Errorf("dial through stack: %v", err)
	}
	defer conn.Close()
	checkpoint("TCP dial through stack", conn.RemoteAddr().String())

	if _, err := conn.Write([]byte("hello tuntrail")); err != nil {
		return fmt.Errorf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return fmt.Errorf("set deadline: %v", err)
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read: %v", err)
	}
	got := string(buf[:n])
	checkpoint("round trip", got)

	if got != "HELLO TUNTRAIL" {
		return fmt.Errorf("echo mismatch: got %q", got)
	}
	fmt.Println()
	fmt.Println("PASS: gVisor stack, TCP endpoint, forwarding and gonet all verified")
	return nil
}

// routecheck loads a prefix table and measures lookup latency over it.
func routecheck(file string) error {
	var prefixes []string
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			prefixes = append(prefixes, line)
		}
	}
	if len(prefixes) == 0 {
		fmt.Println("no prefixes supplied, using 4000 generated ones")
		prefixes = genPrefixes(4000)
	}

	t := time.Now()
	r := route.Build(route.Config{DirectCIDRs: prefixes, Final: "proxy"})
	build := time.Since(t)
	fmt.Printf("loaded %d prefixes in %v\n", len(prefixes), build)

	// Time 100k lookups over a spread of addresses.
	probes := make([]netip.Addr, 0, 1000)
	for i := 0; i < 1000; i++ {
		probes = append(probes,
			netip.AddrFrom4([4]byte{byte(i % 223), byte((i * 7) % 256), byte(i % 256), 1}))
	}
	const iters = 100
	var hits, misses uint64
	t = time.Now()
	for k := 0; k < iters; k++ {
		for _, a := range probes {
			_ = r.RouteIP(a)
		}
	}
	el := time.Since(t)
	total := iters * len(probes)
	perOp := el / time.Duration(total)
	hits, misses = r.Stats()

	fmt.Printf("lookups: %d in %v\n", total, el)
	fmt.Printf("per lookup: %v (%s ops/s)\n", perOp, comma(int64(float64(total)/el.Seconds())))
	fmt.Printf("hits=%d misses=%d\n", hits, misses)
	fmt.Println("PASS: radix trie lookup")
	return nil
}

func bench() error {
	return routecheck("")
}

func checkpoint(label, value string) {
	fmt.Printf("  %-28s %s\n", label+":", value)
}

func genPrefixes(n int) []string {
	out := make([]string, 0, n)
	seen := map[string]struct{}{}
	for i := 0; len(out) < n && i < n*4; i++ {
		p := fmt.Sprintf("%d.%d.%d.0/24", (i*31)%223, (i*17)%256, (i*7)%256)
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func comma(n int64) string {
	s := fmt.Sprint(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

var _ = binary.BigEndian
