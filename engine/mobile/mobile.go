// Package mobile is the single entry point the Kotlin layer binds to.
//
// gomobile only exposes types that satisfy its reflection rules: package-level
// functions, exported structs whose fields are of supported types, and methods
// with supported signatures. Everything here is deliberately primitive — strings,
// ints, bools, bytes — so the JNI boundary stays cheap and the Kotlin side needs
// no generated wrappers beyond what gomobile produces.
//
// The Kotlin side is a thin StateFlow holder: it forwards clicks here and renders
// whatever JSON comes back. No connection logic lives in Kotlin.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"tuntrail/internal/config"
	"tuntrail/internal/engine"
	"tuntrail/internal/log"
	"tuntrail/internal/proto/hysteria2"
	"tuntrail/internal/proto/realis"
	"tuntrail/internal/proto/wireguard"
	"tuntrail/internal/tunnel"
)

// StatusCallback receives every state change as a JSON document.
type StatusCallback interface {
	OnStatus(json string)
}

// LogCallback receives one log line at a time, already formatted.
type LogCallback interface {
	OnLog(line string)
}

var (
	mu      sync.Mutex
	eng     *engine.Engine
	statusC StatusCallback
	logC    LogCallback

	// lastStatus is replayed to a callback that attaches after Start, so the UI
	// never renders an empty screen because it subscribed a moment too late.
	lastStatus string
)

// Version reports the engine build version.
func Version() string { return "1.0.0" }

// SetStatusCallback installs the UI's status sink. Safe to call before or after
// Start; the most recent status is replayed immediately.
func SetStatusCallback(cb StatusCallback) {
	mu.Lock()
	statusC = cb
	last := lastStatus
	mu.Unlock()
	if cb != nil && last != "" {
		cb.OnStatus(last)
	}
}

// SetLogCallback installs the log sink. Existing buffered lines are replayed.
func SetLogCallback(cb LogCallback) {
	mu.Lock()
	logC = cb
	e := eng
	mu.Unlock()
	if cb == nil || e == nil {
		return
	}
	for _, entry := range e.Log().Snapshot() {
		cb.OnLog(formatEntry(entry))
	}
}

func formatEntry(e log.Entry) string {
	return e.At.Format("15:04:05.000") + " " + e.Level.String() + "/" + e.Tag + " " + e.Msg
}

// Start brings a connection up.
//
// fd is the file descriptor returned by VpnService.Builder.establish(). The
// engine takes ownership and closes it on stop.
//
// configJSON is the serialised EngineConfig; the UI owns the schema.
func Start(fd int, configJSON string) error {
	mu.Lock()
	if eng == nil {
		eng = engine.New(log.New(1024, log.Debug), engine.Hooks{
			Protect: protectSocket,
			Status:  emitStatus,
		})
	} else {
		// Re-attach hooks in case a previous engine was replaced.
	}
	e := eng
	mu.Unlock()

	if err := e.Start(fd, configJSON); err != nil {
		return err
	}
	return nil
}

// Stop tears the connection down. Safe to call at any time.
func Stop() {
	mu.Lock()
	e := eng
	mu.Unlock()
	if e != nil {
		e.Stop()
	}
}

// StatusJSON returns the current status snapshot as JSON.
func StatusJSON() string {
	mu.Lock()
	e := eng
	mu.Unlock()
	if e == nil {
		b, _ := json.Marshal(engine.Status{State: engine.StateIdle})
		return string(b)
	}
	b, err := json.Marshal(e.Status())
	if err != nil {
		return `{"state":"error","error":"status marshal failed"}`
	}
	return string(b)
}

// LogsJSON returns the retained log lines as a JSON array of objects.
func LogsJSON() string {
	mu.Lock()
	e := eng
	mu.Unlock()
	if e == nil {
		return "[]"
	}
	b, err := json.Marshal(e.Log().Snapshot())
	if err != nil {
		return "[]"
	}
	return string(b)
}

// ClearLogs empties the log ring.
func ClearLogs() {
	mu.Lock()
	e := eng
	mu.Unlock()
	if e != nil {
		e.Log().Clear()
	}
}

func emitStatus(s engine.Status) {
	b, err := json.Marshal(s)
	if err != nil {
		return
	}
	payload := string(b)

	mu.Lock()
	lastStatus = payload
	cb := statusC
	mu.Unlock()

	if cb != nil {
		cb.OnStatus(payload)
	}
}

// TestConfig validates a configuration document without connecting. The UI calls
// this on every edit so a broken profile is caught before the user hits connect.
//
// Returns an empty string on success, or a human-readable error.
func TestConfig(configJSON string) string {
	if _, err := config.Parse([]byte(configJSON)); err != nil {
		return err.Error()
	}
	return ""
}

// ParseWireGuard extracts the usable fields from a wg-quick style config so the
// import screen does not have to reimplement the parser in Kotlin.
//
// Returns JSON: {"privateKey":..,"address":[..],"endpoint":..,"publicKey":..,"dns":[..]}
//
// gomobile only allows a single non-error return value, so failures come back
// through the error channel and the UI renders err.Error() directly.
func ParseWireGuard(text string) (string, error) {
	out, err := config.ParseWGQuick(text)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ProbeResultJSON measures one profile's handshake and returns timing.
//
// This is what the node list's "test" button calls. It opens a tunnel, performs
// the handshake, measures it, and closes — no traffic is forwarded.
func ProbeResultJSON(configJSON string) string {
	type result struct {
		ID          string `json:"id"`
		HandshakeMS int64  `json:"handshakeMs"`
		Err         string `json:"error,omitempty"`
	}

	cfg, err := config.Parse([]byte(configJSON))
	if err != nil {
		b, _ := json.Marshal(result{Err: err.Error()})
		return string(b)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dev, err := openForProbe(ctx, cfg)
	if err != nil {
		b, _ := json.Marshal(result{ID: cfg.Profile.ID, Err: err.Error()})
		return string(b)
	}
	defer dev.Close()

	p, ok := dev.(tunnel.Prober)
	if !ok {
		b, _ := json.Marshal(result{ID: cfg.Profile.ID, Err: "protocol does not support probing"})
		return string(b)
	}

	pr := p.Probe(ctx)
	r := result{ID: cfg.Profile.ID, HandshakeMS: int64(pr.HandshakeMS)}
	if pr.Err != nil {
		r.Err = pr.Err.Error()
	}
	b, _ := json.Marshal(r)
	return string(b)
}

// LocalIP resolves the device's current physical interface address. The UI shows
// it next to the exit IP so the user can see the difference.
func LocalIP() string {
	// The JNI layer cannot cheaply enumerate Android interfaces from Go; the
	// Kotlin side answers this one itself. Returning empty keeps the contract
	// honest rather than shelling out to netlink.
	return ""
}

// TunAddressFor builds a deterministic /30 for the tun interface from a seed,
// so consecutive connects reuse the same subnet and Android does not keep
// allocating new routes.
func TunAddressFor(seed int) string {
	// 172.19.<n>.1/30 with n bounded to 1..254.
	n := seed%254 + 1
	a := netip.AddrFrom4([4]byte{172, 19, byte(n), 1})
	return netip.PrefixFrom(a, 30).String()
}

// SocksPort returns a stable loopback port for the diagnostics SOCKS listener.
func SocksPort() int { return 10808 }

var errNotWired = errors.New("not wired")

var _ = fmt.Sprint
var _ = strconv.Itoa

// openForProbe builds a device for a single handshake measurement. It is kept
// here rather than in the engine because probing deliberately bypasses the
// connection state machine: no tun, no proxy, no status transitions.
func openForProbe(ctx context.Context, cfg *config.EngineConfig) (tunnel.Device, error) {
	switch cfg.Profile.Protocol {
	case config.ProtoWireGuard:
		return wireguard.New(ctx, &cfg.Profile, protectSocket)
	case config.ProtoReality:
		return realis.New(&cfg.Profile)
	case config.ProtoHysteria2:
		return hysteria2.New(ctx, &cfg.Profile, protectSocket)
	default:
		return nil, fmt.Errorf("probe: protocol %q is not supported", cfg.Profile.Protocol)
	}
}
