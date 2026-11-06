// Package engine is the process-wide controller the Kotlin layer talks to.
//
// It owns exactly one live connection at a time. Every state transition is
// reported through a single status callback so the UI never has to poll the
// JNI bridge for two things and see them disagree.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"tuntrail/internal/config"
	"tuntrail/internal/log"
	"tuntrail/internal/proto/hysteria2"
	"tuntrail/internal/proto/realis"
	"tuntrail/internal/proxy"
	"tuntrail/internal/route"
	"tuntrail/internal/tun"
	"tuntrail/internal/tunnel"
)

// State is the connection lifecycle, mirrored 1:1 by the Kotlin sealed class.
type State string

const (
	StateIdle       State = "idle"
	StateConnecting State = "connecting"
	StateConnected  State = "connected"
	StateStopping   State = "stopping"
	StateError      State = "error"
)

// Status is the snapshot pushed to the UI.
type Status struct {
	State       State  `json:"state"`
	ProfileID   string `json:"profileId,omitempty"`
	ProfileName string `json:"profileName,omitempty"`
	Protocol    string `json:"protocol,omitempty"`

	// HandshakeMS is how long the tunnel handshake took.
	HandshakeMS uint32 `json:"handshakeMs,omitempty"`
	// MTU is the value actually in use, after the probe if it ran.
	MTU int `json:"mtu,omitempty"`
	// ExitIP is the observed egress address once known.
	ExitIP string `json:"exitIp,omitempty"`

	RxBytes uint64 `json:"rxBytes"`
	TxBytes uint64 `json:"txBytes"`
	UptimeS uint64 `json:"uptimeS"`

	// Conns is the number of live forwarded connections.
	Conns int64 `json:"conns"`

	// Error is the user-facing failure text when State is StateError.
	Error string `json:"error,omitempty"`
}

// Hooks are the Android-side callbacks. Every field is optional.
type Hooks struct {
	// Protect exempts an outbound socket fd from the VPN it feeds. Without it
	// the tunnel handshake loops into its own tun and never completes.
	Protect func(fd int) bool
	// Status is called on every state transition and on the periodic tick.
	Status func(Status)
}

// Engine is the controller. Create one per process.
type Engine struct {
	log   *log.Logger
	hooks Hooks

	mu      sync.Mutex
	cfg     *config.EngineConfig
	device  tunnel.Device
	proxy   *proxy.Proxy
	tunDev  *tun.Device
	state   State
	started time.Time
	lastErr string

	stopOnce sync.Once
	stopCh   chan struct{}

	// gauges updated by the ticker
	rxBps atomic.Uint64
	txBps atomic.Uint64
}

// New creates an engine with the given logger and hooks.
func New(l *log.Logger, h Hooks) *Engine {
	if l == nil {
		l = log.New(512, log.Info)
	}
	return &Engine{log: l, hooks: h, state: StateIdle, stopCh: make(chan struct{})}
}

// Log exposes the logger so the UI can read the ring buffer.
func (e *Engine) Log() *log.Logger { return e.log }

// Start brings a connection up. It returns as soon as the tunnel is live; the
// data plane keeps running in the background.
func (e *Engine) Start(fd int, cfgJSON string) error {
	cfg, err := config.Parse([]byte(cfgJSON))
	if err != nil {
		e.fail(err)
		return err
	}

	e.mu.Lock()
	if e.state == StateConnecting || e.state == StateConnected {
		e.mu.Unlock()
		return errors.New("engine: already connected")
	}
	e.cfg = cfg
	e.state = StateConnecting
	e.started = time.Now()
	e.lastErr = ""
	e.mu.Unlock()

	e.emit()

	dev, err := e.openTunnel(context.Background(), cfg)
	if err != nil {
		e.fail(err)
		return err
	}

	tunDev, err := tun.Open(tun.Options{
		FD:      fd,
		Address: cfg.TunAddress,
		MTU:     cfg.TunMTU,
		Logger:  e.log,
	})
	if err != nil {
		_ = dev.Close()
		e.fail(err)
		return err
	}

	router := route.Build(route.Config{
		DirectCIDRs:   cfg.Rules.DirectCIDRs,
		ProxyCIDRs:    cfg.Rules.ProxyCIDRs,
		DirectDomains: cfg.Rules.DirectDomains,
		ProxyDomains:  cfg.Rules.ProxyDomains,
		Final:         cfg.Rules.Final,
	})

	px, err := proxy.Start(proxy.Options{
		Tun:       tunDev,
		Device:    dev,
		Router:    router,
		LocalAddr: tunDev.Addr(),
		MTU:       tunDev.MTU(),
		Logger:    e.log,
	})
	if err != nil {
		_ = tunDev.Close()
		_ = dev.Close()
		e.fail(err)
		return err
	}

	e.mu.Lock()
	e.device = dev
	e.proxy = px
	e.tunDev = tunDev
	e.state = StateConnected
	e.mu.Unlock()

	e.log.Infof("engine", "connected: proto=%s profile=%s", cfg.Profile.Protocol, cfg.Profile.Name)
	e.emit()
	go e.tick()
	return nil
}

// Stop tears the connection down. Safe to call when already stopped.
func (e *Engine) Stop() {
	e.mu.Lock()
	if e.state == StateIdle || e.state == StateStopping {
		e.mu.Unlock()
		return
	}
	e.state = StateStopping
	px, dev, td := e.proxy, e.device, e.tunDev
	e.proxy, e.device, e.tunDev = nil, nil, nil
	e.mu.Unlock()

	e.emit()

	if px != nil {
		px.Stop()
	}
	if td != nil {
		_ = td.Close()
	}
	if dev != nil {
		_ = dev.Close()
	}

	e.mu.Lock()
	e.state = StateIdle
	e.mu.Unlock()
	e.log.Infof("engine", "stopped")
	e.emit()
}

// Status returns the current snapshot.
func (e *Engine) Status() Status {
	e.mu.Lock()
	st := Status{
		State:   e.state,
		Error:   e.lastErr,
		RxBytes: e.rxBps.Load(),
		TxBytes: e.txBps.Load(),
	}
	if e.cfg != nil {
		st.ProfileID = e.cfg.Profile.ID
		st.ProfileName = e.cfg.Profile.Name
		st.Protocol = e.cfg.Profile.Protocol
	}
	if e.tunDev != nil {
		st.MTU = e.tunDev.MTU()
	}
	if e.device != nil {
		ds := e.device.Stats()
		st.RxBytes = ds.RxBytes
		st.TxBytes = ds.TxBytes
		st.HandshakeMS = ds.HandshakeMS
		st.ExitIP = ds.ExitIP.String()
	}
	if e.proxy != nil {
		st.Conns = e.proxy.ConnCount()
	}
	if !e.started.IsZero() && e.state == StateConnected {
		st.UptimeS = uint64(time.Since(e.started).Seconds())
	}
	e.mu.Unlock()
	return st
}

// openTunnel dispatches on protocol. New protocols are added here and nowhere
// else in the engine.
func (e *Engine) openTunnel(ctx context.Context, cfg *config.EngineConfig) (tunnel.Device, error) {
	switch cfg.Profile.Protocol {
	case config.ProtoWireGuard:
		return openWireGuard(ctx, &cfg.Profile, e.hooks.Protect)
	case config.ProtoReality:
		return realis.New(&cfg.Profile)
	case config.ProtoHysteria2:
		return hysteria2.New(ctx, &cfg.Profile, e.hooks.Protect)
	case config.ProtoShadowsocks:
		return nil, fmt.Errorf("engine: protocol %q is not wired up yet", cfg.Profile.Protocol)
	default:
		return nil, fmt.Errorf("engine: unknown protocol %q", cfg.Profile.Protocol)
	}
}

// tick pushes a status sample once a second while connected.
func (e *Engine) tick() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-e.stopCh:
			return
		case <-t.C:
			e.mu.Lock()
			live := e.state == StateConnected
			e.mu.Unlock()
			if !live {
				return
			}
			e.emit()
		}
	}
}

func (e *Engine) fail(err error) {
	e.mu.Lock()
	e.state = StateError
	e.lastErr = err.Error()
	e.mu.Unlock()
	if e.log != nil {
		e.log.Errorf("engine", "%v", err)
	}
	e.emit()
}

func (e *Engine) emit() {
	if e.hooks.Status == nil {
		return
	}
	e.hooks.Status(e.Status())
}

// Close releases the engine permanently.
func (e *Engine) Close() {
	e.stopOnce.Do(func() { close(e.stopCh) })
	e.Stop()
}

// LocalAddr resolves the tun's local address for the proxy. Kept as a helper so
// the engine does not need to know netip details at the call site.
func LocalAddrOf(cfg *config.EngineConfig) (netip.Addr, error) {
	p, err := netip.ParsePrefix(cfg.TunAddress)
	if err != nil {
		return netip.Addr{}, err
	}
	return p.Addr(), nil
}
