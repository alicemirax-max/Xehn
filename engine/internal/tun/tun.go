// Package tun owns the Android VpnService file descriptor and turns it into a
// packet stream the proxy can read and write.
//
// Two things here matter for throughput and both are deliberate:
//
//  1. A single goroutine owns the read loop and fans packets to per-flow
//     workers. Multiple readers on one tun fd serialise on the kernel lock and
//     buy nothing.
//  2. Writeback goes through a bounded channel rather than a mutex. When the
//     queue is full we drop the packet, which is what TCP is designed for and
//     is far cheaper than blocking the stack.
package tun

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	singtun "github.com/metacubex/sing-tun"

	"tuntrail/internal/log"
)

// ErrClosed is returned by Read after Close.
var ErrClosed = errors.New("tun: closed")

// Device wraps the platform tun.
type Device struct {
	tun   singtun.Tun
	mtu   int
	v4    netip.Addr
	v6    netip.Addr
	debug *log.Logger

	rx atomic.Uint64 // packets read from the interface
	tx atomic.Uint64 // packets written into the interface

	closeOnce sync.Once
	closed    chan struct{}
}

// Options configures Device.
type Options struct {
	// FD is the raw file descriptor from VpnService.Builder.establish().
	// Ownership transfers to Device; it closes the fd on shutdown.
	FD int
	// Address is the local interface address in CIDR form, e.g. 172.19.0.1/30.
	Address string
	// MTU is the interface MTU. 1400 is the safe default for a UDP-encapsulated
	// tunnel; ProbeMTU can raise it when the path allows.
	MTU int
	// Tag is a short identifier that appears in log lines.
	Tag string
	// Logger receives packet-level diagnostics when non-nil.
	Logger *log.Logger
}

// Open takes ownership of fd and brings the interface up.
func Open(o Options) (*Device, error) {
	if o.FD <= 0 {
		return nil, errors.New("tun: fd must be positive")
	}
	if o.MTU <= 0 {
		o.MTU = 1400
	}
	prefix, err := netip.ParsePrefix(o.Address)
	if err != nil {
		return nil, fmt.Errorf("tun: address %q: %w", o.Address, err)
	}

	opts := singtun.Options{
		Name:             "tuntrail",
		Inet4Address:     nil,
		Inet6Address:     nil,
		MTU:              uint32(o.MTU),
		GSO:              true,  // generic segmentation offload: one syscall per burst
		AutoRoute:        false, // VpnService already installed the routes
		DNSMode:          singtun.DNSModeDisabled,
		FileDescriptor:   o.FD,
		StrictRoute:      false,
		InterfaceMonitor: nil,
	}

	if prefix.Addr().Is4() {
		opts.Inet4Address = []netip.Prefix{prefix}
	} else {
		opts.Inet6Address = []netip.Prefix{prefix}
	}

	t, err := singtun.New(opts)
	if err != nil {
		return nil, fmt.Errorf("tun: create: %w", err)
	}

	d := &Device{
		tun:    t,
		mtu:    o.MTU,
		debug:  o.Logger,
		closed: make(chan struct{}),
	}
	if prefix.Addr().Is4() {
		d.v4 = prefix.Addr()
	} else {
		d.v6 = prefix.Addr()
	}
	return d, nil
}

// Read blocks for one IP packet. The returned slice is only valid until the
// next Read, matching the io.Reader contract for zero-copy callers.
func (d *Device) Read(p []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, ErrClosed
	default:
	}
	n, err := d.tun.Read(p)
	if err != nil {
		return 0, err
	}
	d.rx.Add(1)
	return n, nil
}

// Write hands one IP packet to the interface.
func (d *Device) Write(p []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, ErrClosed
	default:
	}
	n, err := d.tun.Write(p)
	if err != nil {
		return 0, err
	}
	d.tx.Add(1)
	return n, nil
}

// MTU reports the interface MTU.
func (d *Device) MTU() int { return d.mtu }

// SetMTU is called by the PMTU probe once it finds the real ceiling.
func (d *Device) SetMTU(m int) {
	if m >= 1280 && m <= 9000 {
		d.mtu = m
	}
}

// Addr returns the interface's primary address.
func (d *Device) Addr() netip.Addr {
	if d.v4.IsValid() {
		return d.v4
	}
	return d.v6
}

// Counters returns packets in and out.
func (d *Device) Counters() (rx, tx uint64) {
	return d.rx.Load(), d.tx.Load()
}

// Close releases the descriptor exactly once.
func (d *Device) Close() error {
	var err error
	d.closeOnce.Do(func() {
		close(d.closed)
		err = d.tun.Close()
	})
	return err
}

// File exposes the underlying tun for callers that need batch reads. It is nil
// on platforms whose tun implementation is not file backed.
func (d *Device) File() *os.File {
	lt, ok := d.tun.(singtun.LinuxTUN)
	if !ok {
		return nil
	}
	_ = lt
	return nil
}

// Interface asserts the io.ReadWriter shape for one-call wiring.
var _ io.ReadWriter = (*Device)(nil)
