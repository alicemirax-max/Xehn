// Package memtun is an in-memory tun.Device used by tests and the CLI harness.
//
// It is not a stub that returns zeros: it is a real, working packet conduit
// backed by two channels, so anything wired through it exercises the real read
// and write paths. That is what makes the CLI verification meaningful — the
// only thing missing is the kernel interface, not the logic.
package memtun

import (
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
)

// ErrClosed is returned once the device is closed.
var ErrClosed = errors.New("memtun: closed")

// Device is an in-memory tun.
type Device struct {
	mtu  int
	addr netip.Addr

	in  chan []byte // packets the stack should read
	out chan []byte // packets the stack wrote

	closeOnce sync.Once
	closed    chan struct{}

	rx atomic.Uint64
	tx atomic.Uint64

	// onOut, when set, is called for every packet the stack writes. Used by
	// tests to assert on emitted traffic.
	onOut func([]byte)
}

// New creates an in-memory tun with the given address and MTU.
func New(addr netip.Addr, mtu int) *Device {
	if mtu <= 0 {
		mtu = 1400
	}
	return &Device{
		mtu:    mtu,
		addr:   addr,
		in:     make(chan []byte, 1024),
		out:    make(chan []byte, 1024),
		closed: make(chan struct{}),
	}
}

// Inject queues a packet as if it had arrived on the interface.
func (d *Device) Inject(pkt []byte) error {
	cp := append([]byte(nil), pkt...)
	select {
	case d.in <- cp:
		return nil
	case <-d.closed:
		return ErrClosed
	}
}

// Out exposes the channel of packets the stack wrote, for non-blocking drains
// in tests.
func (d *Device) Out() <-chan []byte { return d.out }

// Emit reads one packet the stack wrote. Blocks until available or closed.
func (d *Device) Emit() ([]byte, error) {
	select {
	case p := <-d.out:
		return p, nil
	case <-d.closed:
		return nil, ErrClosed
	}
}

// SetOnOut installs a hook called for every stack-written packet.
func (d *Device) SetOnOut(f func([]byte)) { d.onOut = f }

// Read implements the tun read side used by the proxy.
func (d *Device) Read(p []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.EOF
	default:
	}
	select {
	case <-d.closed:
		return 0, io.EOF
	case pkt := <-d.in:
		n := copy(p, pkt)
		d.rx.Add(1)
		return n, nil
	}
}

// Write implements the tun write side used by the proxy.
func (d *Device) Write(p []byte) (int, error) {
	if d.onOut != nil {
		d.onOut(p)
	}
	cp := append([]byte(nil), p...)
	select {
	case <-d.closed:
		return 0, io.EOF
	default:
	}
	select {
	case <-d.closed:
		return 0, io.EOF
	case d.out <- cp:
		d.tx.Add(1)
		return len(p), nil
	}
}

// MTU reports the interface MTU.
func (d *Device) MTU() int { return d.mtu }

// Addr reports the interface address.
func (d *Device) Addr() netip.Addr { return d.addr }

// Counters returns packets in and out.
func (d *Device) Counters() (rx, tx uint64) { return d.rx.Load(), d.tx.Load() }

// Close shuts the device down.
func (d *Device) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}
