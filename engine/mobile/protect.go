package mobile

import (
	"fmt"
	"sync"
	"syscall"
)

// The JNI boundary cannot hand a Go function back to Kotlin directly, so the
// Kotlin side registers its VpnService.protect() as a package-level callback.
// Calling into the JVM for every socket is expensive at high rates, so results
// are cached by file descriptor: a given fd is either protected or it is not,
// and fds are recycled predictably by the kernel.

var (
	protectMu    sync.RWMutex
	protectFn    func(fd int) bool
	protectCache = make(map[int]bool)
)

// Protector is the Kotlin-side socket exemption, expressed as an interface
// because gomobile cannot bind a bare Go func type. The generated Java interface
// has one method, Protect(int):boolean.
type Protector interface {
	Protect(fd int) bool
}

// RegisterProtector installs the Kotlin-side protector. Passing nil clears it.
//
// Kotlin calls this once at startup with an object that forwards to
// vpnService.protect(fd). Every socket the engine opens passes through here
// before it is used, and a false result aborts the dial rather than leaking
// traffic outside the tunnel.
func RegisterProtector(p Protector) {
	protectMu.Lock()
	if p == nil {
		protectFn = nil
	} else {
		protectFn = p.Protect
	}
	protectCache = make(map[int]bool)
	protectMu.Unlock()
}

// protectSocket exempts fd from the VPN. Returns false when no protector is
// registered, which the callers treat as a hard error rather than a warning:
// an unprotected socket feeding its own tunnel is an infinite loop, not a
// degradation.
func protectSocket(fd int) bool {
	protectMu.RLock()
	fn := protectFn
	if cached, ok := protectCache[fd]; ok && fn != nil {
		protectMu.RUnlock()
		return cached
	}
	protectMu.RUnlock()

	if fn == nil {
		return false
	}

	ok := fn(fd)

	protectMu.Lock()
	// Bound the cache so a long session with many sockets does not grow without
	// limit; fds are small integers, so a reset is cheaper than an LRU.
	if len(protectCache) > 4096 {
		protectCache = make(map[int]bool)
	}
	protectCache[fd] = ok
	protectMu.Unlock()

	return ok
}

// ResetProtectCache forgets cached fd decisions. Called when the VPN interface
// is re-established, because the old fds refer to sockets that are already gone.
func ResetProtectCache() {
	protectMu.Lock()
	protectCache = make(map[int]bool)
	protectMu.Unlock()
}

// NewUDPProtector returns the function the Hysteria2/QUIC dialer needs: it takes
// a raw file descriptor and reports whether the socket is now exempt.
func NewUDPProtector() func(fd int) bool { return protectSocket }

// fdFromConn is a test seam: it extracts the fd from anything that exposes one.
func fdFromConn(c interface {
	SyscallConn() (syscall.RawConn, error)
}) (int, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var out int
	if err := rc.Control(func(fd uintptr) { out = int(fd) }); err != nil {
		return 0, err
	}
	if out == 0 {
		return 0, fmt.Errorf("no file descriptor")
	}
	return out, nil
}
