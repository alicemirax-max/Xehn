package trail.tun

import android.util.Log
import trail.tun.go.Mobile as GoMobile

/**
 * Bridges Android's socket protection into the Go engine.
 *
 * Why an object and not a lambda: gomobile generates a Java interface for the
 * engine's Protector type, so Kotlin must supply an object implementing it. The
 * indirection also keeps the "no VPN interface yet" case explicit: Protect
 * returns false until TunService has established an interface, and the engine
 * treats false as a hard failure rather than a warning.
 */
object SocketProtector : GoMobile.Protector {

    @Volatile
    private var delegate: ((Int) -> Boolean)? = null

    /** Installs the live protector. Called by TunService when the tun is up. */
    fun install(fn: (Int) -> Boolean) {
        delegate = fn
    }

    /** Clears it on disconnect so a stale fd is never reported as protected. */
    fun clear() {
        delegate = null
        GoMobile.resetProtectCache()
    }

    override fun protect(fd: Int): Boolean {
        val fn = delegate ?: return false
        val ok = runCatching { fn(fd) }.getOrElse {
            Log.w("SocketProtector", "protect($fd) threw: ${it.message}")
            false
        }
        if (!ok) Log.w("SocketProtector", "protect($fd) returned false")
        return ok
    }
}
