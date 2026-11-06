package trail.tun

import android.app.Application
import android.util.Log
import trail.tun.go.mobile.Mobile as GoMobile

/**
 * Wires the socket protector into the engine at process start.
 *
 * This lives in Application rather than the activity because TunService can be
 * started without the UI (quick settings, or a restart after the process was
 * killed) and must still be able to protect its own sockets. A protector that is
 * registered late would leak the first handshake outside the tunnel.
 */
class TrailApp : Application() {

    override fun onCreate() {
        super.onCreate()
        GoMobile.registerProtector(SocketProtector)
        Log.i("TrailApp", "engine protector registered")
    }
}
