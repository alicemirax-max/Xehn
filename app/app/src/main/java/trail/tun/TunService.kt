package trail.tun

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import trail.tun.R
import trail.tun.go.Mobile
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * TunService owns the Android VPN interface and forwards its descriptor to the
 * Go engine.
 *
 * Two responsibilities only:
 *  1. Build the tun interface (addresses, routes, DNS, per-app split).
 *  2. Keep the process alive with a foreground notification while connected.
 *
 * All packet processing, routing decisions and protocol work happen in Go. This
 * class deliberately contains no networking logic: if the tunnel misbehaves the
 * bug is in the engine, and that separation is what makes the engine testable
 * without an emulator.
 */
class TunService : VpnService() {

    companion object {
        private const val TAG = "TunService"
        private const val CHANNEL_ID = "tuntrail_status"
        private const val NOTIFICATION_ID = 0x7455

        const val ACTION_CONNECT = "trail.tun.CONNECT"
        const val ACTION_DISCONNECT = "trail.tun.DISCONNECT"

        const val EXTRA_CONFIG_JSON = "config_json"
        const val EXTRA_SPLIT_APPS = "split_apps"
        const val EXTRA_MODE = "mode"

        /** Latest engine status, so the activity can render immediately on resume. */
        @Volatile
        var lastStatus: String = """{"state":"idle"}"""

        /** Pushes a new status into the activity's collector. */
        @Volatile
        var onStatus: ((String) -> Unit)? = null
    }

    private var tun: ParcelFileDescriptor? = null
    private var connected = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> startTunnel(intent)
            ACTION_DISCONNECT -> stopTunnel()
            else -> if (!connected) stopSelf()
        }
        return START_STICKY
    }

    private fun startTunnel(intent: Intent) {
        val cfg = intent.getStringExtra(EXTRA_CONFIG_JSON) ?: return
        val mode = intent.getStringExtra(EXTRA_MODE) ?: "global"
        val splitApps = intent.getStringArrayExtra(EXTRA_SPLIT_APPS) ?: emptyArray()

        // Establish the interface first: if the user revoked consent this
        // throws, and we must not leave the engine half-started.
        val fd = buildTun(mode, splitApps)
        if (fd == null) {
            publish("""{"state":"error","error":"VPN permission denied"}""")
            stopSelf()
            return
        }
        tun = fd

        try {
            // The engine takes ownership of the descriptor. Kotlin must not
            // close it independently or the Go side reads from a dead fd.
            Mobile.start(fd.fd, cfg)
            connected = true
            startForeground(NOTIFICATION_ID, buildNotification("Connecting…"))
        } catch (t: Throwable) {
            Log.e(TAG, "engine start failed", t)
            closeTun()
            publish("""{"state":"error","error":"${t.message?.replace("\"", "'")}"}""")
            stopSelf()
        }
    }

    /**
     * Builds the tun interface.
     *
     * Route 0.0.0.0/0 plus ::/0 puts everything in the tunnel; the engine's
     * router then decides per connection whether to proxy or to send it back out
     * the physical interface. That is deliberate: doing the split here would
     * require the kernel to know about domains, which it cannot.
     */
    private fun buildTun(mode: String, splitApps: Array<String>): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("TunTrail")
            .setMtu(1400)
            .addAddress("172.19.0.1", 30)
            .addRoute("0.0.0.0", 0)

        // IPv6 only when the stack will handle it; a /128 route on a device
        // with no v6 connectivity just creates DNS timeouts.
        runCatching {
            builder.addAddress("fd00::1", 126)
            builder.addRoute("::", 0)
        }

        // A non-zero DNS server makes Android route DNS into the tun. The engine
        // intercepts :53 and answers through its own resolver.
        builder.addDnsServer("172.19.0.2")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        builder.setBlocking(true)

        if (mode == "app" && splitApps.isNotEmpty()) {
            // Per-app mode: only these apps enter the tunnel. Everything else
            // is untouched by the VPN, which is the whole point of split mode.
            builder.addDisallowedApplication(packageName)
            splitApps.forEach { pkg ->
                runCatching { builder.addAllowedApplication(pkg) }
                    .onFailure { Log.w(TAG, "cannot split $pkg: ${it.message}") }
            }
        } else {
            // Do not tunnel our own traffic: the engine dials out through the
            // radio and would otherwise re-enter this interface.
            builder.addDisallowedApplication(packageName)
        }

        return runCatching { builder.establish() }
            .onFailure { Log.e(TAG, "establish failed", it) }
            .getOrNull()
    }

    private fun stopTunnel() {
        if (connected) {
            runCatching { Mobile.stop() }
            connected = false
        }
        closeTun()
        publish("""{"state":"idle"}""")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun closeTun() {
        runCatching { tun?.close() }
        tun = null
    }

    override fun onRevoke() {
        // The system withdraws consent when another VPN takes over or the user
        // switches it off in settings. The tunnel is already dead at this point.
        Log.w(TAG, "VPN permission revoked")
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    private fun publish(status: String) {
        lastStatus = status
        onStatus?.invoke(status)
        updateNotification(status)
    }

    private fun buildNotification(text: String): Notification =
        NotificationCompat.Builder(this, ensureChannel())
            .setContentTitle("TunTrail")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(
                PendingIntent.getActivity(
                    this, 0,
                    Intent(this, Class.forName("trail.tun.MainActivity")),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
            )
            .build()

    private fun updateNotification(status: String) {
        val text = when {
            status.contains("\"connected\"") -> "Connected"
            status.contains("\"connecting\"") -> "Connecting…"
            status.contains("\"error\"") -> "Connection error"
            else -> "Disconnected"
        }
        runCatching {
            val nm = getSystemService(NotificationManager::class.java)
            nm.notify(NOTIFICATION_ID, buildNotification(text))
        }
    }

    private fun ensureChannel(): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(
                        CHANNEL_ID, "Connection status",
                        NotificationManager.IMPORTANCE_LOW
                    ).apply { setShowBadge(false) }
                )
            }
        }
        return CHANNEL_ID
    }
}
