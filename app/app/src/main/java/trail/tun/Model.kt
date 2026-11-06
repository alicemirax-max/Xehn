package trail.tun

import androidx.compose.runtime.Immutable

/**
 * The engine's status document, parsed.
 *
 * Mirrors engine.Status in Go. Every field is optional because the UI legitimately
 * receives a status before the engine has filled everything in, and a half-empty
 * card is better than a crash.
 */
@Immutable
data class VpnStatus(
    val state: String = "idle",
    val profileId: String = "",
    val profileName: String = "",
    val protocol: String = "",
    val handshakeMs: Int = 0,
    val mtu: Int = 0,
    val exitIp: String = "",
    val rxBytes: Long = 0,
    val txBytes: Long = 0,
    val uptimeS: Long = 0,
    val conns: Long = 0,
    val error: String = "",
) {
    val isConnected get() = state == "connected"
    val isConnecting get() = state == "connecting"
    val isBusy get() = isConnected || isConnecting
    val hasError get() = state == "error" && error.isNotEmpty()

    /** Downstream + upstream in bytes per second, sampled between two statuses. */
    fun rates(previous: VpnStatus?, elapsedSec: Float): Pair<Long, Long> {
        if (previous == null || elapsedSec <= 0f) return 0L to 0L
        val down = ((rxBytes - previous.rxBytes).coerceAtLeast(0)) / elapsedSec
        val up = ((txBytes - previous.txBytes).coerceAtLeast(0)) / elapsedSec
        return down.toLong() to up.toLong()
    }
}

/**
 * One saved node. The UI edits these; the engine only ever sees the serialised
 * form of the selected one.
 */
@Immutable
data class Node(
    val id: String,
    val name: String,
    val protocol: String,
    val host: String,
    /** Raw protocol config as JSON, already in the engine's schema. */
    val configJson: String,
    val latencyMs: Int = -1,
    val pinned: Boolean = false,
)

/** Split-tunnel mode. Mirrors config.Mode in Go. */
enum class TunnelMode(val wire: String) {
    GLOBAL("global"),
    RULE("rule"),
    APP("app");

    val label: String
        get() = when (this) {
            GLOBAL -> "Global"
            RULE -> "Rules"
            APP -> "Per-app"
        }
}
