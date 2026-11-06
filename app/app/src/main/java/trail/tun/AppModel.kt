package trail.tun

import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.ViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import trail.tun.go.Mobile

/**
 * Application state holder.
 *
 * Responsibilities are narrow on purpose: hold status, hold the node list, start
 * and stop the service. Every decision about packets or protocols belongs to the
 * Go engine; this class must never grow networking logic or the layering that
 * makes the engine testable without a device collapses.
 */
class AppModel(private val appContext: Context) {

    private val _status = MutableStateFlow(VpnStatus())
    val status: StateFlow<VpnStatus> = _status.asStateFlow()

    private val _selectedNode = MutableStateFlow<Node?>(null)
    val selectedNode: StateFlow<Node?> = _selectedNode.asStateFlow()

    private val _nodes = MutableStateFlow<List<Node>>(emptyList())
    val nodes: StateFlow<List<Node>> = _nodes.asStateFlow()

    private val _logs = MutableStateFlow<List<String>>(emptyList())
    val logs: StateFlow<List<String>> = _logs.asStateFlow()

    /** True when Android has granted VPN consent and no re-prompt is needed. */
    fun hasConsent(): Boolean = VpnService.prepare(appContext) == null

    /** The intent the activity must launch for consent, or null when already granted. */
    fun consentIntent(): Intent? = VpnService.prepare(appContext)

    /**
     * Parses a status document from the engine.
     *
     * Every field is read defensively: a malformed document must degrade to a
     * usable UI, never crash the activity, because this runs on a background
     * callback from JNI.
     */
    fun onStatusJson(json: String) {
        val parsed = runCatching {
            val o = JSONObject(json)
            VpnStatus(
                state = o.optString("state", "idle"),
                profileId = o.optString("profileId", ""),
                profileName = o.optString("profileName", ""),
                protocol = o.optString("protocol", ""),
                handshakeMs = o.optInt("handshakeMs", 0),
                mtu = o.optInt("mtu", 0),
                exitIp = o.optString("exitIp", ""),
                rxBytes = o.optLong("rxBytes", 0),
                txBytes = o.optLong("txBytes", 0),
                uptimeS = o.optLong("uptimeS", 0),
                conns = o.optLong("conns", 0),
                error = o.optString("error", ""),
            )
        }.getOrElse { VpnStatus(state = "error", error = "status parse: ${it.message}") }

        _status.value = parsed
        TunService.lastStatus = json
    }

    /** Starts the tunnel with the selected node. */
    fun connect() {
        val node = _selectedNode.value ?: run {
            _status.value = _status.value.copy(state = "error", error = "Select a node first")
            return
        }

        val intent = Intent(appContext, TunService::class.java).apply {
            action = TunService.ACTION_CONNECT
            putExtra(TunService.EXTRA_CONFIG_JSON, node.configJson)
            putExtra(TunService.EXTRA_MODE, TunnelMode.GLOBAL.wire)
        }
        appContext.startForegroundService(intent)
    }

    fun disconnect() {
        val intent = Intent(appContext, TunService::class.java).apply {
            action = TunService.ACTION_DISCONNECT
        }
        appContext.startService(intent)
    }

    /** Adds a node parsed from a wg-quick config, returns an error string or null. */
    fun importWireGuard(text: String, name: String): String? {
        val json = try {
            Mobile.parseWireGuard(text)
        } catch (t: Throwable) {
            return t.message ?: "import failed"
        }
        if (json.isBlank()) return "empty config"

        val node = Node(
            id = "wg-" + System.currentTimeMillis(),
            name = name.ifBlank { "WireGuard" },
            protocol = "wg",
            host = runCatching {
                JSONObject(json).optJSONObject("wireguard")?.optString("endpoint").orEmpty()
            }.getOrDefault(""),
            configJson = wrapWireGuard(json),
        )
        _nodes.value = _nodes.value + node
        if (_selectedNode.value == null) _selectedNode.value = node
        return null
    }

    /**
     * Wraps the parsed wg-quick document into the engine's EngineConfig shape.
     *
     * The engine takes one whole config object per connection rather than a node
     * plus settings, which keeps the two sides from drifting: whatever the UI
     * serialises is exactly what the engine validates.
     */
    private fun wrapWireGuard(wgJson: String): String {
        val wg = JSONObject(wgJson)
        val root = JSONObject()
        root.put("mode", "global")
        root.put("tunAddress", Mobile.tunAddressFor(1))
        root.put("tunMtu", 1400)
        root.put("logLevel", "debug")
        root.put("mtuProbe", true)

        val profile = JSONObject()
        profile.put("id", "wg-" + System.currentTimeMillis())
        profile.put("name", "WireGuard")
        profile.put("protocol", "wg")
        profile.put("wireguard", wg)
        root.put("profile", profile)

        val dns = JSONObject()
        dns.put("servers", org.json.JSONArray().put("1.1.1.1"))
        dns.put("fakeIp", false)
        root.put("dns", dns)

        val rules = JSONObject()
        rules.put("final", "proxy")
        root.put("rules", rules)

        return root.toString()
    }

    fun selectNode(node: Node) {
        _selectedNode.value = node
    }

    fun refreshLogs() {
        _logs.value = runCatching {
            val raw = Mobile.logsJSON()
            val arr = JSONArray(raw)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                "${o.optString("msg")}"
            }
        }.getOrDefault(emptyList())
    }
}
