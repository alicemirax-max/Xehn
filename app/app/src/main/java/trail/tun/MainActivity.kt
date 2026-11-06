package trail.tun

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.delay

class MainActivity : ComponentActivity() {

    private lateinit var model: AppModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        model = AppModel(applicationContext)

        // Status arrives from the service as raw JSON; the model parses it and
        // exposes a StateFlow the UI can collect.
        TunService.onStatus = { json -> model.onStatusJson(json) }
        model.onStatusJson(TunService.lastStatus)

        setContent {
            TunTrailTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AppRoot(model)
                }
            }
        }
    }

    override fun onDestroy() {
        TunService.onStatus = null
        super.onDestroy()
    }
}

/**
 * Top-level composable. Keeps the screen graph flat: one route today, a
 * sealed class the moment a second screen exists.
 */
@Composable
private fun AppRoot(model: AppModel) {
    val status by model.status.collectAsStateWithLifecycle()
    val node by model.selectedNode.collectAsStateWithLifecycle()

    // Rate sampling: status arrives once a second, so a 1 s ticker between
    // snapshots is enough and avoids a second timer fighting the first.
    var downBps by remember { mutableLongStateOf(0L) }
    var upBps by remember { mutableLongStateOf(0L) }
    var previous by remember { mutableStateOf<VpnStatus?>(null) }

    LaunchedEffect(status) {
        val (d, u) = status.rates(previous, 1f)
        downBps = d
        upBps = u
        previous = status
    }

    var showingSettings by remember { mutableStateOf(false) }

    if (showingSettings) {
        SettingsScreen(
            model = model,
            onBack = { showingSettings = false }
        )
    } else {
        HomeScreen(
            status = status,
            node = node,
            downBps = downBps,
            upBps = upBps,
            onConnect = { model.connect() },
            onDisconnect = { model.disconnect() },
            onOpenSettings = { showingSettings = true },
            onOpenNodes = { showingSettings = true },
        )
    }
}
