package trail.tun

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.ripple
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.min

/**
 * The connect dial.
 *
 * Visual grammar, borrowed from how Google designs status surfaces: one dominant
 * element, motion that communicates state rather than decorating it, and the
 * number that matters in the middle at a size you can read across a room.
 *
 * State is expressed three ways at once so it survives a glance, a screen reader
 * and a low-power mode with animations disabled:
 *   idle       flat ring, muted colour
 *   connecting a rotating arc, no fill
 *   connected  full ring, accent colour, slow breathing pulse
 *   error      ring in error colour, no motion
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectDial(
    status: VpnStatus,
    downBps: Long,
    upBps: Long,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val accent = when {
        status.hasError -> MaterialTheme.colorScheme.error
        status.isConnected -> MaterialTheme.colorScheme.primary
        else -> MaterialTheme.colorScheme.outline
    }

    // Rotation while connecting. Cancelled automatically when the state leaves
    // connecting because the transition stops composing.
    val infinite = rememberInfiniteTransition(label = "dial")
    val rotation by infinite.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(1400, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "rotation"
    )
    // Breathing pulse while connected. 2.4 s is slow enough to read as
    // "alive" rather than "urgent".
    val breath by infinite.animateFloat(
        initialValue = 0.94f,
        targetValue = 1.06f,
        animationSpec = infiniteRepeatable(
            animation = tween(2400, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "breath"
    )

    // Entrance spring: the dial scales in once on first composition.
    val entrance = remember { Animatable(0.92f) }
    LaunchedEffect(Unit) {
        entrance.animateTo(1f, tween(420, easing = FastOutSlowInEasing))
    }

    Box(
        modifier = modifier
            .size(260.dp)
            .clip(CircleShape),
        contentAlignment = Alignment.Center
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val stroke = 10.dp.toPx()
            val inset = stroke / 2 + 6.dp.toPx()
            val arcSize = size.minDimension - inset * 2
            val topLeft = Offset(inset, inset)
            val scale = entrance.value * if (status.isConnected) breath else 1f
            val pulseInset = inset + (1f - scale) * 26.dp.toPx()

            // Track.
            drawArc(
                color = accent.copy(alpha = 0.16f),
                startAngle = 0f,
                sweepAngle = 360f,
                useCenter = false,
                topLeft = Offset(pulseInset, pulseInset),
                size = androidx.compose.ui.geometry.Size(
                    size.minDimension - pulseInset * 2,
                    size.minDimension - pulseInset * 2
                ),
                style = Stroke(stroke, cap = StrokeCap.Round)
            )

            when {
                status.isConnected -> drawArc(
                    color = accent,
                    startAngle = -90f,
                    sweepAngle = 360f,
                    useCenter = false,
                    topLeft = Offset(pulseInset, pulseInset),
                    size = androidx.compose.ui.geometry.Size(
                        size.minDimension - pulseInset * 2,
                        size.minDimension - pulseInset * 2
                    ),
                    style = Stroke(stroke, cap = StrokeCap.Round)
                )

                status.isConnecting -> drawArc(
                    color = accent,
                    startAngle = rotation,
                    sweepAngle = 96f,
                    useCenter = false,
                    topLeft = topLeft,
                    size = androidx.compose.ui.geometry.Size(arcSize, arcSize),
                    style = Stroke(stroke, cap = StrokeCap.Round)
                )

                else -> drawArc(
                    color = accent,
                    startAngle = -90f,
                    sweepAngle = 120f,
                    useCenter = false,
                    topLeft = topLeft,
                    size = androidx.compose.ui.geometry.Size(arcSize, arcSize),
                    style = Stroke(stroke, cap = StrokeCap.Round)
                )
            }
        }

        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            AnimatedContent(
                targetState = status.state,
                transitionSpec = {
                    (fadeIn(tween(180)) + scaleIn(initialScale = 0.9f, animationSpec = tween(220)))
                        .togetherWith(fadeOut(tween(120)) + scaleOut(targetScale = 1.05f))
                },
                label = "state"
            ) { state ->
                Text(
                    text = when (state) {
                        "connecting" -> "Connecting"
                        "connected" -> "Connected"
                        "stopping" -> "Stopping"
                        "error" -> "Failed"
                        else -> "Tap to connect"
                    },
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.Medium
                )
            }

            Spacer(Modifier.height(10.dp))

            if (status.isConnected) {
                // Rates, monospaced so digits do not jitter as they change.
                Text(
                    text = formatRate(downBps),
                    style = MaterialTheme.typography.headlineMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 30.sp
                    ),
                    color = accent
                )
                Text(
                    text = "↓  " + formatRate(upBps) + " up",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else if (status.isConnecting && status.handshakeMs > 0) {
                Text(
                    text = "${status.handshakeMs} ms",
                    style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

/** Formats a byte rate the way a person reads it: 1.4 MB/s, 840 KB/s, 12 B/s. */
fun formatRate(bytesPerSec: Long): String {
    if (bytesPerSec < 1024) return "$bytesPerSec B/s"
    val kb = bytesPerSec / 1024.0
    if (kb < 1024) return String.format("%.0f KB/s", kb)
    val mb = kb / 1024.0
    if (mb < 1024) return String.format("%.1f MB/s", mb)
    return String.format("%.2f GB/s", mb / 1024.0)
}

/** Formats a total transfer: 1.2 GB, 340 MB. */
fun formatBytes(b: Long): String {
    if (b < 1024) return "$b B"
    val kb = b / 1024.0
    if (kb < 1024) return String.format("%.0f KB", kb)
    val mb = kb / 1024.0
    if (mb < 1024) return String.format("%.1f MB", mb)
    return String.format("%.2f GB", mb / 1024.0)
}
