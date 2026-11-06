package engine

import (
	"context"

	"tuntrail/internal/config"
	"tuntrail/internal/proto/wireguard"
	"tuntrail/internal/tunnel"
)

// openWireGuard builds a WireGuard device. It lives here rather than in the
// protocol package so the engine's switch is the only place that names a
// concrete protocol — adding one means adding a case, not editing the engine.
func openWireGuard(ctx context.Context, p *config.Profile, protect func(fd int) bool) (tunnel.Device, error) {
	return wireguard.New(ctx, p, protect)
}
