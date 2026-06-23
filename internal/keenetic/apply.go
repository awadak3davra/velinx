package keenetic

import (
	"context"
	"fmt"
)

// ApplyOptions tune Apply.
type ApplyOptions struct {
	Save bool // run `system configuration save` after a successful apply (persist to flash)
}

// Apply submits a compiled Plan to the router over RCI — it configures the native VPN
// interfaces and routes. Each interface command block is sent as one /rci/parse batch (so
// its NDM editing context stays intact), then the routes, then optionally a config save.
//
// ⚠️ DEVICE-WRITING. This is the ONLY method in the package that changes router state. The
// research/build loop NEVER calls it; it runs only when the user explicitly OKs a deploy.
// On the device the RCIClient base is http://localhost (the RCI is local). Per-command NDM
// errors are surfaced via the RCI response (the transport-level error here); a richer
// per-line status check is a follow-up once validated against a real apply.
func (p *Plan) Apply(ctx context.Context, rci *RCIClient, o ApplyOptions) error {
	for i, block := range p.Interfaces {
		if _, err := rci.ParseBatch(ctx, block); err != nil {
			return fmt.Errorf("apply interface block %d: %w", i, err)
		}
	}
	if len(p.Routes) > 0 {
		if _, err := rci.ParseBatch(ctx, p.Routes); err != nil {
			return fmt.Errorf("apply routes: %w", err)
		}
	}
	if o.Save {
		if _, err := rci.ParseBatch(ctx, []string{"system configuration save"}); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
	}
	return nil
}

// Deploy applies BOTH planes of a Plan in the correct order: the sing-box (fallback) plane
// FIRST (so its wrtunN TUN devices exist), then the NDM plane over RCI (native interfaces +
// routes, some of which may target those TUNs — a route to a non-existent device would fail).
// A Plan with no non-native endpoints skips the sing-box step (nil Singbox → no-op).
//
// ⚠️ DEVICE-WRITING. The single deploy entry point; runs ONLY on a user-OK'd deploy — the
// research loop never calls it.
func (p *Plan) Deploy(ctx context.Context, rci *RCIClient, run Runner, applyOpt ApplyOptions, sbOpt SingboxApplyOptions) error {
	if err := ApplySingbox(p.Singbox, sbOpt, run); err != nil {
		return fmt.Errorf("sing-box plane: %w", err)
	}
	if err := p.Apply(ctx, rci, applyOpt); err != nil {
		return fmt.Errorf("ndm plane: %w", err)
	}
	return nil
}
