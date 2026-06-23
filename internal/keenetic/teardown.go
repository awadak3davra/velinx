package keenetic

import (
	"context"
	"fmt"
	"strings"
)

// TeardownCommands returns the NDM `no …` commands that REMOVE everything this Plan added to
// the NDM config: each route (`no ip route <dst> <mask> <target>`) and then each native
// interface (`no interface WireguardN`). NDM config is additive, so a clean re-apply must
// first tear down the previously-applied plan — otherwise stale interfaces/routes linger.
//
// Routes are removed BEFORE interfaces (a route references its interface; dropping the
// interface first would auto-invalidate the route and a later `no` could mismatch). The
// route key is the identity portion only (the leading `ip route <dst> <mask> <target>` /
// `ipv6 route …`), with trailing auto/reject/!comment stripped so `no` matches by key.
//
// The sing-box (fallback) plane is NOT torn down here: ApplySingbox rewrites the entire
// sing-box config, so re-Deploying with the new profile drops any removed wrtunN TUNs.
// Pure — no device I/O.
func TeardownCommands(plan *Plan) []string {
	out := make([]string, 0, len(plan.Routes)+len(plan.Interfaces))
	for _, r := range plan.Routes {
		out = append(out, "no "+routeKey(r))
	}
	for _, block := range plan.Interfaces {
		if len(block) > 0 {
			out = append(out, "no "+block[0]) // block[0] == "interface WireguardN"
		}
	}
	return out
}

// routeKey trims a rendered route line to its identity tokens ("ip route <dst> <mask>
// <target>" — 5 fields), dropping any trailing `auto`/`reject`/`!comment` so a `no` removal
// matches the route by key.
func routeKey(line string) string {
	f := strings.Fields(line)
	if len(f) > 5 {
		f = f[:5]
	}
	return strings.Join(f, " ")
}

// Teardown removes this Plan's NDM config from the router (its `no` commands over RCI), then
// optionally saves. The sing-box plane needs no separate teardown — a re-Deploy with the new
// profile rewrites /opt/etc/sing-box wholesale, dropping removed TUNs.
//
// ⚠️ DEVICE-WRITING. The research loop never calls it; runs only on a user-OK'd deploy
// (disable / re-apply). On-device RCI base = http://localhost.
func (p *Plan) Teardown(ctx context.Context, rci *RCIClient, o ApplyOptions) error {
	cmds := TeardownCommands(p)
	if len(cmds) > 0 {
		if _, err := rci.ParseBatch(ctx, cmds); err != nil {
			return fmt.Errorf("teardown: %w", err)
		}
	}
	if o.Save {
		if _, err := rci.ParseBatch(ctx, []string{"system configuration save"}); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
	}
	return nil
}
