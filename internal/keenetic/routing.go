package keenetic

import (
	"fmt"
	"net/netip"
	"strings"
)

// RouteTarget identifies where a static route sends matching traffic on KeeneticOS.
type RouteTarget struct {
	Iface  string // NDM interface name ("Wireguard5", "ISP", "Home"); empty + Reject = blackhole
	Reject bool   // blackhole the destination (drop)
}

// Route is one destination → target static route (the Keenetic equivalent of a pbr zone).
type Route struct {
	CIDR    string      // destination (CIDR or bare IP); "0.0.0.0/0" = default
	Target  RouteTarget //
	Auto    bool        // emit `auto` (NDM-managed / auto-readded)
	Comment string      // optional `!comment` tag
}

// RouteCommands renders NDM `ip route` commands from route entries — the native routing
// mechanism (cycle-2 finding: metric-ordered default-via-VPN + static `/32`-`/16`
// exceptions, NOT fwmark/policy). Form validated live on the Hopper SE:
//
//	ip route <addr> <mask> <iface> [auto] [reject] [!comment]    (v4)
//	ip route <addr> <mask> reject                                 (blackhole)
//
// v6 destinations render as `ipv6 route <addr> <prefixlen> <iface>` (⚠️ exact v6 form still
// TO-VALIDATE on-device). Pure — the apply layer submits these over RCI /rci/parse. The
// metric/priority of a default-via-VPN comes from the interface's `ip global` (NativeVPN),
// not from here.
func RouteCommands(routes []Route) ([]string, error) {
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		cidr := strings.TrimSpace(r.CIDR)
		is6, err := isV6(cidr)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", cidr, err)
		}
		am, err := cidrToAddrMask(cidr)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", cidr, err)
		}
		cmd := "ip route"
		if is6 {
			cmd = "ipv6 route" // ⚠️ v6 route form to validate on-device
		}
		parts := []string{cmd, am}
		switch {
		case r.Target.Reject && r.Target.Iface == "":
			parts = append(parts, "reject")
		case r.Target.Iface != "":
			parts = append(parts, r.Target.Iface)
			if r.Auto {
				parts = append(parts, "auto")
			}
			if r.Target.Reject {
				parts = append(parts, "reject")
			}
		default:
			return nil, fmt.Errorf("route %q: no iface and not a reject", cidr)
		}
		if r.Comment != "" {
			parts = append(parts, "!"+sanitizeComment(r.Comment))
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out, nil
}

func isV6(cidr string) (bool, error) {
	if pfx, err := netip.ParsePrefix(cidr); err == nil {
		return pfx.Addr().Is6(), nil
	}
	a, err := netip.ParseAddr(cidr)
	if err != nil {
		return false, fmt.Errorf("not an IP/CIDR")
	}
	return a.Is6(), nil
}

// sanitizeComment makes a string safe as an NDM `!comment` tag (alnum/_/-; spaces→_).
func sanitizeComment(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ' ':
			b.WriteByte('_')
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-':
			b.WriteRune(r)
		}
	}
	return b.String()
}
