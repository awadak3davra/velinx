package pbr

import (
	"fmt"
	"sort"
	"strings"
)

// hexMark formats a 32-bit fwmark/mask.
func hexMark(v uint32) string { return fmt.Sprintf("0x%08x", v) }

// markSet renders the nft expression that sets our mark bits while preserving any
// non-owned bits (so it coexists with fw4's own marks).
func (pl *Plan) markSet(mark uint32) string {
	return fmt.Sprintf("meta mark set meta mark & %s | %s", hexMark(^pl.Mask), hexMark(mark))
}

func nftElements(cidrs []string) string { return strings.Join(cidrs, ", ") }

// RenderNft returns the full nftables ruleset for this plan's OWN table (applied via
// `nft -f -`). It only ever touches `table inet <pl.Table>`, so it coexists with fw4
// and sing-box's auto_redirect table and survives `fw4 reload` (re-apply on reload).
func (pl *Plan) RenderNft() string {
	var b strings.Builder
	// Self-flushing idiom: one atomic `nft -f` transaction that recreates our table from
	// scratch (ensure-exists → delete → recreate) so apply is idempotent with no gap.
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\n", pl.Table, pl.Table)
	fmt.Fprintf(&b, "table inet %s {\n", pl.Table)

	if len(pl.BypassV4) > 0 {
		fmt.Fprintf(&b, "\tset bypass4 { type ipv4_addr; flags interval; elements = { %s } }\n", nftElements(pl.BypassV4))
	}
	if len(pl.BypassV6) > 0 {
		fmt.Fprintf(&b, "\tset bypass6 { type ipv6_addr; flags interval; elements = { %s } }\n", nftElements(pl.BypassV6))
	}
	for _, z := range pl.Zones {
		if len(z.V4) > 0 {
			fmt.Fprintf(&b, "\tset %s_4 { type ipv4_addr; flags interval; elements = { %s } }\n", z.Name, nftElements(z.V4))
		}
		if len(z.V6) > 0 {
			fmt.Fprintf(&b, "\tset %s_6 { type ipv6_addr; flags interval; elements = { %s } }\n", z.Name, nftElements(z.V6))
		}
	}

	// Chain name must NOT be an nft reserved keyword — `chain mark { ... }` fails to
	// parse ("unexpected mark"), since `mark` is a keyword (meta mark / ct mark). Use a
	// namespaced identifier instead. (Caught only by a real `nft -f` on-device; the unit
	// tests use a mock runner and never parsed the ruleset.)
	b.WriteString("\tchain wr_mark {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	// Anti-loop bypass first: tunnel peer IPs egress via WAN (main table).
	wanMark := pl.markByKind(EgressWAN)
	if len(pl.BypassV4) > 0 {
		fmt.Fprintf(&b, "\t\tip daddr @bypass4 %s\n", pl.markSet(wanMark))
	}
	if len(pl.BypassV6) > 0 {
		fmt.Fprintf(&b, "\t\tip6 daddr @bypass6 %s\n", pl.markSet(wanMark))
	}
	for _, z := range pl.Zones {
		if len(z.V4) > 0 {
			fmt.Fprintf(&b, "\t\tip daddr @%s_4 %s\n", z.Name, pl.markSet(z.Mark))
		}
		if len(z.V6) > 0 {
			fmt.Fprintf(&b, "\t\tip6 daddr @%s_6 %s\n", z.Name, pl.markSet(z.Mark))
		}
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

func (pl *Plan) markByKind(k EgressKind) uint32 {
	for _, e := range pl.Egresses {
		if e.Kind == k {
			return e.Mark
		}
	}
	return 0
}

// RenderIP returns the idempotent `ip rule`/`ip route` commands to install the plan.
// WAN-marked traffic (the bypass) needs no rule — it falls through to the main table.
func (pl *Plan) RenderIP(opt Options) []string {
	opt.withDefaults()
	var cmds []string
	for i, e := range pl.nonWanEgresses() {
		pref := opt.RulePref + i
		cmds = append(cmds, fmt.Sprintf("ip rule add fwmark %s/%s table %d priority %d",
			hexMark(e.Mark), hexMark(pl.Mask), e.Table, pref))
		switch e.Kind {
		case EgressInterface:
			cmds = append(cmds, fmt.Sprintf("ip route replace default dev %s table %d", e.Iface, e.Table))
		case EgressBlackhole:
			cmds = append(cmds, fmt.Sprintf("ip route replace blackhole default table %d", e.Table))
		}
	}
	return cmds
}

// ipTeardown returns just the `ip rule`/`ip route` removal commands (no nft).
func (pl *Plan) ipTeardown(opt Options) []string {
	opt.withDefaults()
	var cmds []string
	for i, e := range pl.nonWanEgresses() {
		pref := opt.RulePref + i
		cmds = append(cmds, fmt.Sprintf("ip rule del fwmark %s/%s table %d priority %d",
			hexMark(e.Mark), hexMark(pl.Mask), e.Table, pref))
		cmds = append(cmds, fmt.Sprintf("ip route flush table %d", e.Table))
	}
	return cmds
}

// RenderTeardown returns the commands to remove everything RenderNft/RenderIP installed.
func (pl *Plan) RenderTeardown(opt Options) []string {
	return append([]string{fmt.Sprintf("nft delete table inet %s", pl.Table)}, pl.ipTeardown(opt)...)
}

// nonWanEgresses returns interface/blackhole egresses in stable (mark) order.
func (pl *Plan) nonWanEgresses() []Egress {
	var out []Egress
	for _, e := range pl.Egresses {
		if e.Kind != EgressWAN {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mark < out[j].Mark })
	return out
}
