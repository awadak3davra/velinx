package server

import (
	"os"
	"os/exec"
	"strings"
)

// probeOffloadDevices discovers the netdevs Phase-1b flow-offload should attach to: the
// WAN uplink (the default route's `dev`) plus the LAN bridge (br-lan, if present). Used
// only when config.Offload is set WITHOUT an explicit OffloadDevices list. Best-effort —
// it returns whatever it finds (possibly empty, in which case pbr.Compile skips offload
// and warns) and never errors. On a non-Linux/no-`ip` host (e.g. the test machine) the
// exec simply fails and this returns nil, so an accidental call is harmless.
func probeOffloadDevices() []string {
	var devs []string
	if out, err := exec.Command("ip", "-o", "route", "show", "default").Output(); err == nil {
		if d := parseDefaultRouteDev(string(out)); d != "" {
			devs = append(devs, d)
		}
	}
	// Standard OpenWrt LAN bridge. awg* tunnel devices are intentionally never added —
	// carve-out traffic must not be offloaded (it would lose its per-packet PBR).
	if _, err := os.Stat("/sys/class/net/br-lan"); err == nil {
		devs = appendUniqueStr(devs, "br-lan")
	}
	return devs
}

// parseDefaultRouteDev extracts the first default route's `dev <name>` from the output of
// `ip -o route show default` (e.g. "default via 192.168.1.254 dev wan src 192.168.1.70").
// Pure, so it is unit-tested without touching the host. Returns "" if no dev is found.
func parseDefaultRouteDev(out string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "dev" {
				return fields[i+1]
			}
		}
	}
	return ""
}

func appendUniqueStr(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}
