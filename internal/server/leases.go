package server

import (
	"os"
	"strings"
)

// parseLeases maps client IP → hostname from dnsmasq's lease file. Pure (file-I/O-free),
// unit-tested. Line format: "<expiry> <mac> <ip> <hostname> <clientid>"; a "*" hostname
// (unknown) is dropped so the UI shows the bare IP instead.
func parseLeases(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		ip, name := f[2], f[3]
		if name != "" && name != "*" {
			out[ip] = name
		}
	}
	return out
}

// readLeases reads the dnsmasq lease file (OpenWrt path), or returns an empty map.
func readLeases() map[string]string {
	b, err := os.ReadFile("/tmp/dhcp.leases")
	if err != nil {
		return map[string]string{}
	}
	return parseLeases(string(b))
}
