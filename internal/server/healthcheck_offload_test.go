package server

import (
	"context"
	"testing"
)

func TestParseOffloadConfig(t *testing.T) {
	cases := []struct {
		name   string
		cfg    string
		wantSW bool
		wantHW bool
	}{
		{"both off", "config defaults\n\toption flow_offloading '0'\n\toption flow_offloading_hw '0'\n", false, false},
		{"sw only", "config defaults\n\toption flow_offloading '1'\n", true, false},
		{"both on", "config defaults\n\toption flow_offloading '1'\n\toption flow_offloading_hw '1'\n", true, true},
		{"unquoted truthy", "config defaults\n\toption flow_offloading 1\n\toption flow_offloading_hw true\n", true, true},
		{"hw without sw (misconfig)", "config defaults\n\toption flow_offloading_hw '1'\n", false, true},
		{"absent", "config defaults\n\toption input 'ACCEPT'\n", false, false},
		{"empty", "", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sw, hw := parseOffloadConfig(c.cfg)
			if sw != c.wantSW || hw != c.wantHW {
				t.Fatalf("parseOffloadConfig() = sw %v hw %v, want sw %v hw %v", sw, hw, c.wantSW, c.wantHW)
			}
		})
	}
}

// On a non-OpenWrt host /etc/config/firewall is absent → the check must degrade to a warn
// row rather than panic or report a misleading status.
func TestFlowOffloadCheck_NonOpenWrt(t *testing.T) {
	row := flowOffloadCheck(context.Background())
	if row.ID != "offload" {
		t.Fatalf("ID = %q, want offload", row.ID)
	}
	if row.Status != "pass" && row.Status != "warn" {
		t.Fatalf("Status = %q, want pass or warn", row.Status)
	}
}
