package keenetic

import (
	"strings"
	"testing"
)

// synthetic keen-pbr config covering each conversion case (NOT a real device config).
const kpFixture = `{
  "lists": {
    "telegram":     {"url": "https://raw.githubusercontent.com/lord-alfred/ipranges/main/telegram/ipv4_merged.txt"},
    "discord_ips":  {"url": "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/discord_ips.lst"},
    "youtube":      {"url": "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/youtube.lst"},
    "ip_list":      {"ip_cidrs": ["64.233.160.0/19", "142.250.0.0/15"]},
    "torrents":     {"domains": ["rutracker.org", "hdrezka.ag"]},
    "teamviewer":   {"domains": ["teamviewer.com"], "ip_cidrs": ["185.188.32.0/22"]},
    "local_list":   {"file": "/opt/etc/keen-pbr/local.lst"},
    "unused":       {"domains": ["nobody.example"]}
  },
  "route": {"rules": [
    {"enabled": true, "list": ["telegram", "discord_ips"], "outbound": "keentest"},
    {"enabled": true, "list": ["youtube", "teamviewer"],   "outbound": "auto_failover_with_wan"},
    {"enabled": true, "list": ["ip_list", "torrents", "local_list"], "outbound": "auto_failover_strict"}
  ]}
}`

func TestImportKeenPBR_PlaneSplit(t *testing.T) {
	files := map[string][]string{"/opt/etc/keen-pbr/local.lst": {"lampa.mx", "jac.red"}}
	outMap := map[string]string{
		"keentest":               "blocked_rf",
		"auto_failover_with_wan": "failover_with_wan",
		"auto_failover_strict":   "failover_strict",
	}
	lists, err := ImportKeenPBR([]byte(kpFixture), files, outMap)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]int{}
	for i, l := range lists {
		by[l.ID] = i
	}
	get := func(id string) (idx int, ok bool) { i, ok := by[id]; return i, ok }

	// IP feeds → CIDRSource (kernel), NOT Source.
	for _, id := range []string{"telegram", "discord_ips"} {
		i, ok := get(id)
		if !ok {
			t.Fatalf("missing %s", id)
		}
		if lists[i].CIDRSource == "" || lists[i].Source != "" {
			t.Errorf("%s must be a kernel CIDRSource (got Source=%q CIDRSource=%q)", id, lists[i].Source, lists[i].CIDRSource)
		}
		if lists[i].Outbound != "blocked_rf" {
			t.Errorf("%s outbound = %q, want blocked_rf", id, lists[i].Outbound)
		}
	}

	// Domain URL → Source (sing-box).
	if i, _ := get("youtube"); lists[i].Source == "" || lists[i].CIDRSource != "" {
		t.Errorf("youtube must be a sing-box Source domain rule_set")
	}

	// Inline IP-CIDRs → Manual (kernel); inline domains → Manual (sing-box).
	if i, _ := get("ip_list"); len(lists[i].Manual) != 2 || lists[i].Outbound != "failover_strict" {
		t.Errorf("ip_list = %+v", lists[by["ip_list"]])
	}
	if i, _ := get("torrents"); len(lists[i].Manual) != 2 {
		t.Errorf("torrents domains not carried: %+v", lists[by["torrents"]])
	}

	// Mixed list split: teamviewer (domains) + teamviewer_ip (CIDRs).
	di, dok := get("teamviewer")
	ii, iok := get("teamviewer_ip")
	if !dok || !iok {
		t.Fatalf("teamviewer must split into teamviewer + teamviewer_ip; got ids %v", keys(by))
	}
	if lists[di].Manual[0] != "teamviewer.com" || !strings.Contains(lists[ii].Manual[0], "185.188.32.0") {
		t.Errorf("teamviewer split wrong: dom=%v ip=%v", lists[di].Manual, lists[ii].Manual)
	}

	// File list → its lines.
	if i, _ := get("local_list"); len(lists[i].Manual) != 2 || lists[i].Manual[0] != "lampa.mx" {
		t.Errorf("local_list from file = %v", lists[by["local_list"]].Manual)
	}

	// Unreferenced list → emitted disabled.
	if i, _ := get("unused"); lists[i].Enabled {
		t.Error("unreferenced list must be disabled")
	}
}

func keys(m map[string]int) []string {
	var k []string
	for s := range m {
		k = append(k, s)
	}
	return k
}
