package keenetic

import (
	"strings"
	"testing"
)

func TestRetireOldStack(t *testing.T) {
	run := &recRunner{}
	if err := RetireOldStack(run); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(run.calls, "\n")
	for _, w := range []string{
		"chmod -x /opt/etc/ndm/netfilter.d/50-keen-pbr-routing.sh", // re-apply hook cut
		"chmod -x /opt/etc/cron.1min/hy-failover",                  // failover cron cut
		"/opt/etc/init.d/S80keen-pbr stop",                         // service stopped
		"chmod -x /opt/etc/init.d/S80keen-pbr",                     // boot-disabled
		"chmod -x /opt/etc/init.d/S89hy_failover",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("retire missing %q\n--- calls ---\n%s", w, got)
		}
	}
	// The netfilter re-apply hook MUST be cut before keen-pbr is stopped (no resurrection window).
	if strings.Index(got, "netfilter.d/50-keen-pbr") > strings.Index(got, "S80keen-pbr stop") {
		t.Error("netfilter re-apply hook must be disabled before stopping keen-pbr")
	}
	// S86 (RU-direct) is KEPT — it coexists via fwmark 0x250 and must NOT be touched.
	if strings.Contains(got, "S86ru_routing") {
		t.Error("S86ru_routing (RU-direct) must be kept, not retired")
	}
	if strings.Contains(got, "60-wgbot-policy") {
		t.Error("60-wgbot-policy.sh (re-applies S86) must be kept, not disabled")
	}
}

func TestRestoreOldStack(t *testing.T) {
	run := &recRunner{}
	if err := RestoreOldStack(run); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(run.calls, "\n")
	for _, w := range []string{
		"chmod +x /opt/etc/init.d/S80keen-pbr",
		"/opt/etc/init.d/S80keen-pbr start",
		"/opt/etc/init.d/S89hy_failover start",
		"chmod +x /opt/etc/cron.1min/hy-failover",
		"chmod +x /opt/etc/ndm/netfilter.d/50-keen-pbr-routing.sh",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("restore missing %q\n--- calls ---\n%s", w, got)
		}
	}
	// Services come back up BEFORE the re-apply paths resume.
	if strings.Index(got, "S80keen-pbr start") > strings.Index(got, "chmod +x /opt/etc/cron.1min/hy-failover") {
		t.Error("services must restart before the cron/netfilter re-apply paths resume")
	}
}

// TestRetireRestore_Inverse: every service retired is restored (no orphans).
func TestRetireRestore_Inverse(t *testing.T) {
	for _, s := range oldStackServices {
		ret := &recRunner{}
		_ = RetireOldStack(ret)
		res := &recRunner{}
		_ = RestoreOldStack(res)
		if !strings.Contains(strings.Join(ret.calls, "\n"), "chmod -x "+initd(s)) {
			t.Errorf("%s not disabled on retire", s)
		}
		if !strings.Contains(strings.Join(res.calls, "\n"), "chmod +x "+initd(s)) {
			t.Errorf("%s not re-enabled on restore", s)
		}
	}
}
