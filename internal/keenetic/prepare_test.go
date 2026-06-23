package keenetic

import (
	"context"
	"strings"
	"testing"
)

// TestPrepareCutover: the full pre-flight → CutoverOptions pipeline, end to end (no device),
// then drive the resulting Cutover against mocks to prove the wiring (kernel closures, config).
func TestPrepareCutover(t *testing.T) {
	in := PrepareInputs{
		KeenPBRConfig:     []byte(kpFixture),
		LocalListFiles:    map[string][]string{"/opt/etc/keen-pbr/local.lst": {"lampa.mx"}},
		RunningConfig:     rcFixture,
		LiveSingboxConfig: []byte(`{"outbounds":[{"type":"hysteria2","tag":"hy2-main","server":"9.9.9.9","server_port":8444,"password":"REAL","tls":{"enabled":true}},{"type":"vless","tag":"vless-main","server":"9.9.9.9","server_port":443,"uuid":"REAL-UUID","tls":{"enabled":true}}]}`),
		WanGateway:        "172.20.0.1",
		Fetch:             func(url string) ([]string, error) { return []string{"149.154.160.0/20"}, nil },
	}
	run := &recRunner{}
	cOpt, warns, err := PrepareCutover(run, in)
	if err != nil {
		t.Fatal(err)
	}

	// The keentest remap warning carries through.
	if !strings.Contains(strings.Join(warns, " "), "keentest") {
		t.Errorf("expected keentest reconciliation warning, got %v", warns)
	}
	// SingboxConfig assembled with real Hy2 params substituted.
	obs := cOpt.SingboxConfig["outbounds"].([]map[string]any)
	var gotReal bool
	for _, ob := range obs {
		if ob["tag"] == EpHy2 && ob["password"] == "REAL" {
			gotReal = true
		}
	}
	if !gotReal {
		t.Error("real Hy2 params were not substituted into the assembled config")
	}

	// Driving the kernel closure applies the bypass + default→wr-tun via the runner.
	if err := cOpt.ApplyKernel(); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(run.calls, "\n")
	if !strings.Contains(got, "ip route replace default dev wr-tun metric 50") {
		t.Errorf("kernel closure did not apply default→wr-tun\n%s", got)
	}
	if !strings.Contains(got, "via 172.20.0.1 dev eth3") {
		t.Errorf("kernel closure did not apply bypass/local-direct via WAN\n%s", got)
	}

	// Teardown closure works too.
	if err := cOpt.TeardownKernel(); err != nil {
		t.Fatal(err)
	}
	_ = context.Background()
}

func TestPrepareCutover_NoInterfaces(t *testing.T) {
	_, _, err := PrepareCutover(&recRunner{}, PrepareInputs{RunningConfig: "ip route 0.0.0.0 0.0.0.0 ISP"})
	if err == nil || !strings.Contains(err.Error(), "no WireGuard interfaces") {
		t.Errorf("empty running-config must fail pre-flight, got %v", err)
	}
}
