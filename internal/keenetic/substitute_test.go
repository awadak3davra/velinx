package keenetic

import "testing"

func TestSubstituteRealOutbounds(t *testing.T) {
	cfg := map[string]any{
		"outbounds": []map[string]any{
			{"type": "direct", "tag": "direct"},
			{"type": "hysteria2", "tag": "hy2_main", "server": "1.1.1.1", "password": "PLACEHOLDER"},
			{"type": "vless", "tag": "vless_main", "server": "1.1.1.1", "uuid": "00000000-0000-0000-0000-000000000000"},
		},
	}
	live := []byte(`{"outbounds":[
		{"type":"hysteria2","tag":"hy2-main","server":"203.0.113.10","server_port":8444,"password":"REALPW","tls":{"enabled":true,"server_name":"x"}},
		{"type":"vless","tag":"vless-main","server":"203.0.113.10","server_port":443,"uuid":"REAL-UUID","flow":"xtls-rprx-vision","tls":{"enabled":true}}
	]}`)

	missing, err := SubstituteRealOutbounds(cfg, live, map[string]string{"hy2-main": "hy2_main", "vless-main": "vless_main"})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("expected all tags substituted, missing=%v", missing)
	}

	obs := cfg["outbounds"].([]map[string]any)
	var hy2, vless map[string]any
	for _, ob := range obs {
		switch ob["tag"] {
		case "hy2_main":
			hy2 = ob
		case "vless_main":
			vless = ob
		}
	}
	// Real params swapped in; assembled tag preserved (groups/rules reference it).
	if hy2["password"] != "REALPW" || hy2["server"] != "203.0.113.10" || hy2["tag"] != "hy2_main" {
		t.Errorf("hy2 not substituted: %v", hy2)
	}
	if vless["uuid"] != "REAL-UUID" || vless["flow"] != "xtls-rprx-vision" || vless["tag"] != "vless_main" {
		t.Errorf("vless not substituted: %v", vless)
	}
	// The placeholder fields are gone (replaced verbatim).
	if hy2["password"] == "PLACEHOLDER" {
		t.Error("placeholder password must be replaced")
	}
}

func TestSubstituteRealOutbounds_ReportsMissing(t *testing.T) {
	cfg := map[string]any{"outbounds": []map[string]any{{"tag": "hy2_main"}}}
	missing, err := SubstituteRealOutbounds(cfg, []byte(`{"outbounds":[]}`), map[string]string{"hy2-main": "hy2_main"})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0] != "hy2-main" {
		t.Errorf("missing live outbound must be reported, got %v", missing)
	}
}
