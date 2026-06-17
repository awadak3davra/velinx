package generator

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wakeroute/internal/model"
)

// allProtocolProfile builds a profile with one endpoint per stable sing-box-native
// protocol the generator emits, plus a group, a route rule and a routing list,
// using minimally-VALID params (correct key lengths) so a real `sing-box check`
// accepts the result, not just structural generation.
//
// Native WireGuard IS included: the generator now emits it as a top-level
// `endpoints` entry (the 1.11+ schema) instead of the `wireguard` outbound that
// 1.11 deprecated and 1.13 removed. That endpoint form is accepted by BOTH the
// deployed 1.12.x and 1.13.x, so it is no longer version-sensitive and a real
// `check` validates it on every pinned sing-box the CI runs.
func allProtocolProfile() *model.Profile {
	ssKey := base64.StdEncoding.EncodeToString(make([]byte, 16)) // 2022-blake3-aes-128-gcm wants a 16-byte key
	wgKey := base64.StdEncoding.EncodeToString(make([]byte, 32)) // WireGuard keys are 32-byte base64
	uuid := "11111111-1111-1111-1111-111111111111"
	// Hysteria2 and TUIC run over QUIC+TLS and sing-box rejects them without a tls
	// block ("TLS required"); attach one (the importer always sets it on real links).
	withTLS := func(e model.Endpoint) model.Endpoint {
		e.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "example.com"}
		return e
	}
	eps := []model.Endpoint{
		generator_singBoxEndpoint("p-vless", model.ProtoVLESS, map[string]any{"uuid": uuid}),
		generator_singBoxEndpoint("p-vmess", model.ProtoVMess, map[string]any{"uuid": uuid, "alter_id": 0, "security": "auto"}),
		generator_singBoxEndpoint("p-trojan", model.ProtoTrojan, map[string]any{"password": "pw"}),
		generator_singBoxEndpoint("p-ss", model.ProtoShadowsocks, map[string]any{"method": "2022-blake3-aes-128-gcm", "password": ssKey}),
		withTLS(generator_singBoxEndpoint("p-hy2", model.ProtoHysteria2, map[string]any{"password": "pw", "obfs": "salamander", "obfs_password": "op"})),
		withTLS(generator_singBoxEndpoint("p-tuic", model.ProtoTUIC, map[string]any{"uuid": uuid, "password": "pw", "congestion_control": "bbr", "udp_relay_mode": "native"})),
		generator_singBoxEndpoint("p-socks", model.ProtoSOCKS, map[string]any{}),
		generator_singBoxEndpoint("p-http", model.ProtoHTTP, map[string]any{}),
		// Native WireGuard → top-level `endpoints` entry. Real 32-byte keys so
		// sing-box's config build (which base64-decodes them) accepts the config.
		generator_singBoxEndpoint("p-wg", model.ProtoWireGuard, map[string]any{
			"private_key": wgKey, "peer_public_key": wgKey, "local_address": []string{"10.0.0.2/32"},
		}),
	}
	return &model.Profile{
		Endpoints: eps,
		Groups:    []model.Group{{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"p-vless", "p-hy2"}}},
		Rules: []model.Rule{
			{ID: "r1", DomainSuffix: []string{"example.com"}, Outbound: "g"},
			{ID: "def", Default: true, Outbound: model.OutboundDirect},
		},
		RoutingLists: []model.RoutingList{
			{ID: "rl", Name: "L", Manual: []string{"openai.com", "1.2.3.0/24"}, Outbound: "p-tuic", Enabled: true},
		},
	}
}

// TestAllProtocolsGenerate asserts every supported protocol generates its outbound
// (the per-protocol "each element" structural check, always run). When WR_SINGBOX
// points at a sing-box binary (CI sets this after downloading sing-box), it also
// validates the whole config with `sing-box check` — catching any protocol whose
// emitted JSON the real core would reject.
func TestAllProtocolsGenerate(t *testing.T) {
	p := allProtocolProfile()
	res, err := Generate(p, Options{MixedPort: 7890, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatalf("generate all-protocols config: %v", err)
	}
	got := map[string]bool{}
	for _, ob := range res.Config["outbounds"].([]map[string]any) {
		if tp, _ := ob["type"].(string); tp != "" {
			got[tp] = true
		}
	}
	// Native WireGuard lives in the top-level `endpoints` array, not outbounds.
	if eps, ok := res.Config["endpoints"].([]map[string]any); ok {
		for _, ep := range eps {
			if tp, _ := ep["type"].(string); tp != "" {
				got[tp] = true
			}
		}
	}
	for _, want := range []string{"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "socks", "http", "urltest", "direct", "wireguard"} {
		if !got[want] {
			t.Errorf("generated config is missing outbound/endpoint type %q", want)
		}
	}

	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — ran generation-only (set it to a sing-box binary for a real `check`)")
	}
	data, err := json.MarshalIndent(res.Config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "all-protocols.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", f).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check rejected the all-protocols config: %v\n%s", err, strings.TrimSpace(string(out)))
	}
}
