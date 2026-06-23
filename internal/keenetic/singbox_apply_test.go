package keenetic

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recRunner struct {
	calls []string
	err   error
}

func (r *recRunner) Run(stdin, name string, args ...string) (string, error) {
	r.calls = append(r.calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	return "", r.err
}

func TestApplySingbox(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	rec := &recRunner{}
	cfg := map[string]any{
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "tun-x", "interface_name": "wrtun0"}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	}
	if err := ApplySingbox(cfg, SingboxApplyOptions{ConfigPath: path}, rec); err != nil {
		t.Fatal(err)
	}

	// Config written + valid JSON round-trips.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("written config is not valid JSON: %v", err)
	}
	if got["route"] == nil || got["inbounds"] == nil {
		t.Errorf("config missing keys: %v", got)
	}

	// Service restarted exactly once via the default init script.
	if len(rec.calls) != 1 || rec.calls[0] != "/opt/etc/init.d/S99sing-box restart" {
		t.Errorf("restart calls = %v, want [/opt/etc/init.d/S99sing-box restart]", rec.calls)
	}
}

func TestApplySingbox_NilNoop(t *testing.T) {
	rec := &recRunner{}
	if err := ApplySingbox(nil, SingboxApplyOptions{}, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 0 {
		t.Errorf("nil config must be a no-op, got calls %v", rec.calls)
	}
}

func TestApplySingbox_RestartError(t *testing.T) {
	dir := t.TempDir()
	rec := &recRunner{err: errors.New("init script failed")}
	cfg := map[string]any{"route": map[string]any{}}
	err := ApplySingbox(cfg, SingboxApplyOptions{ConfigPath: filepath.Join(dir, "config.json")}, rec)
	if err == nil || !strings.Contains(err.Error(), "restart sing-box") {
		t.Errorf("want wrapped restart error, got %v", err)
	}
}
