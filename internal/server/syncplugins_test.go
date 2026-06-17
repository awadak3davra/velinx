package server

import "testing"

// TestSyncPlugins_BringsUpFromProfile verifies the daemon-start sync wires the
// engine plugins a profile needs (so AmneziaWG/olcRTC tunnels come up from boot,
// not only after an Apply). The proc is created even if the host lacks the bring-up
// binaries, so it appears in Status regardless of platform.
func TestSyncPlugins_BringsUpFromProfile(t *testing.T) {
	s := opshandlers_server(t)
	s.cfg.Demo = false // SyncPlugins is a deliberate no-op in demo mode
	if err := s.store.UpsertEndpoint(opshandlers_awgEndpoint("awg1")); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}

	s.SyncPlugins()

	st := s.Plugins().Status()
	if len(st) != 1 || st[0].ID != "awg1" {
		t.Fatalf("SyncPlugins did not wire the plugin from the profile: %+v", st)
	}
}

// TestSyncPlugins_DemoNoop guards that demo mode never touches host interfaces.
func TestSyncPlugins_DemoNoop(t *testing.T) {
	s := opshandlers_server(t) // Demo = true
	if err := s.store.UpsertEndpoint(opshandlers_awgEndpoint("awg1")); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	s.SyncPlugins()
	if st := s.Plugins().Status(); len(st) != 0 {
		t.Fatalf("demo SyncPlugins must be a no-op, got %+v", st)
	}
}
