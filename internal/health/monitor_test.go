package health

import "testing"

func TestStatsAccumulation(t *testing.T) {
	m := &Monitor{stats: map[string]*stat{}}
	// unknown(init) -> alive(40) -> alive(60) -> down -> down -> alive(50)
	m.record("e", "E", "endpoint", Alive, 40, 1000)
	m.record("e", "E", "endpoint", Alive, 60, 2000)
	m.record("e", "E", "endpoint", Down, 0, 3000)
	m.record("e", "E", "endpoint", Down, 0, 4000)
	m.record("e", "E", "endpoint", Alive, 50, 5000)

	v := toView("e", m.stats["e"], 9000)
	if v.Probes != 5 {
		t.Fatalf("probes=%d want 5", v.Probes)
	}
	if v.SuccessRate != 60 {
		t.Fatalf("success_rate=%d want 60 (3 of 5)", v.SuccessRate)
	}
	if v.AvgLatencyMs != 50 {
		t.Fatalf("avg=%d want 50 ((40+60+50)/3)", v.AvgLatencyMs)
	}
	if v.Reconnects != 1 {
		t.Fatalf("reconnects=%d want 1 (one down->alive recovery)", v.Reconnects)
	}
	if v.UptimeS != 4 {
		t.Fatalf("uptime=%d want 4 (since became alive at t=5000)", v.UptimeS)
	}
	if v.State != "alive" {
		t.Fatalf("state=%s want alive", v.State)
	}
}

func TestFirstConnectIsNotReconnect(t *testing.T) {
	m := &Monitor{stats: map[string]*stat{}}
	m.record("e", "E", "endpoint", Unknown, 0, 1000)
	m.record("e", "E", "endpoint", Alive, 10, 2000) // unknown->alive is the first connect
	if v := toView("e", m.stats["e"], 3000); v.Reconnects != 0 {
		t.Fatalf("reconnects=%d want 0", v.Reconnects)
	}
}
