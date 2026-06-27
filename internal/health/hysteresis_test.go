package health

import "testing"

// TestProbeStateHysteresis proves the flap debounce (real mode, flapThreshold=2): a single
// transient Down probe does NOT flip the state or count a reconnect, while a sustained
// outage (flapThreshold consecutive Downs) does, and recovery then counts exactly one.
func TestProbeStateHysteresis(t *testing.T) {
	m := &Monitor{stats: map[string]*stat{}} // demo=false → flapThreshold=2

	m.record("e", "E", "endpoint", Alive, 20, 1000)

	// One transient Down: state holds Alive (debounced).
	m.record("e", "E", "endpoint", Down, 0, 2000)
	if v := toView("e", m.stats["e"], 3000); v.State != "alive" {
		t.Errorf("after one transient Down: state=%s want alive (debounced)", v.State)
	}
	// Recovery without ever committing Down → no reconnect.
	m.record("e", "E", "endpoint", Alive, 25, 3000)
	if v := toView("e", m.stats["e"], 4000); v.Reconnects != 0 {
		t.Errorf("reconnects=%d want 0 (a single transient Down must not inflate it)", v.Reconnects)
	}

	// A sustained outage (flapThreshold consecutive Downs) DOES flip to Down.
	for i := 0; i < flapThreshold; i++ {
		m.record("e", "E", "endpoint", Down, 0, int64(5000+i*1000))
	}
	if v := toView("e", m.stats["e"], 8000); v.State != "down" {
		t.Errorf("after %d consecutive Downs: state=%s want down", flapThreshold, v.State)
	}
	// Recovery from a confirmed outage counts exactly one reconnect.
	m.record("e", "E", "endpoint", Alive, 30, 9000)
	if v := toView("e", m.stats["e"], 10000); v.Reconnects != 1 {
		t.Errorf("reconnects=%d want 1 (one confirmed down→alive recovery)", v.Reconnects)
	}
}
