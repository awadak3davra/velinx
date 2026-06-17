package watchdog

import (
	"errors"
	"testing"
	"time"
)

// fakeSup is a controllable Supervisor for deterministic watchdog tests.
type fakeSup struct {
	desired  bool
	alive    bool
	starts   int
	startErr error
	onStart  func() // called inside Start (e.g. to flip alive)
}

func (f *fakeSup) Desired() bool { return f.desired }
func (f *fakeSup) Alive() bool   { return f.alive }
func (f *fakeSup) Start() error {
	f.starts++
	if f.onStart != nil {
		f.onStart()
	}
	return f.startErr
}

// newAt builds a watchdog with a controllable clock starting at t.
func newAt(sup Supervisor, t *time.Time) *Watchdog {
	w := New("test", sup)
	w.now = func() time.Time { return *t }
	return w
}

func TestNotDesiredNeverRestarts(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: false, alive: false}
	w := newAt(f, &now)
	for i := 0; i < 5; i++ {
		w.tick()
		now = now.Add(w.interval)
	}
	if f.starts != 0 {
		t.Fatalf("not-desired supervisor was restarted %d times", f.starts)
	}
}

func TestAliveNeverRestarts(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: true}
	w := newAt(f, &now)
	for i := 0; i < 5; i++ {
		w.tick()
		now = now.Add(w.interval)
	}
	if f.starts != 0 {
		t.Fatalf("alive supervisor was restarted %d times", f.starts)
	}
	if st := w.Stats(); !st.Supervised || !st.Alive || st.Restarts != 0 {
		t.Fatalf("unexpected stats: %+v", st)
	}
}

func TestCrashTriggersRestart(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: false}
	f.onStart = func() { f.alive = true } // recovers on restart
	w := newAt(f, &now)

	w.tick() // sees dead -> restart #1
	if f.starts != 1 {
		t.Fatalf("expected 1 restart, got %d", f.starts)
	}
	st := w.Stats()
	if st.Restarts != 1 || st.LastRestart == "" {
		t.Fatalf("stats not recorded: %+v", st)
	}

	// Now alive; advancing past `stable` should clear the backoff.
	now = now.Add(w.stable + time.Second)
	w.tick()
	if bo := w.Stats().BackoffMS; bo != 0 {
		t.Fatalf("backoff not cleared after stable period: %d ms", bo)
	}
	if f.starts != 1 {
		t.Fatalf("extra restart while alive: %d", f.starts)
	}
}

func TestBackoffGrowsOnCrashLoop(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: false} // never recovers
	w := newAt(f, &now)

	var backoffs []int64
	// Drive several restart attempts, jumping the clock to each nextAttempt.
	for i := 0; i < 4; i++ {
		w.tick()
		backoffs = append(backoffs, w.Stats().BackoffMS)
		w.mu.Lock()
		next := w.nextAttempt
		w.mu.Unlock()
		now = next // jump exactly to when the next attempt is allowed
	}
	if f.starts != 4 {
		t.Fatalf("expected 4 restart attempts, got %d", f.starts)
	}
	// 1s, 2s, 4s, 8s — strictly growing.
	want := []int64{1000, 2000, 4000, 8000}
	for i := range want {
		if backoffs[i] != want[i] {
			t.Fatalf("backoff[%d] = %d ms, want %d (seq=%v)", i, backoffs[i], want[i], backoffs)
		}
	}
}

func TestBackoffWindowBlocksEagerRestart(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: false}
	w := newAt(f, &now)

	w.tick() // restart #1, backoff 1s, nextAttempt = now+1s
	if f.starts != 1 {
		t.Fatalf("expected 1 restart, got %d", f.starts)
	}
	// Tick again immediately (still within the backoff window) -> no restart.
	now = now.Add(500 * time.Millisecond)
	w.tick()
	if f.starts != 1 {
		t.Fatalf("restart fired inside backoff window: starts=%d", f.starts)
	}
	// Past the window -> restart #2.
	now = now.Add(1 * time.Second)
	w.tick()
	if f.starts != 2 {
		t.Fatalf("expected restart after window, got starts=%d", f.starts)
	}
}

func TestStartErrorRecorded(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: false, startErr: errors.New("boom")}
	w := newAt(f, &now)
	w.tick()
	if st := w.Stats(); st.LastError != "boom" {
		t.Fatalf("start error not surfaced: %+v", st)
	}
}

func TestPluginSupervisorCalledEachTick(t *testing.T) {
	now := time.Unix(0, 0)
	f := &fakeSup{desired: true, alive: true}
	w := newAt(f, &now)
	calls := 0
	w.SetPluginSupervisor(func() { calls++ })
	for i := 0; i < 3; i++ {
		w.tick()
	}
	if calls != 3 {
		t.Fatalf("plugin supervisor called %d times, want 3", calls)
	}
}
