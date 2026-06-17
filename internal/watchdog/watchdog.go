// Package watchdog supervises a long-running process (sing-box, and best-effort
// the engine plugins) and restarts it when it crashes, with exponential backoff
// so a config that crash-loops doesn't thrash. It records restart accounting that
// the UI surfaces on the Dashboard / Diagnostics.
package watchdog

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Supervisor is the minimal contract the watchdog needs from a managed process.
// *core.SingBox implements it.
type Supervisor interface {
	Desired() bool // is it supposed to be running?
	Alive() bool   // is the process currently up?
	Start() error  // (re)start it
}

// Stats is the JSON-facing watchdog state.
type Stats struct {
	Supervised  bool   `json:"supervised"`             // process is desired-running
	Alive       bool   `json:"alive"`                  // process is currently up
	Restarts    int    `json:"restarts"`               // crash-restarts since boot
	LastRestart string `json:"last_restart,omitempty"` // RFC3339 UTC
	LastError   string `json:"last_error,omitempty"`   // last restart error, if any
	BackoffMS   int64  `json:"backoff_ms,omitempty"`   // current backoff window
}

// Watchdog supervises one Supervisor on a fixed tick.
type Watchdog struct {
	name       string
	sup        Supervisor
	interval   time.Duration
	minBackoff time.Duration
	maxBackoff time.Duration
	stable     time.Duration // alive this long after a restart => clear backoff

	notify  func(string) // optional alert hook (e.g. WGBot); nil = off
	plugins func()       // optional per-tick plugin supervision; nil = off
	now     func() time.Time

	mu          sync.Mutex
	restarts    int
	lastRestart time.Time
	lastErr     string
	backoff     time.Duration
	nextAttempt time.Time
}

// New builds a watchdog with router-friendly defaults (3s tick, 1s→60s backoff).
func New(name string, sup Supervisor) *Watchdog {
	return &Watchdog{
		name:       name,
		sup:        sup,
		interval:   3 * time.Second,
		minBackoff: 1 * time.Second,
		maxBackoff: 60 * time.Second,
		stable:     30 * time.Second,
		now:        time.Now,
	}
}

// SetNotify installs an optional alert hook, fired on each crash-restart. Off by
// default — wire it to WGBot only when the user opts in.
func (w *Watchdog) SetNotify(f func(string)) { w.notify = f }

// SetPluginSupervisor installs an optional per-tick callback to also supervise
// the engine plugins (best-effort restart of dead long-running plugin procs).
func (w *Watchdog) SetPluginSupervisor(f func()) { w.plugins = f }

// Run ticks until ctx is cancelled.
func (w *Watchdog) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick()
		}
	}
}

// tick is one supervision cycle (exported logic kept here for unit testing).
func (w *Watchdog) tick() {
	if w.plugins != nil {
		w.plugins()
	}
	if !w.sup.Desired() {
		w.clearBackoff()
		return
	}
	now := w.now()
	if w.sup.Alive() {
		// Clear the backoff only once it has stayed up for `stable` — so a
		// crash loop (dies again before that) keeps the window growing.
		w.mu.Lock()
		if w.backoff > 0 && !w.lastRestart.IsZero() && now.Sub(w.lastRestart) >= w.stable {
			w.backoff = 0
			w.nextAttempt = time.Time{}
		}
		w.mu.Unlock()
		return
	}

	// Crashed while it should be up — restart, honoring the backoff window.
	w.mu.Lock()
	if !w.nextAttempt.IsZero() && now.Before(w.nextAttempt) {
		w.mu.Unlock()
		return
	}
	if w.backoff == 0 {
		w.backoff = w.minBackoff
	} else if w.backoff < w.maxBackoff {
		w.backoff *= 2
		if w.backoff > w.maxBackoff {
			w.backoff = w.maxBackoff
		}
	}
	w.nextAttempt = now.Add(w.backoff)
	w.mu.Unlock()

	err := w.sup.Start()
	w.mu.Lock()
	w.restarts++
	w.lastRestart = now
	if err != nil {
		w.lastErr = err.Error()
	} else {
		w.lastErr = ""
	}
	n, backoff := w.restarts, w.backoff
	w.mu.Unlock()

	if w.notify != nil {
		msg := fmt.Sprintf("%s crashed — restart #%d (next backoff %s)", w.name, n, backoff)
		if err != nil {
			msg = fmt.Sprintf("%s crashed — restart #%d FAILED: %v", w.name, n, err)
		}
		w.notify(msg)
	}
}

func (w *Watchdog) clearBackoff() {
	w.mu.Lock()
	w.backoff = 0
	w.nextAttempt = time.Time{}
	w.mu.Unlock()
}

// Stats returns the current supervision state for the API/UI.
func (w *Watchdog) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := Stats{
		Supervised: w.sup.Desired(),
		Alive:      w.sup.Alive(),
		Restarts:   w.restarts,
		LastError:  w.lastErr,
		BackoffMS:  w.backoff.Milliseconds(),
	}
	if !w.lastRestart.IsZero() {
		st.LastRestart = w.lastRestart.UTC().Format(time.RFC3339)
	}
	return st
}
