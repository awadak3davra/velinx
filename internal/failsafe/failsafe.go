// Package failsafe implements the "Apply (until reboot) vs Apply & Save" safety
// net. After a non-committed Apply it watches connectivity; if the router loses
// internet it auto-rolls-back the previous config, and if internet stays down it
// can auto-reboot (guarded). The decision logic lives in tick() so it can be
// unit-tested without real time, network or reboots.
package failsafe

import (
	"context"
	"sync"
	"time"
)

// Action is what the run loop should do after a tick.
type Action int

const (
	ActNone     Action = iota
	ActRollback        // restore the previous config + reload
	ActReboot          // last resort: reboot the router
	ActDone            // stop watching (kept live, or recovered)
)

// Durations controls the state machine timings.
type Durations struct {
	Grace         time.Duration // wait after apply before first check
	Interval      time.Duration // between connectivity checks
	RollbackAfter time.Duration // bad-for this long -> rollback
	RebootAfter   time.Duration // bad-for this long -> reboot
	KeepWindow    time.Duration // good-for this long -> leave live (unsaved)
}

// DefaultDurations are sensible production defaults.
func DefaultDurations() Durations {
	return Durations{
		Grace:         20 * time.Second,
		Interval:      15 * time.Second,
		RollbackAfter: 45 * time.Second,
		RebootAfter:   5 * time.Minute,
		KeepWindow:    3 * time.Minute,
	}
}

// Status is the JSON-facing fail-safe state.
type Status struct {
	Pending     bool   `json:"pending"`
	Phase       string `json:"phase"` // idle|armed|degraded|rolled_back|rollback_failed|committed|live_unsaved|reboot
	SecondsLeft int    `json:"seconds_left"`
	LastCheckOk bool   `json:"last_check_ok"`
	LastCheckAt int64  `json:"last_check_at"`
	LastError   string `json:"last_error,omitempty"` // why a rollback failed, if it did
}

// Manager runs at most one pending fail-safe window at a time.
type Manager struct {
	mu         sync.Mutex
	d          Durations
	pending    bool
	phase      string
	armedAt    int64 // unix ms
	deadline   int64
	bad        bool
	badSince   int64
	rolledBack bool
	dispatched bool // rb() has been (or is being) invoked for this window — gates fire-once
	lastOk     bool
	lastAt     int64
	lastErr    string

	rollback    func() error
	reboot      func()
	allowReboot bool
	cancel      context.CancelFunc // cancels the currently-armed run() goroutine
}

// New builds a Manager.
func New(d Durations) *Manager { return &Manager{d: d, phase: "idle"} }

func nowMS() int64 { return time.Now().UnixMilli() }

// Arm starts a fail-safe window: check() reports connectivity, rollback()
// restores the previous config, reboot() reboots (only called if allowReboot).
// Re-arming supersedes any prior window so exactly one run() goroutine is ever
// live (a repeated un-saved Apply must not leak a goroutine that double-drives
// the state machine and could double-fire rollback/reboot).
func (m *Manager) Arm(check func() bool, rollback func() error, reboot func(), allowReboot bool) {
	now := nowMS()
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel() // stop the previous window's goroutine
	}
	m.cancel = cancel
	m.pending = true
	m.phase = "armed"
	m.rolledBack = false
	m.dispatched = false
	m.bad = false
	m.badSince = 0
	m.lastErr = ""
	m.armedAt = now
	m.deadline = now + int64(m.d.KeepWindow/time.Millisecond)
	m.rollback = rollback // kept for RollbackNow() (read under the lock)
	m.reboot = reboot
	m.allowReboot = allowReboot
	m.mu.Unlock()
	// Pass the callbacks to run() so its loop uses local copies instead of reading
	// the shared m.rollback/m.reboot/m.allowReboot fields lock-free (which would
	// race a concurrent re-Arm writing them).
	go m.run(ctx, check, rollback, reboot, allowReboot)
}

func (m *Manager) run(ctx context.Context, check func() bool, rollback func() error, reboot func(), allowReboot bool) {
	grace := time.NewTimer(m.d.Grace)
	select {
	case <-grace.C:
	case <-ctx.Done():
		grace.Stop()
		return
	}
	grace.Stop() // drain in case both channels are ready
	t := time.NewTicker(m.d.Interval)
	defer t.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		pending := m.pending
		m.mu.Unlock()
		if !pending {
			return
		}
		switch m.tick(nowMS(), check()) {
		case ActRollback:
			// Fire at most once per window: skip if a manual RollbackNow already
			// claimed (and is running/ran) the rollback for this window.
			if rollback != nil && m.claimRollback() {
				if err := rollback(); err != nil {
					m.markRollbackFailed(err)
				}
			}
		case ActReboot:
			if allowReboot && reboot != nil {
				reboot()
			}
			return
		case ActDone:
			return
		}
		select {
		case <-t.C:
		case <-ctx.Done():
			return
		}
	}
}

// claimRollback atomically claims the right to invoke rb() for the current
// fail-safe window. It returns true to exactly ONE caller; every later caller
// (a concurrent RollbackNow racing tick()'s auto path, or a second RollbackNow)
// gets false and must NOT call rb(). This makes the rollback fire at most once
// per window even though rb() is invoked unlocked. The flag is reset on Arm().
func (m *Manager) claimRollback() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dispatched {
		return false
	}
	m.dispatched = true
	return true
}

// markRollbackFailed records that the rollback could not restore the config, so
// Status reports the truth ("rollback_failed") instead of a false "rolled_back".
func (m *Manager) markRollbackFailed(err error) {
	m.mu.Lock()
	m.phase = "rollback_failed"
	if err != nil {
		m.lastErr = err.Error()
	}
	m.mu.Unlock()
}

// tick advances the state machine. Pure w.r.t. its (now, ok) inputs so tests can
// drive it directly. It optimistically sets phase="rolled_back" when it triggers
// a rollback; run()/RollbackNow correct it to "rollback_failed" if the rollback
// actually errors.
func (m *Manager) tick(now int64, ok bool) Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.pending {
		return ActNone
	}
	m.lastOk, m.lastAt = ok, now

	if ok {
		m.bad = false
		m.badSince = 0
		if m.rolledBack {
			m.pending = false // internet recovered after rollback
			return ActDone
		}
		if now >= m.deadline {
			m.pending = false // stayed healthy through the keep window -> live (unsaved)
			m.phase = "live_unsaved"
			return ActDone
		}
		m.phase = "armed"
		return ActNone
	}

	// connectivity is bad
	if !m.bad {
		m.bad = true
		m.badSince = now
	}
	badFor := now - m.badSince
	if badFor >= int64(m.d.RebootAfter/time.Millisecond) {
		m.pending = false
		m.phase = "reboot"
		return ActReboot
	}
	if !m.rolledBack && badFor >= int64(m.d.RollbackAfter/time.Millisecond) {
		m.rolledBack = true
		m.phase = "rolled_back"
		return ActRollback
	}
	if !m.rolledBack {
		m.phase = "degraded"
	}
	return ActNone
}

// Confirm commits the live config (user said it works); cancels the window.
func (m *Manager) Confirm() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending = false
	m.phase = "committed"
	if m.cancel != nil {
		m.cancel()
	}
}

// RollbackNow performs an immediate manual rollback.
func (m *Manager) RollbackNow() error {
	m.mu.Lock()
	rb := m.rollback
	already := m.dispatched // tick()'s auto path may have already claimed/fired rb()
	if !already {
		m.dispatched = true // claim the single fire-once dispatch under the lock
	}
	m.pending = false
	m.phase = "rolled_back"
	m.rolledBack = true
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Unlock()
	// Fire at most once per window: if the auto path already dispatched the
	// rollback, do NOT invoke rb() a second time (avoids a double rollback).
	if already {
		return nil
	}
	if rb != nil {
		if err := rb(); err != nil {
			m.markRollbackFailed(err)
			return err
		}
	}
	return nil
}

// Status returns the current fail-safe state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Status{Pending: m.pending, Phase: m.phase, LastCheckOk: m.lastOk, LastCheckAt: m.lastAt, LastError: m.lastErr}
	if m.pending && !m.rolledBack {
		if left := (m.deadline - nowMS()) / 1000; left > 0 {
			s.SecondsLeft = int(left)
		}
	}
	return s
}
