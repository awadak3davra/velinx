package server

import (
	"context"
	"log"
	"net/http"
	"os/exec"
	"time"

	"wakeroute/internal/netdiag"
)

// armFailSafe starts the rollback window after a non-saved Apply: it pings the
// configured target, rolls the config back if connectivity is lost, and (only
// when opted in, on-device) reboots as a last resort.
func (s *Server) armFailSafe() {
	c := s.config()
	target := c.FailSafe.Target
	if target == "" {
		target = "1.1.1.1"
	}
	check := func() bool {
		// The routing brain must be up for a bare ping to mean anything. The ping
		// target is often statically routed OUTSIDE sing-box — on this router
		// 1.1.1.1 (the default target) is pinned to the awg0 kernel interface for
		// DoH (`ip route get 1.1.1.1` -> dev awg0), so a ping succeeds even after a
		// new config CRASHED sing-box, and the fail-safe would never roll back.
		// Treat "sing-box installed but down" as a connectivity failure so the bad
		// config is rolled back. (Demo / no core keeps the old ping-only behavior.)
		if !routingBrainUp(s.singbox.Available(), s.singbox.Running()) {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return netdiag.Ping(ctx, target, 2).Ok
	}
	rollback := func() error {
		// Serialize the rollback against handleApply under applyMu: both rewrite the live
		// singbox.json (handleApply via Backup + os.Rename, rollback via Restore) and
		// reload the core, so without a shared lock a rollback firing mid-apply could
		// interleave the file swap + reload and leave a TORN / nondeterministic live
		// config. applyMu already guards handleApply's swap, so it is the right lock.
		// DEADLOCK-SAFE: this closure runs ONLY from goroutines that do NOT hold applyMu —
		// the failsafe run() loop (tick() releases failsafe.mu before run() calls this) and
		// RollbackNow (releases failsafe.mu before invoking it). handleApply never waits on
		// this closure (Arm just starts the goroutine), and the lock order here (applyMu
		// then pbrMu via restore*Baseline, then singbox.mu via the core calls) matches
		// handleApply's, so there is no lock-ordering cycle.
		s.applyMu.Lock()
		defer s.applyMu.Unlock()
		log.Printf("fail-safe: connectivity lost — rolling back to the previous config")
		var sbErr error
		if err := s.singbox.Restore(); err != nil {
			sbErr = err
		} else if s.singbox.Running() {
			sbErr = s.singbox.Reload()
		} else if s.singbox.Available() {
			// The core is down (it likely crashed on the bad config) — start it on the
			// restored config now rather than waiting out the watchdog crash backoff.
			sbErr = s.singbox.Start()
		}
		// Restore the kernel PBR plane to its pre-window baseline too. Best-effort and
		// demo/nil-guarded inside restorePBRBaseline; its error is LOGGED, not returned,
		// so a secondary nft/ip failure can't flip the window to "rollback_failed" when
		// sing-box (the primary connectivity brain) actually recovered.
		s.restorePBRBaseline()
		// Re-Sync the engine plugins (AmneziaWG/olcRTC) to the pre-window set so the
		// restored sing-box config's bind_interface/SOCKS targets are actually up — else
		// the restored config runs a dead tunnel. Best-effort.
		s.restorePluginBaseline()
		return sbErr
	}
	reboot := func() {
		log.Printf("fail-safe: still no connectivity after rollback — rebooting router")
		_ = exec.Command("reboot").Start()
	}
	allowReboot := !c.Demo && c.FailSafe.AutoReboot
	s.failsafe.Arm(check, rollback, reboot, allowReboot)
}

// routingBrainUp reports whether sing-box is in a state where the fail-safe's
// connectivity ping reflects the routing brain's health. It is false only when
// sing-box is installed (available) but not running — a crashed core that a ping
// routed outside sing-box would otherwise miss. With no core at all (demo,
// available=false) the ping alone is the signal, as before.
func routingBrainUp(available, running bool) bool {
	return !available || running
}

// handleApplyConfirm commits the live config (user confirmed it works).
func (s *Server) handleApplyConfirm(w http.ResponseWriter, r *http.Request) {
	_ = s.singbox.Commit()
	s.failsafe.Confirm()
	writeJSON(w, http.StatusOK, map[string]any{"committed": true, "failsafe": s.failsafe.Status()})
}

// handleApplyRollback performs an immediate manual rollback.
func (s *Server) handleApplyRollback(w http.ResponseWriter, r *http.Request) {
	if err := s.failsafe.RollbackNow(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rolled_back": true, "failsafe": s.failsafe.Status()})
}

// handleApplyStatus returns the current fail-safe state (for the countdown UI).
func (s *Server) handleApplyStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.failsafe.Status())
}
