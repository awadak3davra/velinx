package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"wakeroute/internal/atomicfile"
	"wakeroute/internal/config"
	"wakeroute/internal/generator"
	"wakeroute/internal/importer"
	"wakeroute/internal/model"
	"wakeroute/internal/pbr"
	"wakeroute/internal/plugin"
)

// handleImport parses a share link / conf into an endpoint WITHOUT saving it
// (preview before the user confirms).
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	e, err := importer.Parse(body.Link)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Profile())
}

func (s *Server) handleUpsertEndpoint(w http.ResponseWriter, r *http.Request) {
	var e model.Endpoint
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid endpoint JSON")
		return
	}
	if err := s.store.UpsertEndpoint(e); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) handleDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteEndpoint(id); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) handleUpsertGroup(w http.ResponseWriter, r *http.Request) {
	var g model.Group
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid group JSON")
		return
	}
	if err := s.store.UpsertGroup(g); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteGroup(id); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) handleUpsertRule(w http.ResponseWriter, r *http.Request) {
	var ru model.Rule
	if err := json.NewDecoder(r.Body).Decode(&ru); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid rule JSON")
		return
	}
	if err := s.store.UpsertRule(ru); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ru)
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteRule(id); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// --- Routing lists (the "Routing" page) ---

func (s *Server) handleUpsertRoutingList(w http.ResponseWriter, r *http.Request) {
	var rl model.RoutingList
	if err := json.NewDecoder(r.Body).Decode(&rl); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid routing list JSON")
		return
	}
	if err := s.store.UpsertRoutingList(rl); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rl)
}

func (s *Server) handleDeleteRoutingList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteRoutingList(id); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// handleRoutingCatalog returns the curated pre-defined rule-set presets.
func (s *Server) handleRoutingCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, model.RoutingPresets())
}

// handleRoutingStatus reports, per routing list, whether its remote rule-set source
// is reachable/downloadable — the signal the Routing UI shows as a green/red dot +
// error code under each list. Manual (no-source) lists are always ok. Probes run
// concurrently and reuse the SSRF-guarded fetch client.
func (s *Server) handleRoutingStatus(w http.ResponseWriter, r *http.Request) {
	prof := s.store.Profile()
	type st struct {
		ID     string `json:"id"`
		OK     bool   `json:"ok"`
		Status int    `json:"status,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	res := make([]st, len(prof.RoutingLists))
	client := s.subscriptionFetchClient()
	var wg sync.WaitGroup
	for i, rl := range prof.RoutingLists {
		if rl.Source == "" {
			res[i] = st{ID: rl.ID, OK: true} // manual list — nothing to download
			continue
		}
		wg.Add(1)
		go func(i int, id, src string) {
			defer wg.Done()
			cur := st{ID: id}
			ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
			if err != nil {
				cur.Error = "bad url: " + err.Error()
				res[i] = cur
				return
			}
			req.Header.Set("User-Agent", "wakeroute")
			resp, err := client.Do(req)
			if err != nil {
				cur.Error = err.Error()
				res[i] = cur
				return
			}
			resp.Body.Close()
			cur.Status = resp.StatusCode
			cur.OK = resp.StatusCode >= 200 && resp.StatusCode < 400
			if !cur.OK {
				cur.Error = "HTTP " + resp.Status
			}
			res[i] = cur
		}(i, rl.ID, rl.Source)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, res)
}

// handleGenerate returns the sing-box config for the current profile (preview).
func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	p := s.store.Profile()
	res, err := generator.Generate(&p, s.genOptions(&p))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":  res.Config,
		"plugins": pluginSummary(res.Plugins),
	})
}

// syncPluginsFor (re)starts the engine plugins (AmneziaWG interfaces, olcRTC
// procs) required by a generated config. Idempotent; safe to call repeatedly.
func (s *Server) syncPluginsFor(res *generator.Result) {
	specs := make([]plugin.Spec, 0, len(res.Plugins))
	for _, pl := range res.Plugins {
		specs = append(specs, plugin.Spec{ID: pl.Endpoint.ID, Endpoint: pl.Endpoint, SOCKSPort: pl.SOCKSPort})
	}
	s.plugins.Sync(specs)
}

// SyncPlugins brings up the engine plugins the current profile needs AND, in hybrid
// mode, installs the kernel PBR plane. The daemon calls this on start so AmneziaWG/olcRTC
// tunnels + the kernel routes come up from boot — the watchdog only crash-restarts
// already-running plugins, and an Apply is otherwise required. The PBR install is FOLDED
// here (not a separate goroutine) so it runs AFTER the kernel interfaces are up in the
// same goroutine — `ip route ... dev awgX` fails if the device doesn't exist yet, and two
// bare `go` calls have no ordering. No-op in demo mode (must not touch host interfaces/nft).
func (s *Server) SyncPlugins() {
	c := s.config()
	if c.Demo {
		return
	}
	p := s.store.Profile()
	opts, newPlan := s.genOptionsWithPlan(&p, c)
	res, err := generator.Generate(&p, opts)
	if err != nil {
		// Boot path: a swallowed generate error here means the engine plugins + kernel PBR
		// plane never come up after a reboot, with no trace of why. Log it (the watchdog /
		// next Apply will retry); don't change the fail-soft behavior otherwise.
		log.Printf("wakeroute: boot SyncPlugins skipped — config generation failed (tunnels/PBR not brought up): %v", err)
		return
	}
	s.syncPluginsFor(res) // brings AmneziaWG/olcRTC interfaces UP first
	if newPlan != nil {
		// Hybrid: install the kernel plane now that the interfaces exist (best-effort —
		// a later Apply re-establishes; applyPBR records pbrPlan=nil on failure).
		if err := s.applyPBR(newPlan); err != nil {
			log.Printf("SyncPlugins: boot PBR apply failed: %v", err)
		}
	} else if s.pbrRunner != nil {
		// Not hybrid: clear any stale "wakeroute_pbr" table left by a prior hybrid era
		// (e.g. the user switched to tun via Settings and never Applied, then rebooted —
		// the in-memory pbrPlan is nil so there's nothing else to tear down). Idempotent.
		_ = (&pbr.Plan{Table: "wakeroute_pbr"}).Teardown(s.pbrRunner, pbr.Options{})
	}
}

// handleApply generates the config, validates it with sing-box (if available),
// atomically swaps it in, and reloads a running sing-box. Body {save:bool}:
// false (Apply) arms the fail-safe rollback window; true (Apply & Save) commits.
func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Save bool `json:"save"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	// Serialize applies: two concurrent applies would race on the shared
	// singbox.json.tmp path and on Backup()/Restore(), and could interleave the
	// fail-safe window.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	c := s.config() // one consistent snapshot of Demo/RoutingMode/SingBox.Config for this apply
	p := s.store.Profile()
	// genOptionsWithPlan compiles the hybrid Plan ONCE and returns it, so the kernel plane
	// (applyPBR below) and the TUN route_exclude in opts are the same compile — never desync.
	opts, newPlan := s.genOptionsWithPlan(&p, c)
	res, err := generator.Generate(&p, opts)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	data, err := json.MarshalIndent(res.Config, "", "  ")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	path := c.SingBox.Config
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmp := path + ".tmp"
	if err := atomicfile.WriteSynced(tmp, data, 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	checked := false
	if s.singbox.Available() {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if err := s.singbox.CheckConfig(ctx, tmp); err != nil {
			_ = os.Remove(tmp)
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		checked = true
	}

	// Snapshot the pre-window config as the rollback baseline — but only at the
	// FIRST apply of a fail-safe window. A second apply while a window is still
	// open must NOT overwrite the baseline with the interim (unconfirmed, maybe
	// broken) config, or a later rollback would restore that instead of the last
	// known-good config.
	var backupErr, reloadErr, commitErr string
	if !s.failsafe.Status().Pending {
		// A failed Backup means the fail-safe has no rollback target — surface + log it
		// (don't abort: the PBR-fail and connectivity paths below already degrade safely
		// when there's no .bak, and the user may still want to apply).
		if err := s.singbox.Backup(); err != nil {
			backupErr = err.Error()
			log.Printf("handleApply: backup (rollback snapshot) failed: %v — fail-safe may be unable to restore", err)
		}
		s.snapshotPBRBaseline()    // capture the pre-window kernel plan as the rollback target
		s.snapshotPluginBaseline() // capture the pre-window engine-plugin specs too
	}
	if err := os.Rename(tmp, path); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	atomicfile.SyncDir(filepath.Dir(path)) // make the rename durable across power loss

	reloaded := false
	if s.singbox.Running() {
		if err := s.singbox.Reload(); err != nil {
			reloadErr = err.Error()
			log.Printf("handleApply: sing-box reload failed: %v", err)
		} else {
			reloaded = true
		}
	} else if s.singbox.Available() {
		// Not running yet — bring it up so the new config takes effect (and the
		// watchdog starts supervising it).
		if err := s.singbox.Start(); err != nil {
			reloadErr = err.Error()
			log.Printf("handleApply: sing-box start failed: %v", err)
		} else {
			reloaded = true
		}
	}

	// (re)start engine plugins (AmneziaWG, olcRTC) for this config's chained outbounds.
	s.syncPluginsFor(res)

	// Kernel PBR plane (hybrid only; newPlan is nil otherwise). Install the fwmark routes
	// for the CIDRs the generator route_excluded from the TUN, AFTER the sing-box reload so
	// the kernel catch exists as the TUN stops capturing those dests. Demo/non-router is a
	// no-op. On failure during a NON-save apply we ABORT to baseline: the default fail-safe
	// ping target (1.1.1.1) sits OUTSIDE every excluded zone, so a kernel-plane-only failure
	// would otherwise sail through the connectivity check and commit green while the
	// carve-out (e.g. a carrier VoWiFi range) is dead — the exact failure this mode exists to fix.
	var pbrErr error
	if !c.Demo {
		if pbrErr = s.applyPBR(newPlan); pbrErr != nil {
			log.Printf("handleApply: PBR apply failed: %v", pbrErr)
			if !body.Save {
				// Roll the sing-box config back to the pre-apply baseline and tear the
				// kernel plane back to its baseline. If there is NO rollback target (a
				// first-ever apply leaves no .bak, so Restore is a no-op), don't leave a
				// half-hybrid config running unwatched — stop sing-box so the router falls
				// back to plain WAN routing, which the user can then re-apply over.
				restoreErr := s.singbox.Restore()
				if restoreErr == nil {
					if s.singbox.Running() {
						_ = s.singbox.Reload()
					} else if s.singbox.Available() {
						_ = s.singbox.Start()
					}
				} else if s.singbox.Running() {
					_ = s.singbox.Stop()
				}
				s.restorePBRBaseline()
				msg := "hybrid PBR apply failed, rolled back: " + pbrErr.Error()
				if restoreErr != nil {
					msg = "hybrid PBR apply failed; no rollback target, sing-box stopped (plain WAN): " + pbrErr.Error()
				}
				writeErr(w, http.StatusInternalServerError, msg)
				return
			}
			// Save==true: the user explicitly committed; surface the error in the response
			// but keep the applied config (matches the no-abort posture after the rename).
		}
	}

	if body.Save {
		if err := s.singbox.Commit(); err != nil {
			commitErr = err.Error()
			log.Printf("handleApply: commit (save baseline) failed: %v", err)
		}
		s.failsafe.Confirm()
	} else {
		s.armFailSafe()
	}

	resp := map[string]any{
		"applied":     true,
		"saved":       body.Save,
		"checked":     checked,
		"reloaded":    reloaded,
		"config_path": path,
		"plugins":     pluginSummary(res.Plugins),
		"failsafe":    s.failsafe.Status(),
	}
	if pbrErr != nil {
		resp["pbr_error"] = pbrErr.Error() // only on failure → non-hybrid/demo responses stay byte-identical
	}
	// Surface the previously-swallowed apply errors ONLY when present, so a successful
	// apply keeps a byte-identical response (the UI + tests depend on the happy-path shape).
	if backupErr != "" {
		resp["backup_error"] = backupErr
	}
	if reloadErr != "" {
		resp["reload_error"] = reloadErr
	}
	if commitErr != "" {
		resp["commit_error"] = commitErr
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSubscription parses a subscription (pasted text or a fetched URL) into
// endpoints WITHOUT saving them, so the user can pick which to import.
func (s *Server) handleSubscription(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL  string `json:"url"`
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	text := body.Text
	if body.URL != "" {
		u, perr := url.Parse(body.URL)
		if perr != nil {
			writeErr(w, http.StatusBadRequest, "bad url: "+perr.Error())
			return
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			writeErr(w, http.StatusBadRequest, "subscription url must be an http(s) URL")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, body.URL, nil)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad url: "+err.Error())
			return
		}
		req.Header.Set("User-Agent", "wakeroute")
		resp, err := s.subscriptionFetchClient().Do(req)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "fetch failed: "+err.Error())
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			writeErr(w, http.StatusBadGateway, "subscription returned status "+resp.Status)
			return
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		text = string(b)
	}
	eps, errs := importer.ParseSubscription(text)
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": eps, "errors": errs})
}

// subscriptionFetchClient is an http.Client for fetching a user-supplied
// subscription URL with an SSRF guard: it refuses to connect to loopback /
// private / link-local addresses (so the panel can't be used to reach the
// router's own Clash API, other LAN hosts, or cloud metadata). The check runs at
// DIAL time on the already-resolved IP, so it also covers redirects and
// DNS-rebinding. Redirects are capped. (allowInternalFetch disables the guard for
// tests that point at a loopback httptest server.)
func (s *Server) subscriptionFetchClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if !s.allowInternalFetch {
		dialer.Control = blockInternalDial
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}
}

// blockInternalDial rejects a dial to a loopback/private/link-local/unspecified
// address. address is host:port with host already resolved to an IP literal.
func blockInternalDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("could not parse dial address %q", address)
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("refusing to fetch from internal address %s", ip)
	}
	return nil
}

// handleBulkEndpoints upserts many endpoints at once (subscription import).
func (s *Server) handleBulkEndpoints(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Endpoints []model.Endpoint `json:"endpoints"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// Non-fatal: each UpsertEndpoint persists immediately, so bailing on the Nth
	// error would leave 1..N-1 saved while reporting total failure. Accumulate
	// per-endpoint errors and always report the true saved count.
	saved := 0
	var errs []string
	for _, e := range body.Endpoints {
		if e.ID == "" {
			errs = append(errs, "skipped an endpoint with no id")
			continue
		}
		if err := s.store.UpsertEndpoint(e); err != nil {
			errs = append(errs, e.ID+": "+err.Error())
			continue
		}
		saved++
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": saved, "errors": errs})
}

// routingMode resolves the effective routing mode from a config snapshot: "" derives
// from Gateway (back-compat — TUN when gateway is on, else mixed-proxy-only); an explicit
// value ("tun"/"hybrid"/"mixed") wins. One resolver shared by genOptionsWithPlan,
// handleApply, and SyncPlugins so the two planes never disagree on which mode is active.
func (s *Server) routingMode(c config.Config) string {
	mode := c.RoutingMode
	if mode == "" {
		if c.Gateway {
			mode = "tun"
		} else {
			mode = "mixed"
		}
	}
	return mode
}

// genOptionsWithPlan builds the generator options for the given profile AND returns the
// kernel-routing Plan it compiled (nil unless hybrid). handleApply and the boot sync use
// the SAME returned plan to install the kernel plane (applyPBR), so the TUN route_exclude
// set and the kernel routes are always ONE compile of ONE profile — they can never
// desync. The Plan is the single source of truth for the hybrid partition. NOT demo-gated
// (config generation is identical in demo); the demo guard lives only on the kernel side
// (applyPBR), so a demo daemon produces a byte-identical singbox.json without touching nft/ip.
func (s *Server) genOptionsWithPlan(p *model.Profile, c config.Config) (generator.Options, *pbr.Plan) {
	opts := generator.Options{
		MixedPort:   c.Ports.Mixed,
		ClashAddr:   c.Clash.Controller,
		ClashSecret: c.Clash.Secret,
		CacheFile:   filepath.Join(filepath.Dir(c.SingBox.Config), "cache.db"),
		TunEnabled:  c.Gateway,
		TunMTU:      c.GatewayMTU,
		TunAddr:     c.GatewayAddr,
	}
	mode := s.routingMode(c)
	if (mode != "hybrid" && mode != "fast") || p == nil {
		return opts, nil
	}
	// Phase 1b flow-offload applies to "fast" only: it accelerates the GENERAL kernel
	// fast-path, which exists only in fast mode. In hybrid, general traffic transits the
	// capture-all TUN (there is no LAN↔WAN flow to offload), so offload is left off there.
	pbrOpts := pbr.Options{}
	if mode == "fast" {
		pbrOpts.Offload = c.Offload
		devs := c.OffloadDevices
		// Auto-discover the WAN+LAN devices when offload is requested without an explicit
		// list. Gated so the host probe runs ONLY in the opt-in case (never in demo/tests):
		// offload set + no devices given + not demo. The probe is best-effort (empty on a
		// non-router host → Compile skips offload + warns).
		if (c.Offload == "sw" || c.Offload == "hw") && len(devs) == 0 && !c.Demo {
			devs = probeOffloadDevices()
		}
		pbrOpts.OffloadDevices = devs
	}
	plan, _, err := pbr.Compile(p, pbrOpts)
	if err != nil {
		// Fail-safe: never emit a half-hybrid config that excludes CIDRs nothing routes.
		// Fall back to the non-hybrid (TUN) shape and return no plan — both planes agree
		// (nothing excluded, nothing kernel-routed).
		log.Printf("genOptions: pbr.Compile failed, falling back to non-hybrid: %v", err)
		opts.TunEnabled = c.Gateway
		return opts, nil
	}
	opts.Hybrid = true
	if mode == "fast" {
		// "fast": no capture-all TUN. General LAN traffic stays on the kernel fast-path
		// (no userspace-TUN tax → near-line-rate); ONLY the pbr kernel plane (IP/CIDR
		// carve-outs like TG-calls/VoWiFi) steers LAN traffic via fwmark. Domain carve-outs
		// are inactive for LAN here (no TUN to sniff them) — they'd only affect the local
		// mixed-proxy inbound. No route_exclude needed (there is no TUN to exclude from);
		// the plan is still returned so handleApply installs the kernel routes. Phase 1b
		// will additionally enable HW flow-offload (excluding carve-out marks).
		opts.TunEnabled = false
		return opts, plan
	}
	opts.TunEnabled = true // hybrid always keeps the TUN, regardless of c.Gateway
	// Exclude the CIDRs the kernel plane routes — every zone EXCEPT blackhole — plus
	// the anti-loop bypass (peer server IPs). Block stays in the sing-box reject plane
	// in hybrid (the generator keeps block rules as reject actions), so its CIDRs must
	// NOT be excluded from the TUN: excluding them would let the now-dead reject be
	// bypassed and blocked traffic fall through to WAN. The kernel still models the
	// blackhole zone (for a future kernel-level drop) but it isn't part of the TUN
	// exclude contract here.
	blackhole := map[string]bool{}
	for _, e := range plan.Egresses {
		if e.Kind == pbr.EgressBlackhole {
			blackhole[e.Tag] = true
		}
	}
	for _, z := range plan.Zones {
		if blackhole[z.EgressTag] {
			continue
		}
		opts.KernelExcludeV4 = append(opts.KernelExcludeV4, z.V4...)
		opts.KernelExcludeV6 = append(opts.KernelExcludeV6, z.V6...)
	}
	opts.KernelExcludeV4 = append(opts.KernelExcludeV4, plan.BypassV4...)
	opts.KernelExcludeV6 = append(opts.KernelExcludeV6, plan.BypassV6...)
	return opts, plan
}

// genOptions builds the generator options for the current config, discarding the plan.
// handleGenerate/SyncPlugins/preview use this; handleApply uses genOptionsWithPlan so it
// can drive the kernel plane from the same compile.
func (s *Server) genOptions(p *model.Profile) generator.Options {
	opts, _ := s.genOptionsWithPlan(p, s.config())
	return opts
}

// applyPBR installs newPlan as the kernel PBR plane, or tears the plane down when nil.
// One pbrMu-held transaction: Teardown the previously-installed plan first (the nft table
// is self-flushing on its fixed name, so this only matters to clear ip rules/routes in
// tables a SHRINKING plan no longer uses), then Apply the new plan. pbrMu is the single
// authority for s.pbrPlan + the nft/ip command stream, so a concurrent rollback or boot
// sync can't interleave. The nil-runner guard makes a Server built directly in a test
// (bypassing New()) a no-op instead of a panic.
func (s *Server) applyPBR(newPlan *pbr.Plan) error {
	s.pbrMu.Lock()
	defer s.pbrMu.Unlock()
	if s.pbrRunner == nil {
		return nil
	}
	if s.pbrPlan != nil {
		_ = s.pbrPlan.Teardown(s.pbrRunner, pbr.Options{})
	}
	if newPlan != nil {
		if err := newPlan.Apply(s.pbrRunner, pbr.Options{}); err != nil {
			// Apply is not transactional across nft+ip; tear the partial install back out
			// (best-effort) so no interim nft table / ip rules survive, and record an
			// indeterminate state so the next first-apply cleanly reinstalls.
			_ = newPlan.Teardown(s.pbrRunner, pbr.Options{})
			s.pbrPlan = nil
			return err
		}
	}
	s.pbrPlan = newPlan
	return nil
}

// snapshotPBRBaseline records the currently-installed plan as the rollback target. Called
// once at the FIRST apply of a fail-safe window (co-located with singbox.Backup), BEFORE
// applyPBR overwrites s.pbrPlan — so the baseline is the true pre-window kernel state.
func (s *Server) snapshotPBRBaseline() {
	s.pbrMu.Lock()
	defer s.pbrMu.Unlock()
	s.pbrBaseline = s.pbrPlan
}

// restorePBRBaseline restores the kernel PBR plane to the baseline snapshotted at the
// start of the fail-safe window: tear down whatever is installed now, then re-Apply the
// baseline (nil baseline = leave the plane down). Best-effort — errors are logged, not
// returned — so a secondary nft/ip failure never flips the fail-safe verdict (sing-box
// restore is the primary connectivity signal). Reads both fields at call time under pbrMu,
// so a multi-apply window restores the interim-teardown + the true pre-window baseline.
func (s *Server) restorePBRBaseline() {
	s.pbrMu.Lock()
	defer s.pbrMu.Unlock()
	if s.pbrRunner == nil {
		return
	}
	if s.pbrPlan != nil {
		_ = s.pbrPlan.Teardown(s.pbrRunner, pbr.Options{})
	}
	if s.pbrBaseline != nil {
		if err := s.pbrBaseline.Apply(s.pbrRunner, pbr.Options{}); err != nil {
			log.Printf("fail-safe: PBR baseline restore failed: %v", err)
			s.pbrPlan = nil
			return
		}
	}
	s.pbrPlan = s.pbrBaseline
}

// snapshotPluginBaseline records the engine-plugin specs currently running as the
// rollback target — taken at the FIRST apply of a fail-safe window (before
// syncPluginsFor switches them to the new config's set), co-located with the sing-box
// Backup + PBR baseline so all three roll back together.
func (s *Server) snapshotPluginBaseline() {
	s.pbrMu.Lock()
	defer s.pbrMu.Unlock()
	s.pluginBaseline = s.plugins.Specs()
}

// restorePluginBaseline re-Syncs the engine plugins to the pre-window set so a rolled-
// back sing-box config's bind_interface targets (awg devices) / chained SOCKS ports are
// the ones that config expects. Without this, rollback restores the config + kernel plane
// but leaves the plugins at the FAILED apply's set, so a restored outbound bound to an
// awg device the failed apply tore down (or a chained SOCKS on a port no longer served)
// runs dead. plugins.Sync is idempotent + internally locked; best-effort.
func (s *Server) restorePluginBaseline() {
	s.pbrMu.Lock()
	specs := append([]plugin.Spec(nil), s.pluginBaseline...)
	s.pbrMu.Unlock()
	s.plugins.Sync(specs)
}

func pluginSummary(ps []generator.Plugin) []map[string]any {
	out := make([]map[string]any, 0, len(ps))
	for _, p := range ps {
		out = append(out, map[string]any{
			"id":         p.Endpoint.ID,
			"protocol":   p.Endpoint.Protocol,
			"engine":     p.Endpoint.Engine,
			"socks_port": p.SOCKSPort,
		})
	}
	return out
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
