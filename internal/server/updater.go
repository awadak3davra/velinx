package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"wakeroute/internal/updater"
	"wakeroute/internal/version"
)

// handleUpdaterEngines lists managed engines with their installed status (no network).
func (s *Server) handleUpdaterEngines(w http.ResponseWriter, r *http.Request) {
	type item struct {
		updater.Engine
		Installed updater.Installed `json:"installed"`
	}
	out := make([]item, 0, len(updater.Engines))
	for _, e := range updater.Engines {
		out = append(out, item{Engine: e, Installed: s.updater.Installed(e)})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"arch":    s.updater.Arch,
		"mirrors": s.updater.Mirrors,
		"engines": out,
	})
}

// handleUpdaterVersions returns the latest + recent release tags via mirrors.
func (s *Server) handleUpdaterVersions(w http.ResponseWriter, r *http.Request) {
	e := updater.EngineByID(r.PathValue("id"))
	if e == nil {
		writeErr(w, http.StatusNotFound, "unknown engine")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	if e.SourceOnly {
		resp := map[string]any{"source_only": true, "note": e.Note, "installed": s.updater.Installed(*e).Version}
		if tags, err := s.updater.Tags(ctx, *e, 15); err != nil {
			resp["error"] = err.Error()
		} else {
			resp["versions"] = tags
			if len(tags) > 0 {
				resp["latest"] = tags[0]
			}
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	rels, err := s.updater.List(ctx, *e, 15)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "could not reach the release source (try a mirror in config): "+err.Error())
		return
	}
	tags := make([]string, 0, len(rels))
	for _, rl := range rels {
		tags = append(tags, rl.Tag)
	}
	latest := ""
	if len(tags) > 0 {
		latest = tags[0]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"latest":    latest,
		"versions":  tags,
		"installed": s.updater.Installed(*e).Version,
	})
}

// handleUpdaterInstall downloads + installs a chosen version (the side-effecting action).
func (s *Server) handleUpdaterInstall(w http.ResponseWriter, r *http.Request) {
	e := updater.EngineByID(r.PathValue("id"))
	if e == nil {
		writeErr(w, http.StatusNotFound, "unknown engine")
		return
	}
	var body struct {
		Version string `json:"version"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Version == "" {
		writeErr(w, http.StatusBadRequest, "version required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()
	tag, err := s.updater.Install(ctx, *e, body.Version)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	// If we updated the running primary core, reload it.
	reloaded := false
	if e.ID == "sing-box" && s.singbox != nil && s.singbox.Running() {
		if err := s.singbox.Reload(); err == nil {
			reloaded = true
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"installed": tag, "engine": e.ID, "reloaded": reloaded})
}

// --- WakeRoute self-update ---------------------------------------------------

// handleSelfStatus reports WakeRoute's own version and whether a newer release exists.
func (s *Server) handleSelfStatus(w http.ResponseWriter, r *http.Request) {
	c := s.config()
	repo := c.Updater.SelfRepo
	if repo == "" {
		repo = updater.DefaultSelfRepo
	}
	out := map[string]any{
		"current":     version.Version,
		"repo":        repo,
		"arch":        s.updater.Arch,
		"auto_update": c.Updater.AutoUpdate,
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rel, err := s.updater.SelfLatest(ctx, repo)
	if err != nil {
		out["error"] = err.Error()
	} else {
		out["latest"] = rel.Tag
		out["update_available"] = updater.Newer(version.Version, rel.Tag)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSelfUpdate downloads + swaps the WakeRoute binary for the latest (or a given)
// release, then restarts the service so the new binary takes over. The swap is guarded
// by a sanity-run of the new binary (see updater.SelfUpdate); the old binary is kept at
// <exe>.bak for manual rollback.
func (s *Server) handleSelfUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Version string `json:"version"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	c := s.config()
	repo := c.Updater.SelfRepo
	if repo == "" {
		repo = updater.DefaultSelfRepo
	}
	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()
	tag := body.Version
	if tag == "" {
		rel, err := s.updater.SelfLatest(ctx, repo)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err.Error())
			return
		}
		tag = rel.Tag
	}
	exe, err := os.Executable()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot locate the running binary: "+err.Error())
		return
	}
	installed, err := s.updater.SelfUpdate(ctx, repo, tag, exe)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	cmd := restartCommand()
	if cmd == nil {
		writeJSON(w, http.StatusOK, map[string]any{"installed": installed, "restarting": false,
			"note": "binary swapped; restart the service manually to apply (or this is the demo)"})
		return
	}
	if err := cmd.Start(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"installed": installed, "restarting": false, "note": "restart failed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"installed": installed, "restarting": true})
}

// handleSelfAuto toggles background auto-update of WakeRoute itself.
func (s *Server) handleSelfAuto(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	s.cfgMu.Lock()
	s.cfg.Updater.AutoUpdate = body.Enabled
	err := s.cfg.Save()
	s.cfgMu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"auto_update": body.Enabled})
}

// AutoUpdateLoop periodically (daily) checks for a newer WakeRoute release and, when
// Updater.AutoUpdate is enabled, installs it and restarts. Off by default; the first
// check is delayed so a crash-looping bad release can't hammer updates on boot.
func (s *Server) AutoUpdateLoop(ctx context.Context) {
	t := time.NewTimer(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			t.Reset(24 * time.Hour)
		}
		c := s.config()
		if !c.Updater.AutoUpdate {
			continue
		}
		repo := c.Updater.SelfRepo
		if repo == "" {
			repo = updater.DefaultSelfRepo
		}
		cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		rel, err := s.updater.SelfLatest(cctx, repo)
		if err != nil || !updater.Newer(version.Version, rel.Tag) {
			cancel()
			continue
		}
		exe, err := os.Executable()
		if err != nil {
			cancel()
			continue
		}
		installed, err := s.updater.SelfUpdate(cctx, repo, rel.Tag, exe)
		cancel()
		if err != nil {
			log.Printf("auto-update: %v", err)
			continue
		}
		log.Printf("auto-update: installed wakeroute %s, restarting", installed)
		if cmd := restartCommand(); cmd != nil {
			_ = cmd.Start()
		}
		return // being restarted
	}
}
