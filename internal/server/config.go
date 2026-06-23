package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"wakeroute/internal/config"
)

// config returns a value snapshot of the live config taken under cfgMu. ALL
// reads of s.cfg outside the write path must go through this, so they can't race
// handlePutConfig/subToken mutating the shared struct (a torn read of a string/
// slice header can crash). The copy is cheap and read-only for the caller.
func (s *Server) config() config.Config {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	return *s.cfg
}

// handleGetConfig returns the current daemon configuration (LAN tool — secrets
// are returned so the user can see/edit them).
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.config())
}

// handlePutConfig validates and saves a new configuration. Most changes take
// effect on the next daemon restart (restart_needed).
func (s *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var in config.Config
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if in.Listen == "" {
		writeErr(w, http.StatusBadRequest, "listen address is required")
		return
	}
	if err := validatePorts(in.Ports); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Listen and Ports.UI both encode the panel's bind port; keep them from diverging so editing
	// the UI port in Settings actually MOVES the bind (the documented escape from the lighttpd
	// :8088 conflict) instead of silently no-opping. Ports.UI is authoritative for the port; Listen
	// keeps its host/interface. Reject a malformed Listen here rather than letting ListenAndServe
	// fail (log.Fatal) at the next restart.
	host, _, splitErr := net.SplitHostPort(in.Listen)
	if splitErr != nil {
		writeErr(w, http.StatusBadRequest, `listen must be host:port (e.g. ":8088" or "192.168.1.1:8088")`)
		return
	}
	in.Listen = net.JoinHostPort(host, strconv.Itoa(in.Ports.UI))

	// Apply exported fields to the live config (the unexported file path on
	// s.cfg is preserved), then persist — under the config lock so we don't race
	// subToken()/handleGetConfig() on the shared struct or the config.json.tmp file.
	s.cfgMu.Lock()
	s.cfg.Listen = in.Listen
	s.cfg.DataDir = in.DataDir
	s.cfg.Demo = in.Demo
	s.cfg.Gateway = in.Gateway
	s.cfg.GatewayMTU = in.GatewayMTU
	s.cfg.GatewayAddr = in.GatewayAddr
	s.cfg.RoutingMode = in.RoutingMode
	s.cfg.Ports = in.Ports
	s.cfg.Clash = in.Clash
	s.cfg.SingBox = in.SingBox
	s.cfg.Updater = in.Updater
	s.cfg.FailSafe = in.FailSafe
	s.cfg.Watchdog = in.Watchdog
	s.cfg.AllowedHosts = in.AllowedHosts
	err := s.cfg.Save()
	s.cfgMu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true, "restart_needed": true})
}

func validatePorts(p config.Ports) error {
	ports := []struct {
		name string
		v    int
	}{{"ui", p.UI}, {"clash", p.Clash}, {"dns", p.DNS}, {"mixed", p.Mixed}}
	seen := map[int]string{}
	for _, pp := range ports {
		if pp.v < 1 || pp.v > 65535 {
			return fmt.Errorf("port %s=%d is out of range (1-65535)", pp.name, pp.v)
		}
		if other, ok := seen[pp.v]; ok {
			return fmt.Errorf("ports %s and %s cannot both be %d", pp.name, other, pp.v)
		}
		seen[pp.v] = pp.name
	}
	return nil
}
