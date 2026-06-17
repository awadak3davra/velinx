package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"wakeroute/internal/kb"
)

type lineMatch struct {
	Line    string     `json:"line"`
	Error   bool       `json:"error"`
	Entries []kb.Entry `json:"entries,omitempty"`
}

func analyze(lines []string) []lineMatch {
	out := make([]lineMatch, 0, len(lines))
	for _, ln := range lines {
		lm := lineMatch{Line: ln, Error: kb.IsErrorLine(ln)}
		if m := kb.Match(ln); len(m) > 0 {
			lm.Entries = m
		}
		out = append(out, lm)
	}
	return out
}

func respondDiagnostics(w http.ResponseWriter, lines []string) {
	analyzed := analyze(lines)
	seen := map[string]bool{}
	var found []kb.Entry
	for _, lm := range analyzed {
		for _, e := range lm.Entries {
			if !seen[e.ID] {
				seen[e.ID] = true
				found = append(found, e)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"lines": analyzed,
		"found": found,
		"count": len(lines),
	})
}

// handleDiagnostics analyzes the live sing-box log buffer.
func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	var lines []string
	if s.singbox != nil {
		lines = s.singbox.LogLines()
	}
	respondDiagnostics(w, lines)
}

// handleDiagnosticsAnalyze analyzes pasted log text (works anywhere, incl. logs
// copied from the router or another device).
func (s *Server) handleDiagnosticsAnalyze(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	var lines []string
	for _, ln := range strings.Split(body.Text, "\n") {
		if ln = strings.TrimRight(ln, "\r"); strings.TrimSpace(ln) != "" {
			lines = append(lines, ln)
		}
	}
	respondDiagnostics(w, lines)
}

// handleKB returns the whole error knowledgebase for browsing.
func (s *Server) handleKB(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, kb.Entries())
}
