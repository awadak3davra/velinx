package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"wakeroute/internal/exporter"
)

// handleEndpointExport returns one endpoint's share link or .conf so the UI can
// show a QR / copy / download it.
func (s *Server) handleEndpointExport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, e := range s.store.Profile().Endpoints {
		if e.ID == id {
			res, ok := exporter.Export(e)
			if !ok {
				writeErr(w, http.StatusUnprocessableEntity, "this protocol has no shareable link or .conf")
				return
			}
			writeJSON(w, http.StatusOK, res)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "endpoint not found")
}

// handleQR renders arbitrary text as a QR PNG. POST (not GET) so the payload —
// which may be a secret config — never lands in a URL or the access log.
func (s *Server) handleQR(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Text string `json:"text"`
		Size int    `json:"size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Text == "" {
		writeErr(w, http.StatusBadRequest, "text is required")
		return
	}
	size := b.Size
	if size < 128 || size > 1024 {
		size = 320
	}
	png, err := qrcode.Encode(b.Text, qrcode.Medium, size)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not encode QR: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// handleSubInfo returns the subscription token + path (creating the token once).
func (s *Server) handleSubInfo(w http.ResponseWriter, r *http.Request) {
	tok := s.subToken()
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "path": "/api/sub/" + tok})
}

// handleSubServe serves the client subscription: base64 of newline-joined share
// links for every enabled, exportable endpoint (the universal v2ray sub format
// understood by v2rayN/NG, Nekobox, Shadowrocket, v2box, …). Phones/apps poll
// this, so a failover swap or key rotation propagates without re-sharing a QR.
func (s *Server) handleSubServe(w http.ResponseWriter, r *http.Request) {
	// Constant-time compare: this token is the only gate on the user's full set of
	// share links (UUIDs/passwords), so don't leak it through a byte-by-byte `!=`
	// timing side-channel. The "" guard stops an unset token from ever matching.
	tok := s.subToken()
	if tok == "" || subtle.ConstantTimeCompare([]byte(r.PathValue("token")), []byte(tok)) != 1 {
		writeErr(w, http.StatusForbidden, "invalid subscription token")
		return
	}
	var links []string
	for _, e := range s.store.Profile().Endpoints {
		if !e.Enabled {
			continue
		}
		if link, ok := exporter.ShareLink(e); ok {
			links = append(links, link)
		}
	}
	body := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Profile-Update-Interval", "12") // hours; hint for clients
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(body))
}

// subToken returns the subscription token, generating + persisting one on first use.
func (s *Server) subToken() string {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if s.cfg.Subscription.Token == "" {
		buf := make([]byte, 12)
		if _, err := rand.Read(buf); err != nil {
			return "" // never happens on a healthy host
		}
		s.cfg.Subscription.Token = hex.EncodeToString(buf)
		_ = s.cfg.Save()
	}
	return s.cfg.Subscription.Token
}
