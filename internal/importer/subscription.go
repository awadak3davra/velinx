package importer

import (
	"strconv"
	"strings"

	"wakeroute/internal/model"
)

// ParseSubscription parses a subscription blob into endpoints, returning a
// per-failure error list. It accepts either a base64-encoded body (the common
// "v2ray subscription" format) or plain text, with one share link per line.
func ParseSubscription(text string) ([]model.Endpoint, []string) {
	text = strings.TrimSpace(text)

	// A base64 subscription has no scheme markers until decoded.
	if !strings.Contains(text, "://") && !strings.Contains(text, "[Interface]") {
		if dec := decodeB64(text); dec != "" {
			text = dec
		}
	}

	var eps []model.Endpoint
	var errs []string
	// genID is protocol+server+port, so two transport/TLS variants of the same
	// host (a common subscription shape) produce the same ID and would silently
	// overwrite each other on bulk import. Keep batch IDs distinct by suffixing
	// collisions; single endpoints keep their natural slug.
	seen := map[string]bool{}
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e, err := Parse(line)
		if err != nil {
			errs = append(errs, line[:min(len(line), 40)]+": "+err.Error())
			continue
		}
		e.ID = uniqueID(e.ID, seen)
		eps = append(eps, *e)
	}
	return eps, errs
}

// uniqueID returns id if unused, else id-2 / id-3 / … so each parsed endpoint in
// a batch keeps a distinct ID. Records the chosen id in seen.
func uniqueID(id string, seen map[string]bool) string {
	if id != "" && !seen[id] {
		seen[id] = true
		return id
	}
	for n := 2; ; n++ {
		cand := id + "-" + strconv.Itoa(n)
		if !seen[cand] {
			seen[cand] = true
			return cand
		}
	}
}
