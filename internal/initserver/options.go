package initserver

import "strings"

// Option is a provisionable protocol: presentation metadata for the UI plus the
// install-script fragment and a payload detector. This is the single registration
// point — adding a new server-side VPN means appending one Option here (script +
// detector), with no edits to BuildScript, the extractor, or the orchestration.
type Option struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Summary     string   `json:"summary"`
	Details     []string `json:"details"`
	Port        int      `json:"port"`
	Transport   string   `json:"transport"`
	Recommended bool     `json:"recommended"`

	// Script is the shell fragment appended to the installer for this protocol.
	// It MUST print `WR_PROTO=<id>` immediately before its WR_CLIENT_CONFIG line so
	// the client config can be attributed to the right protocol (never by index).
	Script string `json:"-"`
	// Detect recognises this protocol's client config payload (fallback when the
	// WR_PROTO marker is missing, e.g. a hand-run script).
	Detect func(config string) bool `json:"-"`
}

// catalog is the registry of provisionable protocols.
var catalog = []Option{
	{
		ID:      ProtoAmneziaWG,
		Name:    "AmneziaWG",
		Summary: "Censorship-resistant WireGuard with a junk-padded handshake.",
		Details: []string{
			"WireGuard fork that pads/obfuscates the handshake (Jc/Jmin/Jmax/S1/S2/H1-H4) to defeat DPI and TSPU.",
			"Best choice where plain WireGuard is throttled or whitelisted (e.g. RU).",
			"Server listens on UDP :51820; wakeroute generates the matching client automatically.",
		},
		Port:        51820,
		Transport:   "udp",
		Recommended: true,
		Script:      scriptAmneziaWG,
		Detect:      func(c string) bool { return strings.Contains(c, "[Interface]") },
	},
	{
		ID:      ProtoReality,
		Name:    "VLESS-Reality",
		Summary: "TLS-camouflaged proxy that borrows a real site's certificate.",
		Details: []string{
			"sing-box VLESS with Reality: the TLS handshake impersonates a real HTTPS site (www.microsoft.com), so it looks like ordinary web traffic.",
			"Runs over TCP :443 with xtls-rprx-vision flow — strong against active probing.",
			"No domain or certificate of your own required.",
		},
		Port:        443,
		Transport:   "tcp",
		Recommended: true,
		Script:      scriptReality,
		Detect:      func(c string) bool { return strings.HasPrefix(strings.TrimSpace(c), "vless://") },
	},
}

// Options returns the provisionable-protocol catalog.
func Options() []Option { return catalog }

// optionByID returns the catalog entry for id, or nil.
func optionByID(id string) *Option {
	for i := range catalog {
		if catalog[i].ID == id {
			return &catalog[i]
		}
	}
	return nil
}

// ValidOption reports whether id is a known provisionable protocol.
func ValidOption(id string) bool { return optionByID(id) != nil }

// OptionName returns the display name for a protocol id (falls back to the id).
func OptionName(id string) string {
	if o := optionByID(id); o != nil {
		return o.Name
	}
	return id
}

// DetectProto identifies the protocol of a client config payload via the catalog
// detectors (used when a config has no WR_PROTO marker).
func DetectProto(config string) string {
	for i := range catalog {
		if catalog[i].Detect != nil && catalog[i].Detect(config) {
			return catalog[i].ID
		}
	}
	return ""
}
