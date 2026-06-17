// Package config loads and persists the wakeroute daemon configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"wakeroute/internal/atomicfile"
)

// Ports is the reserved port block wakeroute owns. Each is user-editable so the
// daemon can dodge conflicts with the router OS, keen-pbr and https-dns-proxy
// (see docs/CONFLICTS.md #1).
type Ports struct {
	UI    int `json:"ui"`    // web panel
	Clash int `json:"clash"` // sing-box Clash API (external_controller)
	DNS   int `json:"dns"`   // local DNS
	Mixed int `json:"mixed"` // local mixed (socks+http) inbound
}

// Clash describes how to reach sing-box's Clash API.
type Clash struct {
	Controller string `json:"controller"` // host:port, e.g. 127.0.0.1:9090
	Secret     string `json:"secret"`     // bearer secret, may be empty
}

// SingBox locates the sing-box binary and its generated config.
type SingBox struct {
	Bin    string `json:"bin"`    // path to the sing-box executable
	Config string `json:"config"` // path to the generated config.json
}

// Updater configures engine-binary version management (see internal/updater).
type Updater struct {
	Arch    string   `json:"arch"`    // override; empty = autodetect from the running binary
	Mirrors []string `json:"mirrors"` // GitHub URL prefixes tried in order; "" = direct
	// SelfRepo is the GitHub "owner/name" WakeRoute updates ITSELF from (its own
	// CI release builds). Empty → the built-in default (updater.DefaultSelfRepo).
	SelfRepo string `json:"self_repo,omitempty"`
	// AutoUpdate, when true, lets WakeRoute auto-install a newer release of ITSELF
	// (checked daily in the background) and restart. Default off — opt-in.
	AutoUpdate bool `json:"auto_update,omitempty"`
}

// FailSafe configures Apply rollback behaviour (see internal/failsafe).
type FailSafe struct {
	Target     string `json:"target"`      // connectivity-check host (default 1.1.1.1)
	AutoReboot bool   `json:"auto_reboot"` // allow auto-reboot as the last resort (opt-in)
}

// Watchdog configures crash-restart supervision (see internal/watchdog).
type Watchdog struct {
	// NotifyURL, when set, receives a POST {"text":"…"} on each crash-restart
	// (e.g. a WGBot webhook). Empty = alerts off (the default).
	NotifyURL string `json:"notify_url"`
}

// Subscription configures the client subscription endpoint.
type Subscription struct {
	// Token guards /api/sub/<token>. Auto-generated on first use if empty.
	Token string `json:"token"`
}

// Config is the full daemon configuration, persisted as JSON.
type Config struct {
	Listen      string `json:"listen"`                    // UI bind address, e.g. :8088
	DataDir     string `json:"data_dir"`                  // runtime state directory
	Demo        bool   `json:"demo"`                      // synthesize traffic when sing-box is absent
	Gateway     bool   `json:"gateway"`                   // TUN gateway mode: capture LAN traffic via a tun inbound + auto_route (vs the default mixed-proxy-only parallel mode)
	GatewayMTU  int    `json:"gateway_mtu,omitempty"`     // TUN device MTU when gateway=true (0 → 1500). Lower it (e.g. 1280) if large packets stall over a tunnel exit.
	GatewayAddr string `json:"gateway_address,omitempty"` // TUN host address/CIDR when gateway=true ("" → 172.19.0.1/30); not the LAN subnet (auto_route excludes it).
	// RoutingMode selects the routing architecture (see docs/ARCHITECTURE_NATIVE_FIRST.md):
	//   "" (default) → derive from Gateway (back-compat); "tun" → all traffic via the sing-box TUN;
	//   "hybrid" → kernel PBR for WG/AmneziaWG/WAN/block + carve-outs, sing-box only for obfuscation
	//   protocols (Reality/Hysteria2/TUIC/…); "mixed" → no TUN, sing-box mixed-proxy only.
	RoutingMode  string       `json:"routing_mode,omitempty"`
	Ports        Ports        `json:"ports"`
	Clash        Clash        `json:"clash"`
	SingBox      SingBox      `json:"singbox"`
	Updater      Updater      `json:"updater"`
	FailSafe     FailSafe     `json:"failsafe"`
	Watchdog     Watchdog     `json:"watchdog"`
	Subscription Subscription `json:"subscription"`

	path string // source file, used by Save()
}

// Default returns a Config with router-friendly defaults.
func Default() *Config {
	return &Config{
		Listen:   ":8088",
		DataDir:  "/opt/var/wakeroute",
		Demo:     false,
		Ports:    Ports{UI: 8088, Clash: 9090, DNS: 5353, Mixed: 7890},
		Clash:    Clash{Controller: "127.0.0.1:9090", Secret: ""},
		SingBox:  SingBox{Bin: "/opt/sbin/sing-box", Config: "/opt/etc/wakeroute/singbox.json"},
		Updater:  Updater{Arch: "", Mirrors: []string{"", "https://ghproxy.net/", "https://mirror.ghproxy.com/"}},
		FailSafe: FailSafe{Target: "1.1.1.1", AutoReboot: false},
	}
}

// Load reads config from path, creating it with defaults if it does not exist.
func Load(path string) (*Config, error) {
	c := Default()
	c.path = path

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := c.Save(); err != nil {
			return nil, fmt.Errorf("write default config: %w", err)
		}
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.path = path
	return c, nil
}

// Save writes the config atomically + durably (temp file, fsync, rename), mode 0600.
func (c *Config) Save() error {
	if c.path == "" {
		return errors.New("config has no path")
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(c.path, data, 0o600)
}
