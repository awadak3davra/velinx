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
	//   "hybrid" → capture-all TUN + kernel PBR for IP/CIDR carve-outs (general traffic still
	//   transits the userspace TUN — domain carve-outs work but throughput is CPU-bound);
	//   "fast" → like hybrid BUT with NO capture-all TUN: general traffic stays on the kernel
	//   fast-path (no userspace tax → near-line-rate), only IP/CIDR carve-outs are kernel-PBR'd
	//   (TG-calls/VoWiFi etc.); domain carve-outs are INACTIVE for LAN traffic in this mode
	//   (no TUN to sniff them) — a Phase-2 DNS→nftset bridge would restore them. flow_offloading
	//   is left as-is in Phase 1 (Phase 1b enables HW offload with carve-out-mark exclusion);
	//   "mixed" → no TUN, sing-box mixed-proxy only (no kernel PBR).
	RoutingMode string `json:"routing_mode,omitempty"`
	// Offload enables Phase-1b kernel flow-offload for GENERAL traffic in "fast" mode (a
	// no-op in other modes): "" / "off" (default) → none; "sw" → software flowtable; "hw"
	// → also hardware PPE (`flags offload`). Carve-out flows (TG-calls/VoWiFi/RU — any
	// owned fwmark) are EXCLUDED so their per-packet PBR, and the UDP calls it carries,
	// keep working (see docs/ARCHITECTURE_NATIVE_FIRST.md "Phase 1a/1b"). Deploy-gated —
	// validate TG/VoWiFi survive before relying on it.
	Offload string `json:"offload,omitempty"`
	// OffloadDevices are the netdevs flow-offload attaches to (the WAN uplink + LAN bridge,
	// e.g. ["wan","br-lan"]); awg* tunnels are intentionally absent (carve-out traffic must
	// not be offloaded). Empty → offload is skipped (a future auto-probe will fill these
	// from the default route + br-lan).
	OffloadDevices []string     `json:"offload_devices,omitempty"`
	Ports          Ports        `json:"ports"`
	Clash          Clash        `json:"clash"`
	SingBox        SingBox      `json:"singbox"`
	Updater        Updater      `json:"updater"`
	FailSafe       FailSafe     `json:"failsafe"`
	Watchdog       Watchdog     `json:"watchdog"`
	Subscription   Subscription `json:"subscription"`
	// AllowedHosts, when non-empty, restricts which Host header values the panel
	// will serve (host-only, port-stripped, case-insensitive) — a DNS-rebinding
	// defense (see docs/SECURITY.md). EMPTY (the default) allows any Host, so this
	// changes nothing until an operator opts in by listing the names/IPs they use
	// to reach the panel, e.g. ["192.168.2.1","10.0.0.30","router.lan"]. Misconfig
	// locks out the UI (recoverable: clear it in config.json + restart).
	AllowedHosts []string `json:"allowed_hosts,omitempty"`

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
