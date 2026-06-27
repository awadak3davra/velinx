// Package model is the protocol-agnostic configuration model. The UI and
// importers speak this; generators translate it into core-native configs
// (e.g. sing-box JSON). See docs/ARCHITECTURE.md §3.
package model

// Engine identifies which core/binary realizes an endpoint.
type Engine string

const (
	EngineSingBox   Engine = "singbox"
	EngineAmneziaWG Engine = "amneziawg"
	EngineOpenVPN   Engine = "openvpn"
	EngineXray      Engine = "xray"
	EngineMihomo    Engine = "mihomo"
	EngineOlcRTC    Engine = "olcrtc"
	// EngineExternal routes through an existing OS interface that WakeRoute does
	// NOT manage (e.g. a UCI/netifd-brought-up awg0/awg1). It becomes a sing-box
	// `direct` outbound bound to params["interface"]; no tunnel is created.
	EngineExternal Engine = "external"
	// EngineNfqws is the DPI-desync engine (nfqws2): a long-running process on a
	// netfilter NFQUEUE that mangles handshake packets in place so the DPI can't
	// block them. Unlike every other engine it provides NO egress — traffic stays on
	// the DIRECT path; the `desync` routing target installs the NFQUEUE divert
	// separately. See docs/ARCHITECTURE_DESYNC.md.
	EngineNfqws Engine = "nfqws"
)

// Protocol is the wire protocol of an endpoint.
type Protocol string

const (
	ProtoVLESS       Protocol = "vless"
	ProtoVMess       Protocol = "vmess"
	ProtoTrojan      Protocol = "trojan"
	ProtoShadowsocks Protocol = "shadowsocks"
	ProtoHysteria2   Protocol = "hysteria2"
	ProtoTUIC        Protocol = "tuic"
	ProtoWireGuard   Protocol = "wireguard"
	ProtoAmneziaWG   Protocol = "amneziawg"
	ProtoOlcRTC      Protocol = "olcrtc"
	ProtoSOCKS       Protocol = "socks"
	ProtoHTTP        Protocol = "http"
)

// TLS holds transport security settings (plain TLS, Reality, uTLS fingerprint).
type TLS struct {
	Enabled     bool     `json:"enabled,omitempty"`
	Type        string   `json:"type,omitempty"` // "tls" | "reality"
	SNI         string   `json:"sni,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Insecure    bool     `json:"insecure,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"` // uTLS, e.g. "chrome"
	// Reality
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
}

// Transport is the stream transport when not raw TCP (ws/grpc/http/httpupgrade).
type Transport struct {
	Type        string            `json:"type,omitempty"` // "" (tcp) | ws | grpc | http | httpupgrade
	Path        string            `json:"path,omitempty"`
	Host        string            `json:"host,omitempty"`
	ServiceName string            `json:"service_name,omitempty"` // grpc
	Headers     map[string]string `json:"headers,omitempty"`
}

// Health configures an availability check (used by endpoints and groups).
type Health struct {
	URL       string `json:"url,omitempty"`       // default http://cp.cloudflare.com/generate_204
	Interval  int    `json:"interval,omitempty"`  // seconds
	Tolerance int    `json:"tolerance,omitempty"` // ms
}

// Endpoint is one server traffic can be routed out through.
//
// Protocol-specific fields live in Params with these conventional keys:
//
//	vless:       uuid, flow
//	vmess:       uuid, alter_id, security
//	trojan:      password
//	shadowsocks: method, password
//	hysteria2:   password, obfs, obfs_password, up_mbps, down_mbps
//	tuic:        uuid, password, congestion_control, udp_relay_mode
//	wireguard:   private_key, peer_public_key, pre_shared_key, local_address, reserved
//	amneziawg:   (wireguard keys) + jc, jmin, jmax, s1, s2, h1, h2, h3, h4
type Endpoint struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Engine    Engine         `json:"engine"`
	Protocol  Protocol       `json:"protocol"`
	Server    string         `json:"server"`
	Port      int            `json:"port"`
	Params    map[string]any `json:"params,omitempty"`
	Transport *Transport     `json:"transport,omitempty"`
	TLS       *TLS           `json:"tls,omitempty"`
	Health    *Health        `json:"health,omitempty"`
	Enabled   bool           `json:"enabled"`
	// MTU is the WireGuard/AmneziaWG link MTU. 0 = unset (omitted from output,
	// engine default applies). Protocol-agnostic field; only meaningful for the
	// WG-family engines, but harmless when unset for any protocol.
	MTU int `json:"mtu,omitempty"`
	// PersistentKeepalive is the WireGuard/AmneziaWG keepalive interval in seconds.
	// 0 = unset (omitted; no keepalive). Useful behind NAT to keep the tunnel warm.
	PersistentKeepalive int `json:"persistent_keepalive,omitempty"`
}

// GroupType selects how a group chooses among its members.
type GroupType string

const (
	GroupURLTest  GroupType = "urltest"  // automatic, lowest latency working member
	GroupSelector GroupType = "selector" // manual selection
	GroupFallback GroupType = "fallback" // strict ordered preference
)

// Group is a failover/selection set over endpoints (or nested groups).
type Group struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Type    GroupType `json:"type"`
	Members []string  `json:"members"` // endpoint or group IDs, in preference order
	Test    *Health   `json:"test,omitempty"`
	// KillSwitch, when true, DROPs traffic that selects this group while ALL of
	// its members are down — instead of leaking to the WAN. Default false keeps
	// the current behavior (WAN fallback). Opt-in, so an unset/zero value is a
	// byte-identical no-op for existing profiles.
	KillSwitch bool `json:"kill_switch,omitempty"`
}

// Rule routes matching traffic to a target outbound.
type Rule struct {
	ID           string   `json:"id"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	GeoSite      []string `json:"geosite,omitempty"`
	GeoIP        []string `json:"geoip,omitempty"`
	IPCIDR       []string `json:"ip_cidr,omitempty"`
	Port         []int    `json:"port,omitempty"`
	Default      bool     `json:"default,omitempty"` // catch-all (route final)
	Outbound     string   `json:"outbound"`          // endpoint id | group id | "direct" | "block"
}

// RoutingList steers traffic matching a domain/IP set to a chosen outbound. The
// set comes from a rule-set URL (a curated preset or a custom .srs/.json) and/or
// manually entered domains/IPs. It becomes a sing-box route.rule_set (remote for
// a URL — fetched through DownloadVia — or inline for Manual entries) plus a
// route.rule that points the set at Outbound. This is the "Routing" page model.
type RoutingList struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Source       string   `json:"source,omitempty"`        // rule-set URL (.srs or .json); empty for manual-only
	Format       string   `json:"format,omitempty"`        // "binary" (.srs) | "source" (.json) | "" (infer from URL)
	Manual       []string `json:"manual,omitempty"`        // user-entered domains/IPs (inline rule-set)
	Outbound     string   `json:"outbound"`                // route matched traffic here: endpoint/group id | "direct" | "block"
	DownloadVia  string   `json:"download_via,omitempty"`  // outbound used to FETCH the URL (sing-box download_detour); "" = direct
	RefreshHours int      `json:"refresh_hours,omitempty"` // remote update_interval in hours; 0 = default (24h); also the CIDRSource auto-refresh cadence
	Enabled      bool     `json:"enabled"`
	// CIDRSource auto-populates this list's KERNEL CIDRs from a feed so a hybrid/fast
	// carve-out self-maintains instead of relying on a frozen Manual list. Scheme:
	// "https://…"/"http://…" → a plain-text CIDR feed; "asn:13238,47541,…" → RIPEstat
	// announced-prefixes per ASN. Distinct from Source (a sing-box domain rule_set, which
	// is inactive for LAN traffic in fast mode). Empty → no auto-refresh. Cadence reuses
	// RefreshHours. See docs/ARCHITECTURE_NATIVE_FIRST.md "RU / remote CIDR auto-refresh".
	CIDRSource string `json:"cidr_source,omitempty"`
	// CIDRCache is the last-good result of fetching CIDRSource (system-managed, persisted
	// so a fetch failure or restart keeps the carve-out). The kernel zone = Manual ∪
	// CIDRCache. Not user-edited; the refresh loop maintains it.
	CIDRCache []string `json:"cidr_cache,omitempty"`
}

// Profile is the whole user configuration.
type Profile struct {
	Endpoints    []Endpoint    `json:"endpoints"`
	Groups       []Group       `json:"groups"`
	Rules        []Rule        `json:"rules"`
	RoutingLists []RoutingList `json:"routing_lists,omitempty"`
}

// Builtin outbound tags that are always available.
const (
	OutboundDirect = "direct"
	OutboundBlock  = "block"
)

// EndpointByID returns the endpoint with the given id, or nil.
func (p *Profile) EndpointByID(id string) *Endpoint {
	for i := range p.Endpoints {
		if p.Endpoints[i].ID == id {
			return &p.Endpoints[i]
		}
	}
	return nil
}

// GroupByID returns the group with the given id, or nil.
func (p *Profile) GroupByID(id string) *Group {
	for i := range p.Groups {
		if p.Groups[i].ID == id {
			return &p.Groups[i]
		}
	}
	return nil
}

// RoutingListByID returns the routing list with the given id, or nil.
func (p *Profile) RoutingListByID(id string) *RoutingList {
	for i := range p.RoutingLists {
		if p.RoutingLists[i].ID == id {
			return &p.RoutingLists[i]
		}
	}
	return nil
}
