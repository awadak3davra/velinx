// Package kb is a curated knowledgebase of common VPN/proxy engine errors. Each
// entry maps a log-line signature (regexp) to a plain-language explanation, a
// fix, and source links (GitHub issues / forums / official docs) the entry was
// distilled from. Match() annotates a log line with any entries that apply.
//
// Entries were researched from real reports; see each Sources list.
package kb

import "regexp"

// Entry is one known error and its explanation.
type Entry struct {
	ID          string   `json:"id"`
	Engine      string   `json:"engine"`
	Title       string   `json:"title"`
	Explanation string   `json:"explanation"`
	Fix         string   `json:"fix"`
	Sources     []string `json:"sources"`
	Pattern     string   `json:"-"` // regexp source (case-insensitive)
	re          *regexp.Regexp
}

var entries = []Entry{
	// --- sing-box ---
	{
		ID: "sb-tun-file-exists", Engine: "sing-box", Pattern: `configure tun interface:.*file exists`,
		Title:       "TUN interface already exists",
		Explanation: "sing-box could not create its TUN device because one with the same name already exists — usually a previous instance is still running or left a stale interface behind.",
		Fix:         "Stop any other sing-box/wakeroute instance, delete the stale TUN (e.g. `ip link del tun0`), or reboot. Make sure only one router owns the TUN.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/3411"},
	},
	{
		ID: "sb-tun-invalid-arg", Engine: "sing-box", Pattern: `configure tun interface:.*invalid argument`,
		Title:       "TUN interface rejected (invalid argument)",
		Explanation: "The kernel rejected the TUN configuration — typically the tun module isn't loaded or an option is unsupported on this kernel/platform.",
		Fix:         "Ensure `/dev/net/tun` exists and `modprobe tun` succeeds. On Entware routers where TUN may be limited, use TPROXY/redirect mode instead of TUN.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/3734"},
	},
	{
		ID: "sb-wg-route-exists", Engine: "sing-box", Pattern: `start outbound/wireguard.*add route.*file exists`,
		Title:       "WireGuard outbound route conflict",
		Explanation: "sing-box failed to add a route for the WireGuard outbound because that route already exists — often seen after an upgrade or when another tool owns the route.",
		Fix:         "Remove the conflicting route (`ip route`), or disable the duplicate WireGuard interface, then restart sing-box.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/3738"},
	},
	{
		ID: "sb-fatal-start", Engine: "sing-box", Pattern: `FATAL.*start service`,
		Title:       "sing-box failed to start",
		Explanation: "sing-box aborted at startup; the rest of the line names the failing inbound/outbound. Usually a config error or a port/interface already in use.",
		Fix:         "Validate with `sing-box check -c config.json` (wakeroute's Apply does this automatically), then fix the named section or free the busy port.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues"},
	},

	// --- xray / reality ---
	{
		ID: "xr-reality-invalid", Engine: "xray", Pattern: `REALITY:.*invalid connection|failed to read client hello`,
		Title:       "Reality rejected the connection",
		Explanation: "The Reality handshake failed verification. Top causes: client/server clocks differ by more than ~90s (Reality embeds a timestamp), a wrong public key (pbk) / short id (sid) / SNI, or a UUID that isn't registered on the server.",
		Fix:         "Sync the router clock (NTP). Re-check that the Reality public key, short id and SNI match the server, and that the UUID exists server-side.",
		Sources:     []string{"https://github.com/XTLS/Xray-core/issues/2728", "https://github.com/XTLS/Xray-core/issues/6048"},
	},
	{
		ID: "xr-deadline", Engine: "xray", Pattern: `context deadline exceeded`,
		Title:       "Connection / latency test timed out",
		Explanation: "A dial or URL-test exceeded its timeout — the endpoint is slow/unreachable, or the configured test timeout is too tight.",
		Fix:         "Increase the test timeout (e.g. 3000 → 6000 ms), confirm the server is reachable, and check for packet loss or DPI blocking on the path.",
		Sources:     []string{"https://github.com/throneproj/Throne/issues/1237", "https://proxypoland.com/blog/vless-connection-errors-troubleshooting"},
	},
	{
		ID: "xr-invalid-user", Engine: "xray", Pattern: `invalid user|not match any user`,
		Title:       "User / UUID not recognized",
		Explanation: "The server could not find the client's UUID/password in its user list — the credentials don't match.",
		Fix:         "Verify the UUID/password exactly matches a server-side user (watch for trailing spaces); re-import the share link to be sure.",
		Sources:     []string{"https://github.com/XTLS/Xray-core/issues/2359"},
	},

	// --- wireguard ---
	{
		ID: "wg-handshake-timeout", Engine: "wireguard", Pattern: `handshake did not complete`,
		Title:       "WireGuard handshake never completed",
		Explanation: "The client sent handshake initiations but got no reply. This is almost always an unreachable UDP port: a blocked/filtered network, wrong endpoint host:port, NAT, or a firewall dropping UDP. (A wrong peer public key is also silent.)",
		Fix:         "Confirm UDP reaches the server port (tcpdump on server / nc on client), verify endpoint+port+AllowedIPs and the peer public key. On censored networks WireGuard/UDP is often throttled — switch to AmneziaWG or a TCP/QUIC-camouflaged protocol.",
		Sources:     []string{"https://forum.opnsense.org/index.php?topic=30540.0", "https://discourse.nixos.org/t/wireguard-problems-handshake-did-not-complete/26237", "https://github.com/pivpn/pivpn/discussions/1532"},
	},
	{
		ID: "wg-unknown-peer", Engine: "wireguard", Pattern: `handshake initiation from unknown peer|invalid handshake initiation`,
		Title:       "Handshake from an unknown peer",
		Explanation: "The server received a handshake it couldn't match to any configured peer — the client's public key isn't on the server, or (AmneziaWG) the junk-packet params differ so the packet can't be parsed.",
		Fix:         "Add the client's public key to the server's peers. For AmneziaWG, make sure Jc/Jmin/Jmax/S1/S2/H1–H4 match the server exactly.",
		Sources:     []string{"https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/issues/132"},
	},

	// --- amneziawg ---
	{
		ID: "awg-junk-mismatch", Engine: "amneziawg", Pattern: `sending dummy junk|only \d+ bytes received`,
		Title:       "AmneziaWG junk-packet parameters mismatch",
		Explanation: "AmneziaWG's obfuscation params (Jc, Jmin, Jmax, S1, S2, H1–H4) must be IDENTICAL on both ends. When they differ the server can't parse the obfuscated handshake, so you see partial reads ('only 92 bytes received') or it never completes.",
		Fix:         "Copy the exact Jc/Jmin/Jmax/S1/S2/H1–H4 from the server. (A plain WireGuard server also works if only Jc/Jmin/Jmax are set and the rest are 0.) Re-import the .conf so wakeroute captures every param.",
		Sources:     []string{"https://github.com/amnezia-vpn/amnezia-client/issues/1823", "https://github.com/amnezia-vpn/amnezia-client/issues/1041", "https://github.com/shtorm-7/sing-box-extended/issues/18"},
	},

	// --- hysteria2 ---
	{
		ID: "hy-tls-verify", Engine: "hysteria2", Pattern: `tls: failed to verify certificate|x509: certificate signed by unknown|certificate is not (trusted|valid)`,
		Title:       "TLS certificate verification failed",
		Explanation: "The client rejected the server's TLS certificate — usually a self-signed cert that isn't trusted, an incomplete certificate chain, or an SNI/server_name that doesn't match the certificate.",
		Fix:         "If self-signed, enable 'insecure' or add the CA. Ensure the cert file contains the full chain (multiple BEGIN CERTIFICATE blocks). Set SNI/server_name to the certificate's domain.",
		Sources:     []string{"https://v2.hysteria.network/docs/advanced/Troubleshooting/"},
	},
	{
		ID: "hy-auth", Engine: "hysteria2", Pattern: `authentication failed|auth error|HTTP/\S+ 401`,
		Title:       "Hysteria2 authentication failed",
		Explanation: "The server rejected the client. Beyond a wrong password, Hysteria2 is picky: the ALPN must match the server and the server_name must match the certificate.",
		Fix:         "Check the password; ensure ALPN matches the server and server_name matches the certificate domain.",
		Sources:     []string{"https://v2.hysteria.network/docs/advanced/Troubleshooting/", "https://github.com/SagerNet/sing-box/issues/1844"},
	},

	// --- general (any engine) ---
	{
		ID: "gen-no-host", Engine: "any", Pattern: `no such host|name resolution failed|server misbehaving`,
		Title:       "DNS resolution failed",
		Explanation: "The engine couldn't resolve the server's hostname to an IP — DNS is failing, blocked, or hijacked.",
		Fix:         "Use an IP instead of a hostname, point wakeroute's DNS at a working DoH/DoT resolver, or check that DNS isn't being intercepted upstream.",
		Sources:     []string{"https://sing-box.sagernet.org/configuration/dns/"},
	},
	{
		ID: "gen-conn-refused", Engine: "any", Pattern: `connection refused`,
		Title:       "Connection refused",
		Explanation: "The server actively refused the connection — nothing is listening on that port, the port is wrong, or a firewall is sending RST.",
		Fix:         "Verify the server is running and the port is correct and open. For UDP/QUIC protocols, 'refused' can also mean the path is filtered.",
		Sources:     []string{"https://github.com/apernet/hysteria/issues/1207"},
	},
	{
		ID: "gen-io-timeout", Engine: "any", Pattern: `i/o timeout|dial tcp.*timeout`,
		Title:       "Connection timed out",
		Explanation: "The connection attempt timed out with no response — the server is unreachable or the path is being silently dropped (common with DPI blocking).",
		Fix:         "Check reachability and firewall. On censored networks try a camouflaged transport (Reality, WebSocket-over-CDN) or AmneziaWG.",
		Sources:     []string{"https://github.com/XTLS/Xray-core/issues/5332"},
	},
	{
		ID: "gen-clock", Engine: "any", Pattern: `certificate has expired|not valid before|tls: failed to verify certificate because of clock`,
		Title:       "System clock is wrong",
		Explanation: "TLS and Reality handshakes fail when the router clock is off (common after a power loss on devices without an RTC). Certificates look 'expired' or 'not yet valid'.",
		Fix:         "Sync the clock via NTP. wakeroute warns on large clock skew at startup.",
		Sources:     []string{"https://github.com/XTLS/Xray-core/issues/2728"},
	},
	{
		ID: "gen-permission", Engine: "any", Pattern: `permission denied|operation not permitted`,
		Title:       "Permission denied",
		Explanation: "The engine lacks privileges for the operation — creating a TUN device, binding a low port, or setting routes.",
		Fix:         "Run as root with CAP_NET_ADMIN and ensure `/dev/net/tun` is accessible. On Entware the service runs as root by default.",
		Sources:     []string{"https://github.com/SagerNet/sing-box/issues/3411"},
	},
}

var errLine = regexp.MustCompile(`(?i)\b(fatal|error|panic|failed|denied|refused|invalid|timeout|reject)\b`)

func init() {
	for i := range entries {
		entries[i].re = regexp.MustCompile(`(?i)` + entries[i].Pattern)
	}
}

// Entries returns the whole knowledgebase (for browsing in the UI).
func Entries() []Entry { return entries }

// Match returns every knowledgebase entry whose signature appears in the line.
func Match(line string) []Entry {
	var out []Entry
	for i := range entries {
		if entries[i].re.MatchString(line) {
			out = append(out, entries[i])
		}
	}
	return out
}

// IsErrorLine reports whether a log line looks like an error/warning.
func IsErrorLine(line string) bool { return errLine.MatchString(line) }
