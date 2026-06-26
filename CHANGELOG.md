# Changelog

All notable changes to WakeRoute are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.3.1]

### Added
- **Settings backup & restore** — download the whole configuration as a file (secrets
  redacted by default, included only on request), restore it from a backup, or reset to
  defaults. Reset keeps your panel address, UI port, host allow-list and subscription
  token, so it can never lock you out.

### Changed
- **Settings page** — secret fields (Clash secret, watchdog webhook) are masked with a
  reveal toggle; client-side validation catches a bad listen/port/URL before saving; an
  unsaved-changes guard; and a clearer split between **Save** (store config) and **Apply**
  (regenerate routing), with a prompt to Apply after a routing-mode change.
- **Accurate "restart needed"** — saving reports a restart only when a startup-time field
  actually changed (bind / ports / proxy core / demo); hot fields apply without one.
- **Host allow-list is now hot** — a saved allow-list takes effect on the next request (no
  restart), and a too-narrow one is recoverable straight from the UI instead of via SSH.

### Fixed
- Config validation (`listen`/`clash` host:port, port range + uniqueness, routing-mode and
  offload enums, webhook URL) is enforced fail-closed by the API and warned-only at load.
- Persist the `offload` / `offload_devices` fast-mode settings the config API used to drop.

### Security
- Config export redacts the Clash secret, subscription token and watchdog webhook by default.

## [0.3.0]

### Added
- **Keenetic kernel-PBR backend** — native iptables + ipset policy routing for KeeneticOS
  routers (which ship no nftables), compiled from the same routing model as the OpenWrt path:
  `hash:net` ipsets, mangle fwmark marking, per-list `ip rule`/`ip route` tables, a 1-minute
  **load-independent failover cron** (RX-counter → WireGuard-handshake → ICMP liveness, with
  miss-hysteresis so a transient probe miss can't flap a list onto the WAN), a `netfilter.d`
  re-assert hook, and a scripted cutover/rollback that leaves the default path untouched.
- **Summarise live connections by destination IP** — each remote IP groups the ports it used,
  with per-port byte counts on hover.
- **DPI-desync engine (nfqws2)** — supervised as a long-running plugin (groundwork for a
  direct-path desync routing target).

### Fixed
- **Per-exit reachability test** now probes native kernel tunnels iface-bound
  (`curl --interface`) instead of only through the proxy core, so AmneziaWG/WireGuard exits
  report reachability correctly — with an **SSRF guard** (internal/metadata targets refused,
  the resolved public IP pinned to defeat DNS-rebind) and IPv4 preference so a v6-first host
  isn't a false negative.
- **Monitor mode** — detect an independently-running proxy core via the Clash API, so the UI
  no longer shows "core not running" while live traffic is flowing.
- **Kernel-plane forwarding correctness** — NAT forwarded LAN traffic on every failover-member
  tunnel; keep LAN/private-destination replies on the main routing table (so a re-marked reply
  can't loop back out the tunnel); and wire a symmetric IPv6 datapath so a marked v6 packet
  routes through the tunnel instead of leaking to the WAN.

## [0.2.0]

### Added
- **Diagnostics health battery** — a one-click *"Run all checks"* that fans out across the
  core, internet, tunnels, exit IP, clock, IPv6, DNS and system resources, then shows a
  verdict-first banner with expandable per-check rows (cause, fix and deep links) and a
  copyable Markdown report.
  - **Exit-IP geolocation** — the active exit's country (flag), ISP and AS number.
  - **Blocked-sites reachability** — probes representative censored hosts through every exit
    so you can see at a glance whether a tunnel still carries them.
  - **DNS-over-HTTPS health** — confirms encrypted DNS resolvers actually answer
    (DNS rcode checked, not just HTTP 200), plus **IPv6-leak** and **router clock-skew**
    checks the browser can't run itself.
  - **Per-row re-check** and a **support-grade report** with default-on redaction of public
    IPs, keys and tokens.
  - **Sortable reachability matrix** (Exit · Status · Latency) with a mobile card layout.
- **Redesigned Dashboard** — status hero, live RAM/CPU/uptime strip, per-tunnel latency
  sparklines, grouped health with severity, a live connections table with top talkers, and
  the public exit IP.
- **Kernel-native policy routing** — an optional `hybrid` mode that programs per-destination
  carve-outs directly with `nft` + `ip rule` fwmark tables, alongside the sing-box TUN gateway.
- **Self-update** — WakeRoute can check for and install its own releases, with opt-in auto-update.
- **Mobile-responsive panel** and additional UI translations.

### Changed
- Import/validation hardening across transports (ws/gRPC/httpupgrade), TLS/Reality/uTLS,
  TUIC ALPN, IPv6 hosts and WireGuard keys.
- Backend health probes now run concurrently.

### Fixed
- Numerous generator and config round-trip fixes.

### Security
- **Same-origin (CSRF) guard** — state-changing requests carrying a cross-origin
  `Origin`/`Referer` are rejected, so another site open in a LAN browser can't drive
  Apply / Rollback / Restart through the panel.
- **Anti-clickjacking + hardening headers** on every response — `X-Frame-Options: DENY`
  and a `frame-ancestors 'none'` CSP, plus `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: no-referrer`.
- **Content-Security-Policy `script-src 'self'`** — neutralises injected/reflected scripts
  (the bundled UI loads only same-origin scripts).
- **Request-body size cap** — bounds memory so one oversized request can't OOM a low-RAM
  router and take the proxy core down with it.
- **SSRF guard** on subscription fetches — a user-supplied URL can't be turned into a
  request against the router's own control API, other LAN hosts or cloud metadata.
- **Optional Host allow-list** (`allowed_hosts`, Settings → Security) — pin which Host
  headers the panel serves, as a DNS-rebinding defense; empty (default) allows any.
- See the **Security** section of the README for the trust model. The panel is
  unauthenticated and LAN-trust by design — do not expose `:8088` to the internet without
  fronting it with authentication + TLS.

## [0.1.0] — Initial public release

First public release of WakeRoute: a self-hosted web panel for configuring any VPN/proxy
protocol on Entware/OpenWrt routers, with failover, health checks and live traffic graphs.

### Added
- Go daemon with the dark/light web UI embedded in a single static binary.
- **Connections** — paste-link / subscription / `.conf` import for VLESS-Reality, Hysteria2,
  TUIC, AmneziaWG, WireGuard, Shadowsocks, Trojan, VMess and more, including olcRTC.
- **Failover groups** built on sing-box `urltest`, with a watchdog that autostarts and
  crash-restarts the core with backoff.
- **Selective routing** — list-based, per-destination routing through any tunnel, namespaced
  away from an existing policy-routing setup via a dedicated fwmark + table.
- **Dashboard** with a live traffic graph and per-tunnel health, **Diagnostics** (per-tunnel
  speedtests), **Updater**, **Init Server** (SSH-provision a VPS into an endpoint) and **Settings**.
- Per-Apply fail-safe rollback and a researched error knowledgebase.
- CI: `go vet` + `go test -race`, cross-builds for `mipsle`, `mips`, `arm` v7, `arm64`, `amd64`,
  and tagged GitHub Releases with per-arch Entware + OpenWrt tarballs and `SHA256SUMS.txt`.
