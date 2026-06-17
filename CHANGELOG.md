# Changelog

All notable changes to WakeRoute are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

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
