# WakeRoute (`wakeroute`)

A self-hosted web panel that lets you configure **any** VPN/proxy protocol on your Entware
or OpenWrt router, with one-click **failover**, automatic **health checks**, and live **traffic
graphs**. It runs as a service on its **own port** (`:8088`) and never touches the router's
native VPN config.

Think: a polished router web UI, but on top of a universal proxy core (sing-box), so you
can run VLESS-Reality, Hysteria2, TUIC, AmneziaWG, WireGuard, Shadowsocks, Trojan, and more from one
clean interface, with real failsafe instead of hand-written scripts.

## Why

Stock router firmware gives you WireGuard/IPsec/OpenVPN, but not the modern censorship-resistant stack
(VLESS/Reality, Hysteria2, TUIC, AmneziaWG) and not an easy way to chain them with automatic failover.
Today that means hand-edited sing-box/xray JSON, policy-routing scripts and SSH. `wakeroute` turns all of
that into a UI that looks like it belongs on the router.

## Features

- **Connections** — paste-link / subscription / `.conf` import for any protocol, including
  **AmneziaWG** and **olcRTC**.
- **Failover groups** — first-class objects built on sing-box `urltest` plus a daemon watchdog that
  autostarts sing-box and crash-restarts it with backoff.
- **Dashboard** — live traffic graph and per-tunnel health.
- **Selective routing** — list-based, per-destination routing through any tunnel; coexists with an
  existing policy-routing setup via a dedicated fwmark + routing table.
- **Init Server** — SSH-provision a VPS into a VPN endpoint.
- **Diagnostics, Updater, Settings** — per-tunnel speedtests, per-Apply fail-safe rollback, and a
  researched error knowledgebase.
- Light/dark theme. Single static Go binary with the UI embedded — no runtime deps beyond the proxy cores.

## Install (short version)

**Easiest — grab a prebuilt tarball** from the [Releases](../../releases) page (built in CI for every
router SoC). Each arch ships in **two flavours**: `wakeroute-<ver>-<arch>.tar.gz` for **Entware**
(busybox sysvinit under `/opt`) and `wakeroute-<ver>-<arch>-openwrt.tar.gz` for **OpenWrt** (native
`procd` service, `/usr/sbin` + `/etc/wakeroute`). Match the arch to your router's `uname -m`:
`mips` → `mipsle` (little-endian, most MT7621) or `mips` (big-endian), `armv7l` → `arm`,
`aarch64` → `arm64`, `x86_64` → `amd64`.

```sh
# Entware — router has /opt + SSH:
cd /tmp && curl -fsSLO <release-url>/wakeroute-<ver>-mipsle.tar.gz
mkdir wakeroute && tar -xzf wakeroute-*.tar.gz -C wakeroute && cd wakeroute && sh ./install.sh
```

```sh
# OpenWrt (procd) — busybox has no scp, so stream the -openwrt tarball over ssh:
ssh root@192.168.1.1 "cat > /tmp/wakeroute.tgz" < wakeroute-<ver>-arm64-openwrt.tar.gz
ssh root@192.168.1.1 "mkdir -p /tmp/wr && tar -xzf /tmp/wakeroute.tgz -C /tmp/wr && cd /tmp/wr && sh ./install.sh"
```

Then open `http://192.168.1.1:8088` (substitute your router's LAN address).

**Or build it yourself:**

```powershell
./build.ps1                                    # cross-compile + package all arches (Windows)
```
```sh
make package                                   # same, on a Unix build host
```

## CI / Releases

[`.github/workflows/build.yml`](.github/workflows/build.yml) runs on every push/PR: `go vet` + `go test -race`,
then cross-compiles for all router SoCs (`mipsle`, `mips`, `arm` v7, `arm64`, `amd64`) as downloadable
artifacts. Pushing a `v*` tag (`git tag v0.2.0 && git push --tags`) additionally publishes a GitHub Release
with the per-arch tarballs — both the **Entware** (`…-<arch>.tar.gz`) and **OpenWrt**
(`…-<arch>-openwrt.tar.gz`) flavours — plus `SHA256SUMS.txt`.

## Design in one breath

```
Browser ──http:8088──▶ wakeroute-daemon (Go, single binary, UI embedded)
                          ├─ writes config ─▶ sing-box (primary core: routing, DNS, urltest failover)
                          ├─ Clash API :9090 ◀─ live traffic / latency for graphs
                          └─ engine plugins ─▶ amneziawg-go (awg-quick), olcrtc (only for gaps)
```

One universal core does ~90% of protocols; dedicated binaries fill the gaps (AmneziaWG is the big one,
olcRTC is the anti-whitelist WebRTC tunnel). Failover is a first-class object built on sing-box `urltest`
+ a daemon watchdog that autostarts sing-box and crash-restarts it with backoff. Routing coexists with an
existing policy-routing setup via a dedicated fwmark + table.

## Non-goals (for now)

- Not a replacement for stock router firmware. It sits beside it.
- Not a server/hosting panel in v1 — client-out first (router connects out through chosen protocols).
- Not reimplementing protocols — it orchestrates proven cores.

## License

[MIT](LICENSE). Built on MIT/Apache cores (sing-box, mihomo, xray, amneziawg).
