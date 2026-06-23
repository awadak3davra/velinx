// Package initserver generates an idempotent installer script that stands up a
// light VPN server (AmneziaWG and/or sing-box VLESS-Reality) on a fresh
// Debian/Ubuntu VPS, and (optionally, on-device) runs it over SSH and captures
// the client config the script prints. Credentials are never stored or logged.
package initserver

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Protocol ids the UI sends.
const (
	ProtoAmneziaWG = "amneziawg"
	ProtoReality   = "vless-reality"
)

const scriptHeader = `#!/bin/sh
# WakeRoute — server provisioning (idempotent). Run as root on Debian/Ubuntu.
set -e
log() { echo "[wakeroute-init] $*"; }
# Guard: WireGuard/AmneziaWG need kernel modules — OpenVZ/LXC containers can't load
# them, so fail early with a clear message instead of a confusing runtime error.
VIRT="$(systemd-detect-virt 2>/dev/null || echo unknown)"
case "$VIRT" in openvz|lxc) log "WARNING: virtualization '$VIRT' may not support kernel WireGuard — AmneziaWG could fail";; esac
PUBLIC_IP="${WR_PUBLIC_IP:-$(curl -fsS https://api.ipify.org 2>/dev/null || ip -4 route get 1 2>/dev/null | awk '{print $7; exit}')}"
WANIF="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
log "public ip: ${PUBLIC_IP:-unknown}, wan iface: ${WANIF:-eth0}, virt: ${VIRT}"
export DEBIAN_FRONTEND=noninteractive
# Performance tuning (idempotent): BBR + fair queueing, and larger UDP buffers so
# QUIC-based protocols aren't receive-starved. Best-effort; failures are non-fatal.
cat > /etc/sysctl.d/99-wakeroute.conf <<'SYSCTL'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
SYSCTL
sysctl --system >/dev/null 2>&1 || true
`

const scriptAmneziaWG = `
# ---- AmneziaWG ----
log "installing AmneziaWG..."
if ! command -v awg >/dev/null 2>&1; then
  apt-get update -y || true
  apt-get install -y software-properties-common curl iptables || true
  add-apt-repository -y ppa:amnezia/ppa || log "PPA add failed (blocked in RU?) — AWG may need a source build"
  apt-get update -y || true
  apt-get install -y amneziawg amneziawg-tools || apt-get install -y amneziawg-dkms amneziawg-tools || log "amneziawg install failed"
fi
mkdir -p /etc/amnezia/amneziawg && cd /etc/amnezia/amneziawg
[ -f server.key ] || awg genkey > server.key
awg pubkey < server.key > server.pub
[ -f client.key ] || awg genkey > client.key
awg pubkey < client.key > client.pub
SK=$(cat server.key); SP=$(cat server.pub); CK=$(cat client.key); CP=$(cat client.pub)
JC=4; JMIN=40; JMAX=70; S1=0; S2=0
# H1-H4 are AmneziaWG's header-magic values. They MUST be randomized (not the
# WireGuard defaults 1/2/3/4) or the handshake message types stay unobfuscated and
# DPI fingerprints it as plain WireGuard — defeating AmneziaWG's purpose. Persist
# them (like the keys) so a re-run reuses the same values and existing clients keep working.
HF=/etc/amnezia/amneziawg/wr-hparams
[ -f "$HF" ] || awk 'BEGIN{srand();for(i=1;i<=4;i++)printf "H%d=%d\n",i,int(rand()*2000000000)+5}' > "$HF"
. "$HF"
cat > awg0.conf <<EOF
[Interface]
PrivateKey = $SK
Address = 10.13.13.1/24
ListenPort = 51820
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1
S2 = $S2
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4
[Peer]
PublicKey = $CP
AllowedIPs = 10.13.13.2/32
EOF
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
iptables -t nat -C POSTROUTING -s 10.13.13.0/24 -o "${WANIF:-eth0}" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.13.13.0/24 -o "${WANIF:-eth0}" -j MASQUERADE
awg-quick down awg0 2>/dev/null || true
awg-quick up awg0 || log "awg-quick up failed (install issue?)"
systemctl enable awg-quick@awg0 2>/dev/null || true
AWG_CONF="[Interface]
PrivateKey = $CK
Address = 10.13.13.2/32
DNS = 1.1.1.1
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1
S2 = $S2
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4
[Peer]
PublicKey = $SP
Endpoint = $PUBLIC_IP:51820
AllowedIPs = 0.0.0.0/0"
echo "WR_PROTO=amneziawg"
echo "WR_CLIENT_CONFIG_B64=$(printf '%s' "$AWG_CONF" | base64 -w0 2>/dev/null || printf '%s' "$AWG_CONF" | base64 | tr -d '\n')"
`

const scriptReality = `
# ---- sing-box VLESS-Reality ----
log "installing sing-box (VLESS-Reality)..."
if ! command -v sing-box >/dev/null 2>&1; then
  apt-get install -y curl tar >/dev/null 2>&1 || true
  A=$(dpkg --print-architecture 2>/dev/null || echo amd64)
  case "$A" in amd64) SB=amd64;; arm64) SB=arm64;; armhf) SB=armv7;; *) SB=amd64;; esac
  VER=$(curl -fsS https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep -o '"tag_name":[^,]*' | head -1 | sed 's/.*"v\{0,1\}\([0-9][^"]*\)".*/\1/')
  curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${VER}/sing-box-${VER}-linux-${SB}.tar.gz" -o /tmp/sb.tgz
  tar -xzf /tmp/sb.tgz -C /tmp
  install -m755 "/tmp/sing-box-${VER}-linux-${SB}/sing-box" /usr/local/bin/sing-box
fi
mkdir -p /etc/sing-box
# Persist the Reality identity so a re-run REUSES it. Regenerating the uuid /
# keypair / short_id on every provision would silently invalidate every
# previously-issued client. Mirrors the AmneziaWG key guard above.
SBD=/etc/sing-box
[ -f "$SBD/wr-reality-uuid" ] || sing-box generate uuid > "$SBD/wr-reality-uuid"
[ -f "$SBD/wr-reality.key" ] || sing-box generate reality-keypair > "$SBD/wr-reality.key"
[ -f "$SBD/wr-reality-sid" ] || sing-box generate rand --hex 8 > "$SBD/wr-reality-sid"
chmod 600 "$SBD/wr-reality-uuid" "$SBD/wr-reality.key" "$SBD/wr-reality-sid" 2>/dev/null || true
UUID=$(cat "$SBD/wr-reality-uuid")
PRIV=$(awk '/PrivateKey/{print $2}' "$SBD/wr-reality.key")
PUB=$(awk '/PublicKey/{print $2}' "$SBD/wr-reality.key")
SID=$(cat "$SBD/wr-reality-sid")
SNI=www.microsoft.com
cat > /etc/sing-box/config.json <<EOF
{"inbounds":[{"type":"vless","listen":"::","listen_port":443,"users":[{"uuid":"$UUID","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"$SNI","reality":{"enabled":true,"handshake":{"server":"$SNI","server_port":443},"private_key":"$PRIV","short_id":["$SID"]}}}],"outbounds":[{"type":"direct"}]}
EOF
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box
After=network.target
[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload 2>/dev/null || true
systemctl enable --now sing-box 2>/dev/null || true
echo "WR_PROTO=vless-reality"
echo "WR_CLIENT_CONFIG=vless://$UUID@$PUBLIC_IP:443?security=reality&sni=$SNI&fp=chrome&pbk=$PUB&sid=$SID&flow=xtls-rprx-vision&type=tcp#wakeroute-server"
`

// BuildScript assembles the installer for the chosen protocols. publicHost (the
// server's reachable address) overrides the script's auto-detected public IP.
//
// SECURITY PRECONDITION: publicHost MUST already be validated to a bare host/IP
// (callers use netdiag.ValidTarget, which rejects shell metacharacters, spaces, and a
// leading '-'). The %q below is Go-quoting, NOT shell-quoting — inside the emitted
// double-quoted `PUBLIC_IP="…"`, a `$(…)`/backtick in publicHost would still be expanded
// by the remote shell. ValidTarget's charset (alnum . _ : - [ ]) contains no such
// characters, so %q is safe here; do NOT call BuildScript with unvalidated input, or
// shell-quote publicHost first.
func BuildScript(protocols []string, publicHost string) string {
	var b strings.Builder
	b.WriteString(scriptHeader)
	if publicHost != "" {
		// prepend an override (placed after header sets the default; re-set it).
		b.WriteString(fmt.Sprintf("PUBLIC_IP=%q\n", publicHost))
	}
	for _, p := range protocols {
		if o := optionByID(p); o != nil && o.Script != "" {
			b.WriteString(o.Script)
		}
	}
	b.WriteString("\nlog \"done\"\n")
	return b.String()
}

// Creds are per-request SSH credentials. They are never stored or logged.
type Creds struct {
	Host     string
	Port     int
	User     string
	Password string
	Key      string
}

// Provision tries to run the script on the server over SSH. ran=false means the
// auto path isn't available (no ssh/sshpass, or no creds) — the caller should
// fall back to manual instructions. Output is the captured stdout/stderr.
func Provision(ctx context.Context, c Creds, script string) (output string, ran bool, err error) {
	sshPath, e := exec.LookPath("ssh")
	if e != nil {
		return "", false, nil
	}
	if c.Port == 0 {
		c.Port = 22
	}
	base := []string{
		"-p", strconv.Itoa(c.Port),
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=15",
		c.User + "@" + c.Host, "sh -s",
	}

	var cmd *exec.Cmd
	switch {
	case c.Key != "":
		kf, e := os.CreateTemp("", "wrkey-*")
		if e != nil {
			return "", false, e
		}
		defer os.Remove(kf.Name())
		_ = os.Chmod(kf.Name(), 0o600)
		_, _ = kf.WriteString(c.Key)
		_ = kf.Close()
		cmd = exec.CommandContext(ctx, sshPath, append([]string{"-i", kf.Name()}, base...)...)
	case c.Password != "":
		sp, e := exec.LookPath("sshpass")
		if e != nil {
			return "", false, nil // no sshpass -> manual fallback
		}
		cmd = exec.CommandContext(ctx, sp, append([]string{"-p", c.Password, sshPath}, base...)...)
	default:
		return "", false, nil
	}

	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return string(out), true, err
}

// ExtractConfig pulls the first client config the script printed (a vless:// link,
// or a base64-encoded AmneziaWG .conf).
func ExtractConfig(output string) string {
	if cs := ExtractConfigs(output); len(cs) > 0 {
		return cs[0]
	}
	return ""
}

// ExtractConfigs pulls every client config the script printed, in order — one per
// installed protocol (multi-protocol provisioning prints several).
func ExtractConfigs(output string) []string {
	out := make([]string, 0)
	for _, tc := range ExtractTagged(output) {
		out = append(out, tc.Config)
	}
	return out
}

// TaggedConfig is a client config paired with the protocol that produced it, so
// the orchestration never has to guess by position.
type TaggedConfig struct {
	Proto  string
	Config string
}

// ExtractTagged pulls every client config the installer printed, each attributed
// to its protocol via the WR_PROTO marker the script prints just above it. If a
// marker is missing it falls back to detecting the protocol from the payload.
func ExtractTagged(output string) []TaggedConfig {
	var out []TaggedConfig
	proto := ""
	add := func(cfg string) {
		p := proto
		if p == "" {
			p = DetectProto(cfg)
		}
		out = append(out, TaggedConfig{Proto: p, Config: cfg})
		proto = "" // consume the marker
	}
	for _, ln := range strings.Split(output, "\n") {
		ln = strings.TrimSpace(ln)
		if v, ok := strings.CutPrefix(ln, "WR_PROTO="); ok {
			proto = strings.TrimSpace(v)
			continue
		}
		if v, ok := strings.CutPrefix(ln, "WR_CLIENT_CONFIG_B64="); ok {
			if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v)); err == nil {
				add(string(b))
			}
			continue
		}
		if v, ok := strings.CutPrefix(ln, "WR_CLIENT_CONFIG="); ok {
			add(v)
		}
	}
	return out
}

// OneLiner is the manual command the user can run themselves (creds inline are
// theirs; wakeroute doesn't keep them).
func OneLiner(c Creds) string {
	port := c.Port
	if port == 0 {
		port = 22
	}
	if c.Key != "" {
		return fmt.Sprintf("ssh -i <your-key> -p %d %s@%s 'sh -s' < wakeroute-install.sh", port, c.User, c.Host)
	}
	return fmt.Sprintf("ssh -p %d %s@%s 'sh -s' < wakeroute-install.sh   # (or: sshpass -p '<pass>' ssh ...)", port, c.User, c.Host)
}
