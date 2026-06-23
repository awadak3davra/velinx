package initserver

import (
	"fmt"
	"strings"
)

// ServerBinary identifies a binary wakeroute can version-check (and update) on a
// PROVISIONED server over SSH. Unlike the router's local engine Updater, these run on
// the remote VPS: sing-box is the VLESS-Reality endpoint core (GitHub-managed, so a
// latest-release comparison is meaningful), while AmneziaWG is an apt package (managed
// by the distro — we report its version and offer an apt upgrade, no GitHub compare).
type ServerBinary struct {
	Key     string `json:"key"`     // singbox | awg
	Name    string `json:"name"`    // display name
	Managed string `json:"managed"` // github | apt
	Repo    string `json:"repo,omitempty"`
	Marker  string `json:"-"` // WR_INSTALLED_<MARKER> the probe prints
}

// ServerBinaries is the set of remote binaries the Init Server panel manages. Kept
// small + matched to what provisioning actually installs (Reality=sing-box, AWG=apt).
var ServerBinaries = []ServerBinary{
	{Key: "singbox", Name: "sing-box", Managed: "github", Repo: "SagerNet/sing-box", Marker: "SINGBOX"},
	{Key: "awg", Name: "AmneziaWG", Managed: "apt", Marker: "AWG"},
}

// VersionCheckScript probes the installed version of each managed binary that is
// present on the server, plus the server arch. It is read-only (no apt/network/mutate)
// and prints WR_* markers the daemon parses. Absent binaries are simply skipped.
func VersionCheckScript() string {
	return `#!/bin/sh
echo "WR_ARCH=$(uname -m 2>/dev/null)"
if command -v sing-box >/dev/null 2>&1; then
  echo "WR_INSTALLED_SINGBOX=$(sing-box version 2>/dev/null | head -n1)"
fi
if dpkg-query -W -f='${Version}' amneziawg >/dev/null 2>&1; then
  echo "WR_INSTALLED_AWG=$(dpkg-query -W -f='${Version}' amneziawg 2>/dev/null)"
elif command -v awg >/dev/null 2>&1; then
  echo "WR_INSTALLED_AWG=$(awg --version 2>/dev/null | head -n1)"
fi
echo "WR_VERCHECK_DONE=1"
`
}

// ExtractVersions parses the WR_INSTALLED_<MARKER> + WR_ARCH markers into a map keyed
// by ServerBinary.Key plus an "arch" entry (raw `uname -m`). Missing binaries are
// absent from the map (the probe only prints markers for binaries it found).
func ExtractVersions(output string) map[string]string {
	out := map[string]string{}
	for _, ln := range strings.Split(output, "\n") {
		ln = strings.TrimSpace(ln)
		if v, ok := strings.CutPrefix(ln, "WR_ARCH="); ok {
			out["arch"] = strings.TrimSpace(v)
			continue
		}
		for _, b := range ServerBinaries {
			if v, ok := strings.CutPrefix(ln, "WR_INSTALLED_"+b.Marker+"="); ok {
				out[b.Key] = strings.TrimSpace(v)
			}
		}
	}
	return out
}

// VerCheckRan reports whether the probe script reached the end (so an empty result is
// "nothing installed" rather than "the script never ran / SSH died mid-way").
func VerCheckRan(output string) bool { return strings.Contains(output, "WR_VERCHECK_DONE=1") }

// UpdateSingBoxScript replaces sing-box on the server with the given x.y.z release
// from the official GitHub download (HTTPS, upstream). The script resolves the server
// arch itself, backs up the current binary, swaps atomically, restarts the service,
// and prints WR_UPDATE_OK=<new version> on success. DESTRUCTIVE (brief endpoint drop).
func UpdateSingBoxScript(version string) string {
	return fmt.Sprintf(`#!/bin/sh
set -e
log(){ echo "[wakeroute-update] $*"; }
VER=%q
[ -n "$VER" ] || { echo "WR_UPDATE_ERR=no version"; exit 1; }
case "$(uname -m)" in
  x86_64|amd64) A=amd64;;
  aarch64|arm64) A=arm64;;
  armv7l|armv7*) A=armv7;;
  *) echo "WR_UPDATE_ERR=unsupported arch $(uname -m)"; exit 1;;
esac
URL="https://github.com/SagerNet/sing-box/releases/download/v${VER}/sing-box-${VER}-linux-${A}.tar.gz"
TMP=$(mktemp -d); cd "$TMP"
log "downloading $URL"
curl -fsSL "$URL" -o sb.tgz || { echo "WR_UPDATE_ERR=download failed"; rm -rf "$TMP"; exit 1; }
tar -xzf sb.tgz
BIN=$(find . -type f -name sing-box | head -n1)
[ -n "$BIN" ] || { echo "WR_UPDATE_ERR=binary not in archive"; rm -rf "$TMP"; exit 1; }
DST=$(command -v sing-box || echo /usr/local/bin/sing-box)
cp -f "$DST" "$DST.wakeroute.bak" 2>/dev/null || true
install -m 0755 "$BIN" "$DST"
( systemctl restart sing-box 2>/dev/null || service sing-box restart 2>/dev/null ) || true
sleep 1
echo "WR_UPDATE_OK=$("$DST" version 2>/dev/null | head -n1)"
rm -rf "$TMP"
log "done"
`, version)
}

// UpdateAWGScript upgrades the apt-managed AmneziaWG packages and reports the new
// version. apt decides the target; nothing is pinned.
const UpdateAWGScript = `#!/bin/sh
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --only-upgrade amneziawg amneziawg-tools 2>/dev/null || apt-get install -y --only-upgrade amneziawg-dkms amneziawg-tools
echo "WR_UPDATE_OK=$(dpkg-query -W -f='${Version}' amneziawg 2>/dev/null)"
`

// UpdateConfirmed reports whether an update script signalled success, and returns the
// new version it printed (after WR_UPDATE_OK=).
func UpdateConfirmed(output string) (ok bool, newVersion string) {
	for _, ln := range strings.Split(output, "\n") {
		if v, found := strings.CutPrefix(strings.TrimSpace(ln), "WR_UPDATE_OK="); found {
			return true, strings.TrimSpace(v)
		}
	}
	return false, ""
}

// UpdateScriptFor returns the install script for a server binary key (or "", false).
func UpdateScriptFor(key, version string) (string, bool) {
	switch key {
	case "singbox":
		return UpdateSingBoxScript(version), true
	case "awg":
		return UpdateAWGScript, true
	default:
		return "", false
	}
}
