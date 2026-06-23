// Package updater manages the engine binaries wakeroute orchestrates (sing-box, xray,
// mihomo, hysteria, dnscrypt-proxy, ...). It reports the installed version,
// queries upstream GitHub releases *through configurable mirrors* (GitHub is
// frequently blocked/throttled in censored regions), and installs a chosen
// version with SHA-256 verification when the release metadata provides it.
package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Engine describes a managed core binary and where to get it. Role tells the UI how
// the binary is actually used on THIS router so the Updater can foreground the ones
// the router runs and tuck the rest away:
//
//	core         — the sing-box proxy core
//	kernel-plugin— an engine driving a kernel iface (AmneziaWG)
//	socks-plugin — a long-running chained-SOCKS engine (olcRTC)
//	standalone   — a separate core wakeroute does NOT run here; sing-box covers the
//	               protocol natively, so it's catalog-only (install only for a manual
//	               setup). The UI files these under "Advanced".
type Engine struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Repo        string   `json:"repo"`     // GitHub "owner/name"
	BinName     string   `json:"bin_name"` // installed filename
	Role        string   `json:"role"`     // core | kernel-plugin | socks-plugin | standalone
	VersionArgs []string `json:"-"`        // args that print the version
	SourceOnly  bool     `json:"source_only"`
	Note        string   `json:"note,omitempty"`
}

// RouterUsed reports whether the router actually runs this engine (vs catalog-only).
func (e Engine) RouterUsed() bool { return e.Role != "" && e.Role != "standalone" }

// Engines is the registry of cores wakeroute can manage.
var Engines = []Engine{
	{ID: "sing-box", Name: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box", Role: "core", VersionArgs: []string{"version"}},
	{ID: "mihomo", Name: "Mihomo (Clash.Meta)", Repo: "MetaCubeX/mihomo", BinName: "mihomo", Role: "standalone", VersionArgs: []string{"-v"}},
	{ID: "xray", Name: "Xray-core", Repo: "XTLS/Xray-core", BinName: "xray", Role: "standalone", VersionArgs: []string{"version"}},
	{ID: "hysteria", Name: "Hysteria 2", Repo: "apernet/hysteria", BinName: "hysteria", Role: "standalone", VersionArgs: []string{"version"}},
	{ID: "dnscrypt-proxy", Name: "dnscrypt-proxy", Repo: "DNSCrypt/dnscrypt-proxy", BinName: "dnscrypt-proxy", Role: "standalone", VersionArgs: []string{"-version"}},
	{ID: "amneziawg-go", Name: "AmneziaWG (userspace)", Repo: "amnezia-vpn/amneziawg-go", BinName: "amneziawg-go", Role: "kernel-plugin", SourceOnly: true,
		Note: "No prebuilt releases; build from source on-device (the PPA is blocked in RU)."},
	{ID: "olcrtc", Name: "olcRTC (WebRTC tunnel)", Repo: "alexsvl/olcrtc", BinName: "olcrtc", Role: "socks-plugin", VersionArgs: []string{"version"},
		Note: "Anti-whitelist WebRTC-over-meet tunnel (Jitsi/Telemost/WbStream). Pulled from the alexsvl/olcrtc fork, which daily auto-syncs upstream openlibrecommunity/olcrtc and publishes prebuilt `olcrtc-linux-<arch>` binaries (upstream ships none; the WebRTC stack is too heavy to build on the router)."},
}

// EngineByID returns the engine with the given id, or nil.
func EngineByID(id string) *Engine {
	for i := range Engines {
		if Engines[i].ID == id {
			return &Engines[i]
		}
	}
	return nil
}

// Updater performs installed/latest/install operations.
type Updater struct {
	BinDir  string   // where binaries live, e.g. /opt/sbin
	Arch    string   // wakeroute arch token: amd64|arm64|arm|mipsle|mips
	Mirrors []string // URL prefixes tried in order; "" = direct
	hc      *http.Client
}

// New builds an Updater. An empty arch autodetects from the running binary
// (wakeroute is built for the router's arch, so runtime.GOARCH is correct on-device).
func New(binDir, arch string, mirrors []string) *Updater {
	if arch == "" {
		arch = runtime.GOARCH // mipsle/mips/arm/arm64/amd64 line up with our tokens
	}
	if len(mirrors) == 0 {
		mirrors = []string{""}
	}
	return &Updater{BinDir: binDir, Arch: arch, Mirrors: mirrors, hc: &http.Client{}}
}

// Installed reports the on-disk state of an engine.
type Installed struct {
	Present bool   `json:"present"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

var verRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

func parseVersion(s string) string { return verRe.FindString(s) }

// ParseVersion extracts the first x.y.z from s (exported for cross-package reuse, e.g.
// the Init Server panel formatting a remote `sing-box version` line). "" if none.
func ParseVersion(s string) string { return parseVersion(s) }

// Installed locates the binary (in BinDir or PATH) and runs its version command.
func (u *Updater) Installed(e Engine) Installed {
	path := filepath.Join(u.BinDir, e.BinName)
	if _, err := os.Stat(path); err != nil {
		p, err2 := exec.LookPath(e.BinName)
		if err2 != nil {
			return Installed{Present: false}
		}
		path = p
	}
	in := Installed{Present: true, Path: path}
	if len(e.VersionArgs) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, _ := exec.CommandContext(ctx, path, e.VersionArgs...).CombinedOutput()
		in.Version = parseVersion(string(out))
	}
	return in
}

// --- GitHub releases (mirror-aware) ---------------------------------------

type Release struct {
	Tag        string  `json:"tag_name"`
	Name       string  `json:"name"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"` // "sha256:..." on newer GitHub API
	Size   int64  `json:"size"`
}

// apiGet fetches a GitHub API path, trying each mirror prefix in turn.
func (u *Updater) apiGet(ctx context.Context, path string, v any) error {
	base := "https://api.github.com" + path
	var lastErr error
	for _, m := range u.Mirrors {
		url := base
		if m != "" {
			url = strings.TrimRight(m, "/") + "/" + base
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", "wakeroute-updater")
		resp, err := u.hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("%s: status %d", url, resp.StatusCode)
			continue
		}
		err = json.NewDecoder(resp.Body).Decode(v)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no mirrors configured")
	}
	return lastErr
}

// Latest returns the newest release.
func (u *Updater) Latest(ctx context.Context, e Engine) (Release, error) {
	var r Release
	err := u.apiGet(ctx, "/repos/"+e.Repo+"/releases/latest", &r)
	return r, err
}

// List returns up to limit recent releases (newest first).
func (u *Updater) List(ctx context.Context, e Engine, limit int) ([]Release, error) {
	if limit <= 0 {
		limit = 15
	}
	var rs []Release
	err := u.apiGet(ctx, fmt.Sprintf("/repos/%s/releases?per_page=%d", e.Repo, limit), &rs)
	return rs, err
}

type tag struct {
	Name string `json:"name"`
}

// Tags lists recent git tags — used for source-only engines (e.g. amneziawg-go)
// that publish no release assets but still tag versions.
func (u *Updater) Tags(ctx context.Context, e Engine, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 15
	}
	var ts []tag
	if err := u.apiGet(ctx, fmt.Sprintf("/repos/%s/tags?per_page=%d", e.Repo, limit), &ts); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out, nil
}

func (u *Updater) release(ctx context.Context, e Engine, tag string) (Release, error) {
	var r Release
	err := u.apiGet(ctx, "/repos/"+e.Repo+"/releases/tags/"+tag, &r)
	return r, err
}

// Install downloads the asset for u.Arch from the given release tag, verifies it
// (when a digest is provided), extracts the binary, and installs it atomically.
// Returns the installed tag.
// enoughSpaceFor reports whether `avail` free bytes can safely hold a freshly-staged
// binary of binSize (+ a same-size backup when withBackup) plus a small margin. When
// the free space is unknown (known=false, e.g. the off-Linux build) it returns true —
// never block on a stat we couldn't take. This guards the small router overlay
// (~60 MB) against a swap that runs out of space mid-write and leaves a partial binary.
func enoughSpaceFor(avail uint64, known bool, binSize int, withBackup bool) bool {
	if !known {
		return true
	}
	mult := uint64(1)
	if withBackup {
		mult = 2
	}
	return avail >= uint64(binSize)*mult+(2<<20) // + 2 MiB margin
}

func (u *Updater) Install(ctx context.Context, e Engine, tag string) (string, error) {
	if e.SourceOnly {
		return "", fmt.Errorf("%s has no prebuilt releases: %s", e.ID, e.Note)
	}
	rel, err := u.release(ctx, e, tag)
	if err != nil {
		return "", fmt.Errorf("lookup %s %s: %w", e.ID, tag, err)
	}
	asset := pickAsset(rel.Assets, u.Arch)
	if asset == nil {
		return "", fmt.Errorf("no %s asset for arch %q in %s %s", e.ID, u.Arch, e.ID, tag)
	}

	data, err := u.download(ctx, asset.URL)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", asset.Name, err)
	}
	if err := verifyDigest(data, asset.Digest); err != nil {
		return "", err
	}

	bin, err := extractBinary(asset.Name, data, e.BinName)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(u.BinDir, 0o755); err != nil {
		return "", err
	}
	if avail, ok := availBytes(u.BinDir); !enoughSpaceFor(avail, ok, len(bin), false) {
		return "", fmt.Errorf("not enough free space to install %s in %s (~%d MiB free) — free some space and retry", e.ID, u.BinDir, avail>>20)
	}
	dst := filepath.Join(u.BinDir, e.BinName)
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		_ = os.Remove(tmp) // don't leave a partial .new wasting the overlay
		return "", err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return rel.Tag, nil
}

func (u *Updater) download(ctx context.Context, rawURL string) ([]byte, error) {
	var lastErr error
	for _, m := range u.Mirrors {
		url := rawURL
		if m != "" {
			url = strings.TrimRight(m, "/") + "/" + rawURL
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "wakeroute-updater")
		resp, err := u.hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("%s: status %d", url, resp.StatusCode)
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 96<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return b, nil
	}
	return nil, lastErr
}

// --- asset matching + extraction ------------------------------------------

var archTokens = map[string][]string{
	"amd64": {"amd64", "x86_64", "linux-64", "linux_64"},
	"arm64": {"arm64", "aarch64"},
	// Bare "arm" matches a suffix-less "-linux-arm" asset (e.g. hysteria-linux-arm);
	// the arm64/aarch64 guard in matchAsset keeps it from matching 64-bit names.
	"arm":    {"armv7", "arm32", "armhf", "armv6", "armv5", "arm"},
	"mipsle": {"mipsle", "mips32le", "mipsel"},
	"mips":   {"mips"},
}

// pickAsset selects the best-matching release asset for arch. For most arches any
// match is equivalent (first wins); for 32-bit arm it prefers the most specific
// build — explicit armv7/armhf/arm32 > a bare "-linux-arm" > armv6 > armv5 — so an
// ARMv7 router never settles for a slower lowest-common-denominator binary when a
// better one is published.
func pickAsset(assets []Asset, arch string) *Asset {
	var best *Asset
	bestScore := -1
	for i := range assets {
		if !matchAsset(assets[i].Name, arch) {
			continue
		}
		if sc := assetScore(assets[i].Name, arch); sc > bestScore {
			bestScore = sc
			best = &assets[i]
		}
	}
	return best
}

func assetScore(name, arch string) int {
	if arch != "arm" {
		return 1 // any matching asset is equally good
	}
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "armv7"), strings.Contains(n, "armhf"), strings.Contains(n, "arm32"):
		return 3
	case strings.Contains(n, "armv6"):
		return 1
	case strings.Contains(n, "armv5"):
		return 0
	default:
		return 2 // bare "-linux-arm": ARMv7-safe baseline, better than v5/v6
	}
}

// matchAsset reports whether a release asset name is the Linux build for arch.
func matchAsset(name, arch string) bool {
	n := strings.ToLower(name)
	if !strings.Contains(n, "linux") {
		return false
	}
	for _, ext := range []string{".sha256", ".asc", ".sig", ".pem", ".dgst", ".txt", ".json"} {
		if strings.HasSuffix(n, ext) {
			return false
		}
	}
	// disambiguate near-collisions
	if arch == "arm" && (strings.Contains(n, "arm64") || strings.Contains(n, "aarch64")) {
		return false
	}
	if arch == "mips" && (strings.Contains(n, "mipsle") || strings.Contains(n, "mipsel") || strings.Contains(n, "mips32le") || strings.Contains(n, "mips64")) {
		return false
	}
	if arch == "amd64" && (strings.Contains(n, "arm") || strings.Contains(n, "mips")) {
		return false
	}
	for _, t := range archTokens[arch] {
		if strings.Contains(n, t) {
			return true
		}
	}
	return false
}

func extractBinary(assetName string, data []byte, binName string) ([]byte, error) {
	n := strings.ToLower(assetName)
	switch {
	case strings.HasSuffix(n, ".tar.gz") || strings.HasSuffix(n, ".tgz"):
		return fromTarGz(data, binName)
	case strings.HasSuffix(n, ".zip"):
		return fromZip(data, binName)
	case strings.HasSuffix(n, ".gz"):
		return fromGz(data)
	default:
		return data, nil // raw binary
	}
}

func fromGz(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, 256<<20))
}

func fromTarGz(data []byte, binName string) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && filepath.Base(h.Name) == binName {
			return io.ReadAll(io.LimitReader(tr, 256<<20))
		}
	}
	return nil, fmt.Errorf("binary %q not found in archive", binName)
}

func fromZip(data []byte, binName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) == binName {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, 256<<20))
		}
	}
	return nil, fmt.Errorf("binary %q not found in zip", binName)
}

func verifyDigest(data []byte, digest string) error {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 || parts[0] != "sha256" {
		return nil // no/unknown digest -> best-effort, skip
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), parts[1]) {
		return fmt.Errorf("sha256 mismatch: refusing to install")
	}
	return nil
}

// --- WakeRoute self-update -------------------------------------------------
//
// WakeRoute can update ITSELF (not just the engines it orchestrates) from its own
// CI release builds. The build workflow publishes per-arch tarballs named
// wakeroute-<ver>-<arch>.tar.gz and wakeroute-<ver>-<arch>-openwrt.tar.gz (the latter
// carries the procd init), each containing a wakeroute-<arch> binary. Those names have
// no "linux" token, so the engine asset matcher does not apply — selfAsset handles them.

// DefaultSelfRepo is where WakeRoute fetches its OWN release builds when the config
// leaves Updater.SelfRepo empty (the maintainer's fork, CI-built on every v* tag).
const DefaultSelfRepo = "alexsvl/wakeroute"

// selfAsset picks the WakeRoute release tarball for arch, preferring the OpenWrt
// package over the generic one. The leading "-"+arch avoids "arm" matching "arm64".
func selfAsset(assets []Asset, arch string) *Asset {
	var generic *Asset
	ow := "-" + arch + "-openwrt.tar.gz"
	gen := "-" + arch + ".tar.gz"
	for i := range assets {
		n := strings.ToLower(assets[i].Name)
		if !strings.HasPrefix(n, "wakeroute-") {
			continue
		}
		if strings.HasSuffix(n, ow) {
			return &assets[i] // openwrt package wins
		}
		if strings.HasSuffix(n, gen) {
			generic = &assets[i]
		}
	}
	return generic
}

// SelfLatest returns the newest WakeRoute release that carries a tarball for this
// arch (newest first; includes prereleases). repo "" → DefaultSelfRepo.
func (u *Updater) SelfLatest(ctx context.Context, repo string) (Release, error) {
	if repo == "" {
		repo = DefaultSelfRepo
	}
	rels, err := u.List(ctx, Engine{Repo: repo}, 10)
	if err != nil {
		return Release{}, err
	}
	for _, r := range rels {
		if selfAsset(r.Assets, u.Arch) != nil {
			return r, nil
		}
	}
	return Release{}, fmt.Errorf("no wakeroute %s asset in recent %s releases", u.Arch, repo)
}

// SelfUpdate downloads WakeRoute release `tag` from repo, verifies it, SANITY-RUNS the
// new binary (`<bin> -version` must print a version), backs up the current executable
// (exePath+".bak", reboot-safe rollback), then atomically swaps it in. The caller must
// restart the service to run it (the running process keeps the old inode until then).
// The sanity-run guarantees a corrupt/wrong-arch download never replaces a working daemon.
func (u *Updater) SelfUpdate(ctx context.Context, repo, tag, exePath string) (string, error) {
	if repo == "" {
		repo = DefaultSelfRepo
	}
	rel, err := u.release(ctx, Engine{Repo: repo}, tag)
	if err != nil {
		return "", fmt.Errorf("lookup wakeroute %s: %w", tag, err)
	}
	asset := selfAsset(rel.Assets, u.Arch)
	if asset == nil {
		return "", fmt.Errorf("no wakeroute %s asset in %s", u.Arch, tag)
	}
	data, err := u.download(ctx, asset.URL)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", asset.Name, err)
	}
	if err := verifyDigest(data, asset.Digest); err != nil {
		return "", err
	}
	bin, err := fromTarGz(data, "wakeroute-"+u.Arch)
	if err != nil {
		return "", fmt.Errorf("extract wakeroute-%s: %w", u.Arch, err)
	}
	dir := filepath.Dir(exePath)
	// Pre-flight: the staged binary AND the .bak backup both land on exePath's
	// filesystem. On the tiny router overlay a swap that runs out of space mid-write
	// would otherwise leave a truncated binary — abort cleanly instead, untouched.
	if avail, ok := availBytes(dir); !enoughSpaceFor(avail, ok, len(bin), true) {
		return "", fmt.Errorf("not enough free space to self-update safely on %s (~%d MiB free, need ~%d MiB for the new binary + backup) — free some space and retry", dir, avail>>20, (uint64(len(bin))*2+(2<<20))>>20)
	}
	staged := filepath.Join(dir, ".wakeroute.new")
	if err := os.WriteFile(staged, bin, 0o755); err != nil {
		_ = os.Remove(staged) // don't leave a partial .wakeroute.new wasting the overlay
		return "", err
	}
	// Sanity-run BEFORE swapping — refuse a binary that won't execute on this arch.
	out, runErr := exec.CommandContext(ctx, staged, "-version").CombinedOutput()
	if runErr != nil || parseVersion(string(out)) == "" {
		_ = os.Remove(staged)
		return "", fmt.Errorf("staged wakeroute binary failed its sanity check (corrupt or wrong arch): %v", runErr)
	}
	// Back up the current binary on the same filesystem, then atomically swap. A
	// half-written backup is worse than none (it poses as a valid rollback), so drop
	// it on a write error rather than leaving a truncated .bak behind.
	if cur, err := os.ReadFile(exePath); err == nil {
		if werr := os.WriteFile(exePath+".bak", cur, 0o755); werr != nil {
			_ = os.Remove(exePath + ".bak")
		}
	}
	if err := os.Rename(staged, exePath); err != nil {
		_ = os.Remove(staged)
		return "", fmt.Errorf("swap binary: %w", err)
	}
	return rel.Tag, nil
}

// Newer reports whether release tag `latest` is a higher x.y.z than `current`.
// Returns false when latest carries no parseable version (can't decide safely → no
// auto-update on an unversioned tag).
func Newer(current, latest string) bool {
	lv := parseVersion(latest)
	if lv == "" {
		return false
	}
	cv := parseVersion(current)
	if cv == "" {
		return true
	}
	return semverLess(cv, lv)
}

func semverLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		if x, y := numAt(pa, i), numAt(pb, i); x != y {
			return x < y
		}
	}
	return false
}

func numAt(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	n := 0
	for _, c := range parts[i] {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
