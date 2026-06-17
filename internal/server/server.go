// Package server exposes the wakeroute HTTP API and serves the embedded web UI.
package server

import (
	"io/fs"
	"net/http"
	"path/filepath"
	"sync"

	"wakeroute/internal/clash"
	"wakeroute/internal/config"
	"wakeroute/internal/core"
	"wakeroute/internal/failsafe"
	"wakeroute/internal/health"
	"wakeroute/internal/initserver"
	"wakeroute/internal/pbr"
	"wakeroute/internal/plugin"
	"wakeroute/internal/serverstore"
	"wakeroute/internal/store"
	"wakeroute/internal/traffic"
	"wakeroute/internal/updater"
	"wakeroute/internal/watchdog"
)

// Server wires the HTTP handlers to the daemon's components.
type Server struct {
	cfg      *config.Config
	hub      *traffic.Hub
	clash    *clash.Client
	singbox  *core.SingBox
	store    *store.Store
	updater  *updater.Updater
	monitor  *health.Monitor
	failsafe *failsafe.Manager
	plugins  *plugin.Manager
	watchdog *watchdog.Watchdog
	servers  *serverstore.Store
	jobs     *initserver.JobManager
	cfgMu    sync.Mutex // serializes all s.cfg field writes + Save() + reads
	applyMu  sync.Mutex // serializes Apply so concurrent applies don't race singbox.json.tmp / Backup

	// Kernel policy-based-routing plane (RoutingMode=="hybrid"). pbrMu is the SINGLE
	// authority for pbrPlan+pbrBaseline AND for the whole nft/ip command stream against
	// the shared "wakeroute_pbr" table — DISTINCT from applyMu. The rollback closure and
	// boot sync take ONLY pbrMu (never applyMu, which handleApply holds end-to-end), so
	// there is no lock-ordering cycle. pbrRunner is injectable (a RecordRunner) for tests.
	pbrRunner   pbr.Runner
	pbrMu       sync.Mutex
	pbrPlan     *pbr.Plan // currently-installed kernel plan (nil = none installed)
	pbrBaseline *pbr.Plan // rollback target, snapshotted at the FIRST apply of a fail-safe window
	// Engine-plugin specs (AmneziaWG/olcRTC) matching the pre-window config, snapshotted
	// alongside pbrBaseline so a fail-safe rollback re-Syncs the plugins to the restored
	// config (else a restored outbound bound to a torn-down awg device runs dead). Guarded
	// by pbrMu (same rollback-baseline state, set under applyMu, read in the rollback path).
	pluginBaseline []plugin.Spec
	ui             fs.FS
	etagOnce       sync.Once // computes the UI asset ETag lazily, once
	etag           string
	exitIP         exitIPState // cached public-exit-IP lookup for the Dashboard hero

	allowInternalFetch bool // test-only: skip the subscription-fetch SSRF dial guard so httptest (loopback) servers can be used
}

// New builds a Server.
func New(cfg *config.Config, hub *traffic.Hub, cl *clash.Client, sb *core.SingBox, st *store.Store, mon *health.Monitor, ss *serverstore.Store, ui fs.FS) *Server {
	up := updater.New(filepath.Dir(cfg.SingBox.Bin), cfg.Updater.Arch, cfg.Updater.Mirrors)
	pdir := filepath.Join(filepath.Dir(cfg.SingBox.Config), "plugins")
	s := &Server{cfg: cfg, hub: hub, clash: cl, singbox: sb, store: st, updater: up, monitor: mon,
		failsafe: failsafe.New(failsafe.DefaultDurations()), plugins: plugin.New(pdir, filepath.Dir(cfg.SingBox.Bin)),
		servers: ss, jobs: initserver.NewJobManager(), ui: ui, pbrRunner: pbr.ExecRunner{}}
	// Crash-restart supervision for sing-box (and best-effort the engine plugins).
	wd := watchdog.New("sing-box", sb)
	wd.SetPluginSupervisor(s.plugins.Supervise)
	if u := cfg.Watchdog.NotifyURL; u != "" {
		wd.SetNotify(makeWebhookNotifier(u))
	}
	s.watchdog = wd
	return s
}

// Watchdog exposes the crash-restart supervisor so the daemon can Run it.
func (s *Server) Watchdog() *watchdog.Watchdog { return s.watchdog }

// Plugins exposes the engine-plugin manager so the daemon can stop the engines
// (olcRTC procs, AmneziaWG interfaces) cleanly on shutdown.
func (s *Server) Plugins() *plugin.Manager { return s.plugins }

// Handler returns the root http.Handler with all routes mounted.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("GET /api/health/endpoints", s.handleHealthEndpoints)
	mux.HandleFunc("POST /api/health/test/{id}", s.handleHealthTest)
	mux.HandleFunc("/api/traffic/recent", s.handleTrafficRecent)
	mux.HandleFunc("/api/traffic/stream", s.handleTrafficStream)

	// Profile API (M2b). Go 1.22 method+wildcard routing.
	mux.HandleFunc("POST /api/import", s.handleImport)
	mux.HandleFunc("POST /api/subscription", s.handleSubscription)
	mux.HandleFunc("GET /api/profile", s.handleGetProfile)
	mux.HandleFunc("POST /api/endpoints", s.handleUpsertEndpoint)
	mux.HandleFunc("POST /api/endpoints/bulk", s.handleBulkEndpoints)
	mux.HandleFunc("DELETE /api/endpoints/{id}", s.handleDeleteEndpoint)
	mux.HandleFunc("POST /api/groups", s.handleUpsertGroup)
	mux.HandleFunc("DELETE /api/groups/{id}", s.handleDeleteGroup)
	mux.HandleFunc("POST /api/rules", s.handleUpsertRule)
	mux.HandleFunc("DELETE /api/rules/{id}", s.handleDeleteRule)
	// Routing lists (the "Routing" page): list CRUD + the preset catalog.
	mux.HandleFunc("POST /api/routing", s.handleUpsertRoutingList)
	mux.HandleFunc("DELETE /api/routing/{id}", s.handleDeleteRoutingList)
	mux.HandleFunc("GET /api/routing/catalog", s.handleRoutingCatalog)
	mux.HandleFunc("GET /api/routing/status", s.handleRoutingStatus)
	mux.HandleFunc("POST /api/generate", s.handleGenerate)
	mux.HandleFunc("POST /api/apply", s.handleApply)
	// Share / QR / subscription (export connections to client apps).
	mux.HandleFunc("GET /api/endpoints/{id}/export", s.handleEndpointExport)
	mux.HandleFunc("POST /api/qr", s.handleQR)
	mux.HandleFunc("GET /api/subscription/info", s.handleSubInfo)
	mux.HandleFunc("GET /api/sub/{token}", s.handleSubServe)
	mux.HandleFunc("POST /api/apply/confirm", s.handleApplyConfirm)
	mux.HandleFunc("POST /api/apply/rollback", s.handleApplyRollback)
	mux.HandleFunc("GET /api/apply/status", s.handleApplyStatus)
	mux.HandleFunc("POST /api/speedtest", s.handleSpeedtest)
	mux.HandleFunc("GET /api/plugins", s.handlePlugins)
	mux.HandleFunc("GET /api/watchdog", s.handleWatchdog)
	mux.HandleFunc("GET /api/system", s.handleSystem)
	mux.HandleFunc("GET /api/connections", s.handleConnections)
	mux.HandleFunc("GET /api/exit-ip", s.handleExitIP)
	mux.HandleFunc("GET /api/pbr/preview", s.handlePBRPreview)

	// Diagnostics + error knowledgebase.
	mux.HandleFunc("GET /api/diagnostics", s.handleDiagnostics)
	mux.HandleFunc("POST /api/diagnostics", s.handleDiagnosticsAnalyze)
	mux.HandleFunc("GET /api/healthcheck", s.handleHealthCheck)
	mux.HandleFunc("POST /api/netdiag", s.handleNetDiag)
	mux.HandleFunc("POST /api/netdiag/all", s.handleNetDiagAll)
	mux.HandleFunc("GET /api/netdiag/stream", s.handleNetDiagStream)
	mux.HandleFunc("GET /api/kb", s.handleKB)

	// Init Server (R8) — multi-server registry, options, job-based provisioning,
	// hardening, and the smart-console job feed.
	mux.HandleFunc("GET /api/servers", s.handleServers)
	mux.HandleFunc("POST /api/servers", s.handleServers)
	mux.HandleFunc("DELETE /api/servers/{id}", s.handleDeleteServer)
	mux.HandleFunc("GET /api/server/options", s.handleServerOptions)
	mux.HandleFunc("GET /api/server/job/{id}", s.handleServerJob)
	mux.HandleFunc("POST /api/server/check", s.handleServerCheck)
	mux.HandleFunc("POST /api/server/script", s.handleServerScript)
	mux.HandleFunc("POST /api/server/provision", s.handleServerProvision)
	mux.HandleFunc("POST /api/server/harden/keys", s.handleServerHardenKeys)
	mux.HandleFunc("POST /api/server/harden/lockdown", s.handleServerLockdown)

	// Config (Settings).
	mux.HandleFunc("GET /api/config", s.handleGetConfig)
	mux.HandleFunc("PUT /api/config", s.handlePutConfig)
	mux.HandleFunc("POST /api/service/restart", s.handleServiceRestart)

	// Engine version manager (Updater) + WakeRoute self-update.
	mux.HandleFunc("GET /api/updater/engines", s.handleUpdaterEngines)
	mux.HandleFunc("GET /api/updater/self", s.handleSelfStatus)
	mux.HandleFunc("POST /api/updater/self/install", s.handleSelfUpdate)
	mux.HandleFunc("PUT /api/updater/self/auto", s.handleSelfAuto)
	mux.HandleFunc("GET /api/updater/{id}/versions", s.handleUpdaterVersions)
	mux.HandleFunc("POST /api/updater/{id}/install", s.handleUpdaterInstall)

	if s.clash != nil {
		mux.Handle("/api/clash/", s.clash.Proxy("/api/clash"))
	}
	mux.Handle("/", s.staticHandler())
	// Outer-to-inner: access log (sees final status) -> gzip -> routes.
	return logRequests(gzipMiddleware(mux))
}
