// Command wakeroute is the WakeRoute daemon: it serves the web panel and
// supervises the proxy cores (sing-box plus engine plugins).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"wakeroute/internal/clash"
	"wakeroute/internal/config"
	"wakeroute/internal/core"
	"wakeroute/internal/health"
	"wakeroute/internal/platform"
	"wakeroute/internal/server"
	"wakeroute/internal/serverstore"
	"wakeroute/internal/store"
	"wakeroute/internal/traffic"
	"wakeroute/internal/version"
	"wakeroute/web"
)

func main() {
	var (
		configPath = flag.String("config", "/opt/etc/wakeroute/config.json", "path to the wakeroute config file")
		listen     = flag.String("listen", "", "override the UI listen address (e.g. :8088)")
		demo       = flag.Bool("demo", false, "synthesize traffic for UI development without sing-box")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("wakeroute %s (%s, %s)\n", version.Version, version.Commit, version.Date)
		return
	}

	// Non-daemon subcommands: `wakeroute import <link>`, `wakeroute gen <link>`.
	if args := flag.Args(); len(args) > 0 {
		if err := runTool(args); err != nil {
			log.Fatalf("%s: %v", args[0], err)
		}
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *demo {
		cfg.Demo = true
	}

	// Runtime platform detection (D-PLAT-2: one universal binary, behavior chosen at
	// runtime rather than per-platform builds). Informational today — the OpenWrt apply
	// path (pbr/nft + sing-box) is unchanged. On Keenetic the native-first backend
	// (internal/keenetic implementing platform.RoutingBackend) is what the apply path will
	// select here once it is platform-routed; the backend itself is built + validated.
	log.Printf("platform: %s", platform.Detect())

	hub := traffic.NewHub(300)
	sb := core.New(cfg.SingBox.Bin, cfg.SingBox.Config)
	cl, err := clash.New(cfg.Clash.Controller, cfg.Clash.Secret)
	if err != nil {
		log.Fatalf("clash client: %v", err)
	}

	profilePath := filepath.Join(filepath.Dir(*configPath), "profile.json")
	st, err := store.Open(profilePath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	serversPath := filepath.Join(filepath.Dir(*configPath), "servers.json")
	ss, err := serverstore.Open(serversPath)
	if err != nil {
		log.Fatalf("server store: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Feed the traffic hub from the demo generator or the real Clash stream.
	if cfg.Demo {
		go runDemoTraffic(ctx, hub)
	} else {
		go runClashTraffic(ctx, cl, hub)
	}

	// Background health monitor: probes endpoints/groups, accumulates stats,
	// attributes traffic, and derives failure causes from the sing-box log.
	mon := health.NewMonitor(cl, st, sb, cfg.Demo)
	go mon.Run(ctx)

	// Autostart sing-box if a config already exists (so it's supervised from
	// boot). Demo mode and a missing binary are no-ops handled by Start.
	if !cfg.Demo && sb.Available() {
		if _, err := os.Stat(cfg.SingBox.Config); err == nil {
			if err := sb.Start(); err != nil {
				log.Printf("sing-box autostart: %v", err)
			} else {
				log.Printf("sing-box started")
			}
		}
	}

	srv := server.New(cfg, hub, cl, sb, st, mon, ss, web.FS())
	go srv.SyncPlugins()       // bring engine plugins (AmneziaWG interfaces, olcRTC) up from boot
	go srv.AutoUpdateLoop(ctx) // self-update WakeRoute when Updater.AutoUpdate is on (default off)
	// Crash-restart supervision for sing-box (+ best-effort engine plugins).
	wdDone := make(chan struct{})
	go func() { srv.Watchdog().Run(ctx); close(wdDone) }()
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("wakeroute %s listening on %s (demo=%v)", version.Version, cfg.Listen, cfg.Demo)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down…")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	// Wait for the watchdog to stop ticking before tearing down the engine: an
	// in-flight tick could otherwise (re)start sing-box right after we Stop it,
	// orphaning a process that keeps the listen ports bound. tick() is fast, so
	// this returns promptly.
	<-wdDone
	_ = sb.Stop()
	srv.Plugins().StopAll() // stop engine plugins (olcRTC procs, awg interfaces) so they don't orphan
}

// runClashTraffic keeps the Clash /traffic stream connected, retrying on failure.
//
// The Clash API only exists while sing-box is running, so a failure here is
// normally just "no engine up yet" — the expected idle state, not a fault. We
// log the first drop, then stay quiet while retrying so we don't flood the
// router log (logread) every few seconds when nothing is applied. The next
// drop is logged again only after a stream that actually stayed connected.
func runClashTraffic(ctx context.Context, cl *clash.Client, hub *traffic.Hub) {
	const retry = 3 * time.Second
	loggedDown := false
	for ctx.Err() == nil {
		start := time.Now()
		err := cl.StreamTraffic(ctx, hub.Push)
		if ctx.Err() != nil {
			return
		}
		// A stream that lasted longer than the retry interval was a real,
		// connected session that dropped — treat the next failure as fresh
		// news worth logging. A near-instant return is the idle "engine not
		// up" state, which we announce once and then suppress.
		if time.Since(start) > retry {
			loggedDown = false
		}
		if !loggedDown {
			log.Printf("clash traffic stream unavailable (%v); retrying every %s until the engine is up", err, retry)
			loggedDown = true
		}
		select {
		case <-ctx.Done():
		case <-time.After(retry):
		}
	}
}

// runDemoTraffic synthesizes a believable up/down signal at 1 Hz so the UI and
// graph can be developed without a running sing-box.
func runDemoTraffic(ctx context.Context, hub *traffic.Hub) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var i float64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			i++
			down := 1.5e6 + 1.0e6*math.Sin(i/7) + 4.0e5*math.Sin(i/2.3)
			up := 5.0e5 + 3.0e5*math.Sin(i/5+1) + 1.5e5*math.Sin(i/1.7)
			if down < 0 {
				down = 0
			}
			if up < 0 {
				up = 0
			}
			hub.Push(traffic.Sample{T: time.Now().UnixMilli(), Up: int64(up), Down: int64(down)})
		}
	}
}
