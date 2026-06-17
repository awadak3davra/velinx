package server

import (
	"compress/gzip"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// staticHandler serves the embedded UI with revalidate-on-version caching. The
// ETag is a hash of the bundled assets, so a new build changes it and the browser
// fetches fresh JS/CSS (no hard-reload needed), while an unchanged build returns a
// tiny 304 instead of re-sending ~97KB on every page load.
func (s *Server) staticHandler() http.Handler {
	fileServer := http.FileServer(http.FS(s.ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		etag := s.uiETag()
		w.Header().Set("Cache-Control", "no-cache") // always revalidate
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

// uiETag is a content hash of the embedded UI assets, computed once. Weak ETag
// (W/) because gzip changes the on-the-wire bytes per representation.
func (s *Server) uiETag() string {
	s.etagOnce.Do(func() {
		h := fnv.New64a()
		for _, name := range []string{"index.html", "app.js", "styles.css"} {
			if b, err := fs.ReadFile(s.ui, name); err == nil {
				_, _ = h.Write(b)
			}
		}
		s.etag = fmt.Sprintf(`W/"wr-%x"`, h.Sum64())
	})
	return s.etag
}

// logRequests logs only mutating requests and errors — never the high-frequency
// GET polls (traffic/health), which would otherwise flood the router's logread.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(sw, r)
		mutating := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
		if mutating || sw.status >= 400 {
			log.Printf("%s %s %d (%s)", r.Method, r.URL.Path, sw.status, time.Since(start).Round(time.Millisecond))
		}
	})
}

// statusWriter records the response status while passing everything through.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wroteHeader = true
	return w.ResponseWriter.Write(b)
}

// Flush keeps SSE / streaming working through the wrapper (the traffic-stream
// handler asserts http.Flusher directly).
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController (used by httputil.ReverseProxy for the
// Clash proxy) reach the underlying ResponseWriter's Flusher/Hijacker through
// this access-log wrapper, instead of silently losing them.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ---- gzip ----

var gzipPool = sync.Pool{New: func() any {
	gz, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
	return gz
}}

// gzipMiddleware compresses compressible responses for clients that accept gzip.
// It skips the streaming endpoints (the SSE traffic stream and the Clash reverse
// proxy) and non-text content (the QR PNG), deciding from the response Content-Type.
func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") ||
			r.URL.Path == "/api/traffic/stream" ||
			r.URL.Path == "/api/netdiag/stream" ||
			strings.HasPrefix(r.URL.Path, "/api/clash/") {
			next.ServeHTTP(w, r)
			return
		}
		gz := gzipPool.Get().(*gzip.Writer)
		gw := &gzipResponseWriter{ResponseWriter: w, gz: gz}
		defer func() {
			if gw.use == useGzip {
				_ = gw.gz.Close()
			}
			gzipPool.Put(gz)
		}()
		next.ServeHTTP(gw, r)
	})
}

const (
	useUnknown = iota
	useGzip
	usePlain
)

type gzipResponseWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	use         int
	wroteHeader bool
}

// decide picks gzip vs passthrough from the Content-Type the handler set, and
// (when gzipping) re-targets the pooled writer at the real ResponseWriter.
func (w *gzipResponseWriter) decide() {
	if w.use != useUnknown {
		return
	}
	if gzipCompressible(w.Header().Get("Content-Type")) {
		w.use = useGzip
		w.gz.Reset(w.ResponseWriter)
		w.Header().Del("Content-Length") // length changes after compression
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
	} else {
		w.use = usePlain
	}
}

func (w *gzipResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.decide()
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.use == useGzip {
		return w.gz.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *gzipResponseWriter) Flush() {
	if w.use == useGzip {
		_ = w.gz.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func gzipCompressible(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "css") ||
		strings.Contains(ct, "svg") ||
		strings.Contains(ct, "xml")
}
