package server

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// gzipMiddleware must compress text/json, pass image bytes through untouched, and
// not compress for clients that don't advertise gzip.
func TestGzipMiddlewareJSONRoundTrip(t *testing.T) {
	h := gzipMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hello":"world","n":12345}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	body, _ := io.ReadAll(zr)
	if string(body) != `{"hello":"world","n":12345}` {
		t.Fatalf("decompressed body = %q", body)
	}
}

func TestGzipMiddlewareSkipsImageAndNoAccept(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\nrest-of-bytes")
	mk := func() http.Handler {
		return gzipMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(png)
		}))
	}
	// image/png: gzip-capable client, but content is not compressible -> passthrough.
	req := httptest.NewRequest(http.MethodGet, "/api/qr", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	mk().ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") == "gzip" {
		t.Fatal("image/png must not be gzipped")
	}
	if string(rec.Body.Bytes()) != string(png) {
		t.Fatal("png body altered")
	}
	// No Accept-Encoding: never gzip, even for JSON.
	h := gzipMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"a":1}`))
	}))
	req2 := httptest.NewRequest(http.MethodGet, "/api/y", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Header().Get("Content-Encoding") == "gzip" {
		t.Fatal("must not gzip without Accept-Encoding: gzip")
	}
	if rec2.Body.String() != `{"a":1}` {
		t.Fatalf("plain body = %q", rec2.Body.String())
	}
}

// staticHandler must serve assets with a stable ETag and answer If-None-Match
// with 304 (no body) so repeat loads don't re-download the bundle.
func TestStaticHandlerETag304(t *testing.T) {
	s := &Server{ui: fstest.MapFS{
		"index.html": {Data: []byte("<html>hi</html>")},
		"app.js":     {Data: []byte("console.log(1)")},
		"styles.css": {Data: []byte("body{}")},
	}}
	h := s.staticHandler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag set on static response")
	}
	if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		t.Fatalf("first load: code=%d len=%d, want 200 with body", rec.Code, rec.Body.Len())
	}

	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	req.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match match: code=%d, want 304", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Fatal("304 must have no body")
	}
}
