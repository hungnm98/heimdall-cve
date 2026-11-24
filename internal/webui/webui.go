// Package webui serves the React SPA embedded in the binary.
//
// The SPA is built in web/ (Vite) into web/dist; `make web` copies web/dist
// into internal/webui/dist, which is embedded here. The committed
// internal/webui/dist holds only a placeholder index.html, so `go build`
// works from a clean checkout without Node.
package webui

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed all:dist
var embedded embed.FS

// Handler serves the embedded SPA. Existing files are served as is (hashed
// assets under /assets/ are cached for a year); any other path without a
// file extension gets index.html so client-side routes work on reload.
// /api/ paths are never answered with the SPA.
func Handler() http.Handler {
	dist, err := fs.Sub(embedded, "dist")
	if err != nil {
		panic(err) // the embed directive guarantees dist exists
	}
	return newHandler(dist)
}

func newHandler(dist fs.FS) http.Handler {
	index, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		panic("webui: dist/index.html missing")
	}
	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := path.Clean("/" + r.URL.Path)
		if p == "/api" || strings.HasPrefix(p, "/api/") {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(p, "/")
		if name == "" || name == "index.html" {
			serveIndex(w, r)
			return
		}
		if st, err := fs.Stat(dist, name); err == nil && !st.IsDir() {
			if strings.HasPrefix(name, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			http.ServeFileFS(w, r, dist, name)
			return
		}
		if path.Ext(name) != "" { // a missing asset must not turn into HTML
			http.NotFound(w, r)
			return
		}
		serveIndex(w, r)
	})
}
