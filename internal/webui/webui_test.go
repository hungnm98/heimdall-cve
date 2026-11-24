package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestHandler(t *testing.T) {
	h := newHandler(fstest.MapFS{
		"index.html":           {Data: []byte("<html>app</html>")},
		"favicon.svg":          {Data: []byte("<svg/>")},
		"assets/app-1a2b3c.js": {Data: []byte("console.log(1)")},
	})
	cases := []struct {
		method, path string
		status       int
		body, cache  string
	}{
		{"GET", "/", 200, "app", "no-cache"},
		{"GET", "/findings/abc?x=1", 200, "app", "no-cache"},
		{"GET", "/assets/app-1a2b3c.js", 200, "console.log", "immutable"},
		{"GET", "/favicon.svg", 200, "<svg", "no-cache"},
		{"GET", "/assets/missing.js", 404, "", ""},
		{"GET", "/api/v1/unknown", 404, "", ""},
		{"GET", "/index.html", 200, "app", "no-cache"},
		{"POST", "/", 405, "", ""},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.body) || !strings.Contains(rec.Header().Get("Cache-Control"), c.cache) {
			t.Errorf("%s %s = %d %q cache %q", c.method, c.path, rec.Code, rec.Body, rec.Header().Get("Cache-Control"))
		}
	}
}

func TestEmbeddedPlaceholder(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Heimdall") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
