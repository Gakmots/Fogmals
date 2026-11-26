package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dwebproxy/internal/content"
)

const swarmReference = "d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162"

func TestSwarmGatewayPathHeadersAndStreaming(t *testing.T) {
	root, _ := content.Parse(content.Swarm, swarmReference)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/bzz/"+swarmReference+"/docs/a%20b.html?x=1&x=2" || strings.Contains(r.Host, ".bzz.") {
			t.Errorf("Bee destination: %s %s", r.Host, r.RequestURI)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("website credentials leaked to Bee")
		}
		if r.Header.Get("Range") != "bytes=0-3" || r.Header.Get("If-None-Match") != `"version"` {
			t.Error("Range or validator was lost")
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("ETag", `"version"`)
		w.Header().Set("Content-Range", "bytes 0-3/100")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("Set-Cookie", "bee=private")
		w.WriteHeader(206)
		if r.Method != "HEAD" {
			io.WriteString(w, "data")
		}
	}))
	defer up.Close()
	p, err := New([]string{up.URL}, time.Second, logger(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, method := range []string{"GET", "HEAD"} {
		r := httptest.NewRequest(method, "http://example.eth/docs/a%20b.html?x=1&x=2", nil)
		r.Header.Set("Range", "bytes=0-3")
		r.Header.Set("If-None-Match", `"version"`)
		r.Header.Set("Cookie", "private=1")
		r.Header.Set("Authorization", "private")
		r.Header.Set("Proxy-Authorization", "private")
		w := httptest.NewRecorder()
		p.Serve(w, r, root)
		if w.Code != 206 || w.Header().Get("ETag") != `"version"` || w.Header().Get("Cache-Control") != "no-cache" || w.Header().Get("Set-Cookie") != "" {
			t.Fatalf("Bee response: %d %v", w.Code, w.Header())
		}
		if method == "GET" && w.Body.String() != "data" || method == "HEAD" && w.Body.Len() != 0 {
			t.Fatalf("%s body: %s", method, w.Body.String())
		}
	}
}

func TestSwarmRedirectsStayInsideManifest(t *testing.T) {
	root, _ := content.Parse(content.Swarm, swarmReference)
	base, _ := url.Parse("http://localhost:1633")
	in, _ := url.Parse("https://example.eth/docs")
	out := targetURL(base, root, in)
	for _, tc := range []struct {
		location, want string
		invalid        bool
	}{
		{"/bzz/" + swarmReference + "/docs/", "https://example.eth/docs/", false},
		{"http://localhost:1633/bzz/" + swarmReference + "/docs/?lang=zh", "https://example.eth/docs/?lang=zh", false},
		{"./docs/", "https://example.eth/docs/", false},
		{"../login", "", true},
		{"/bzz/" + swarmReference + "/100%25.html", "https://example.eth/100%25.html", false},
		{"/bzz/" + strings.Repeat("a", 64) + "/", "", true},
		{"/bzz/" + swarmReference + "suffix/", "", true},
		{"/stamps", "", true},
		{"/debug", "", true},
		{"../../stamps", "", true},
		{"/bzz/" + swarmReference + "/%252e%252e/stamps", "", true},
		{"https://outside.example/path?uri=ok", "https://outside.example/path?uri=ok", false},
	} {
		got, err := rewriteLocation(tc.location, base, out, in, in.Host, root)
		if (err != nil) != tc.invalid || !tc.invalid && got != tc.want {
			t.Errorf("Location %q: got=%q error=%v", tc.location, got, err)
		}
	}
	// A parent-directory reference within the manifest remains valid.
	in, _ = url.Parse("https://example.eth/docs/page")
	out = targetURL(base, root, in)
	if got, err := rewriteLocation("../login", base, out, in, in.Host, root); err != nil || got != "https://example.eth/login" {
		t.Fatalf("bounded parent redirect: %s %v", got, err)
	}
}

func TestSwarmRootAndFailover(t *testing.T) {
	root, _ := content.Parse(content.Swarm, swarmReference)
	for _, status := range []int{404, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer first.Close()
			second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.RequestURI != "/bzz/"+swarmReference+"/" {
					t.Errorf("Bee root: %s", r.RequestURI)
				}
				io.WriteString(w, "index")
			}))
			defer second.Close()
			p, _ := New([]string{first.URL, second.URL}, time.Second, logger(), nil)
			defer p.Close()
			w := httptest.NewRecorder()
			p.Serve(w, httptest.NewRequest("GET", "http://example.eth/", nil), root)
			if status == 404 && (w.Code != 404 || calls.Load() != 0) || status == 503 && (w.Code != 200 || w.Body.String() != "index" || calls.Load() != 1) {
				t.Fatalf("Bee failover: status=%d response=%d calls=%d", status, w.Code, calls.Load())
			}
		})
	}
}
