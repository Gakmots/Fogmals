package gateway

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dwebproxy/internal/content"
)

const cidV0 = "QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4"

func logger() *slog.Logger        { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func localhost(raw string) string { return strings.Replace(raw, "127.0.0.1", "localhost", 1) }

func TestSubdomainRequestAndStreamingHeaders(t *testing.T) {
	root, _ := content.Parse(content.IPFS, cidV0)
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !strings.HasPrefix(r.Host, root.ID+".ipfs.localhost:") {
			t.Errorf("upstream Host=%s", r.Host)
		}
		if r.URL.RequestURI() != "/docs/a%20b.html?lang=zh&x=1" {
			t.Errorf("upstream URI=%s", r.URL.RequestURI())
		}
		if r.Header.Get("Range") != "bytes=0-3" || r.Header.Get("If-None-Match") != "\"version\"" {
			t.Error("lost conditional/range headers")
		}
		for _, h := range []string{"Cookie", "Authorization", "Proxy-Authorization", "X-Forwarded-Host"} {
			if r.Header.Get(h) != "" {
				t.Errorf("leaked %s", h)
			}
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("Set-Cookie", "gateway=secret")
		w.Header().Set("ETag", "\"version\"")
		w.Header().Set("Content-Range", "bytes 0-3/100")
		w.WriteHeader(http.StatusPartialContent)
		if r.Method != http.MethodHead {
			io.WriteString(w, "data")
		}
	}))
	defer up.Close()
	p, err := New([]string{localhost(up.URL)}, time.Second, logger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		r := httptest.NewRequest(method, "http://alice.eth/docs/a%20b.html?lang=zh&x=1", nil)
		r.Header.Set("Range", "bytes=0-3")
		r.Header.Set("If-None-Match", "\"version\"")
		r.Header.Set("Cookie", "private=1")
		r.Header.Set("Authorization", "Bearer secret")
		r.Header.Set("Proxy-Authorization", "secret")
		r.Header.Set("X-Forwarded-Host", "evil")
		w := httptest.NewRecorder()
		p.Serve(w, r, root)
		if w.Code != 206 || w.Header().Get("Cache-Control") != "no-cache" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("ETag") != "\"version\"" {
			t.Fatalf("response %d %v", w.Code, w.Header())
		}
		if method == http.MethodGet && w.Body.String() != "data" {
			t.Fatal(w.Body.String())
		}
		if method == http.MethodHead && w.Body.Len() != 0 {
			t.Fatal("HEAD has a body")
		}
	}
	if hits.Load() != 2 {
		t.Fatal(hits.Load())
	}
}

func TestFailoverOnlyForUpstreamFailures(t *testing.T) {
	root, _ := content.Parse(content.IPFS, cidV0)
	for _, status := range []int{404, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var fallback atomic.Int32
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer first.Close()
			second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fallback.Add(1); io.WriteString(w, "fallback") }))
			defer second.Close()
			p, _ := New([]string{localhost(first.URL), localhost(second.URL)}, time.Second, logger())
			defer p.Close()
			w := httptest.NewRecorder()
			p.Serve(w, httptest.NewRequest("GET", "http://alice.eth/", nil), root)
			want := int32(0)
			if status == 503 {
				want = 1
			}
			if fallback.Load() != want {
				t.Fatalf("fallback requests=%d", fallback.Load())
			}
			if status == 404 && w.Code != 404 {
				t.Fatal(w.Code)
			}
			if status == 503 && w.Body.String() != "fallback" {
				t.Fatal(w.Body.String())
			}
		})
	}
}

func TestRedirectMapping(t *testing.T) {
	ipfs, _ := content.Parse(content.IPFS, cidV0)
	ar, _ := content.Parse(content.Arweave, strings.Repeat("A", 43))
	base, _ := url.Parse("http://localhost:8080")
	in, _ := url.Parse("http://alice.eth/docs")
	for _, tc := range []struct {
		target    content.Target
		raw, want string
		invalid   bool
	}{
		{ipfs, "/docs/", "http://alice.eth/docs/", false},
		{ipfs, "http://localhost:8080/ipfs/" + cidV0 + "/docs/", "http://alice.eth/docs/", false},
		{ipfs, "https://example.com/", "https://example.com/", false},
		{ipfs, "/docs", "", true},
		{ipfs, "http://localhost:8080/api/v0/shutdown", "", true},
		{ipfs, "/../escape", "", true},
		{ar, "/" + ar.ID + "/docs/", "http://alice.eth/docs/", false},
		{ar, "/api/v0/shutdown", "", true},
	} {
		out := targetURL(base, tc.target, in)
		got, err := rewriteLocation(tc.raw, base, out, in, "alice.eth", tc.target)
		if (err != nil) != tc.invalid || (!tc.invalid && got != tc.want) {
			t.Errorf("%s: got=%s err=%v", tc.raw, got, err)
		}
	}
	out := targetURL(base, ar, in)
	out.Host = "sandbox.localhost:8080"
	got, err := rewriteLocation("http://localhost:8080/"+ar.ID+"/docs/", base, out, in, "alice.eth", ar)
	if err != nil || got != "http://alice.eth/docs/" {
		t.Fatalf("sandbox to gateway redirect: %s %v", got, err)
	}
}

func TestPathTraversalAndOverrides(t *testing.T) {
	for _, s := range []string{"/../x", "/%2e%2e/x", "/x%2fy", "/x%5cy", "/%252e%252e/x", "/?uri=ipfs%3A%2F%2Fevil", "/?%75ri=evil", "/?x=%xx"} {
		u, err := url.Parse(s)
		if err == nil && ValidatePath(u) == nil {
			t.Errorf("accepted %s", s)
		}
	}
	for _, s := range []string{"/", "/x%20y/", "/docs/?x=a%2Fb"} {
		u, _ := url.Parse(s)
		if err := ValidatePath(u); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
}

func TestArweaveSandboxRedirectStaysInsideProxy(t *testing.T) {
	root, _ := content.Parse(content.Arweave, strings.Repeat("A", 43))
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/"+root.ID+"/docs/a.html" {
			t.Errorf("path=%s", r.URL.Path)
		}
		if strings.HasPrefix(r.Host, "localhost:") {
			w.Header().Set("Location", "http://sandbox."+r.Host+r.URL.RequestURI())
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		if !strings.HasPrefix(r.Host, "sandbox.localhost:") {
			t.Errorf("host=%s", r.Host)
		}
		io.WriteString(w, "Arweave content")
	}))
	defer up.Close()
	p, _ := New([]string{localhost(up.URL)}, time.Second, logger())
	defer p.Close()
	w := httptest.NewRecorder()
	p.Serve(w, httptest.NewRequest("GET", "http://alice.eth/docs/a.html", nil), root)
	if w.Code != 200 || w.Body.String() != "Arweave content" || hits.Load() != 2 {
		t.Fatalf("%d %q hits=%d", w.Code, w.Body.String(), hits.Load())
	}
}
