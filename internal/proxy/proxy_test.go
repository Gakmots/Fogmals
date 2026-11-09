package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"dwebproxy/internal/config"
	"dwebproxy/internal/content"
)

type fakeResolver struct{ calls atomic.Int32 }

func (r *fakeResolver) Resolve(context.Context, string) (content.Target, error) {
	r.calls.Add(1)
	return content.Parse(content.IPFS, "QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4")
}

func httpConfig() config.Config {
	c := config.Default()
	c.HTTPS.Enabled = false
	return c
}

func newHandler(t *testing.T, c config.Config) (*Handler, *fakeResolver) {
	t.Helper()
	r := &fakeResolver{}
	h, err := New(c, r, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h, r
}

func TestRoutingBoundaries(t *testing.T) {
	h, resolver := newHandler(t, httpConfig())
	for _, tc := range []struct {
		method, url string
		status      int
	}{
		{"CONNECT", "http://alice.eth:443", 501},
		{"GET", "http://alice.sol/", 403},
		{"GET", "http://alice.eth.evil/", 403},
		{"GET", "http://example.com/", 403},
		{"GET", "https://alice.eth/", 400},
		{"GET", "http://alice.eth:8080/", 400},
		{"POST", "http://alice.eth/", 405},
		{"TRACE", "http://alice.ton/", 405},
		{"GET", "http://alice.ton/", 503},
		{"GET", "http://alice.sns/?uri=evil", 400},
		{"GET", "http://alice.eth/%2e%2e/x", 400},
	} {
		t.Run(tc.method+tc.url, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.url, nil))
			if w.Code != tc.status {
				t.Fatalf("got %d: %s", w.Code, w.Body.String())
			}
		})
	}
	if resolver.calls.Load() != 0 {
		t.Fatal("invalid requests reached resolver")
	}
	r := httptest.NewRequest("GET", "http://alice.eth/", nil)
	r.Host = "bob.eth"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("accepted conflicting Host")
	}
}

func TestTONUsesForwardProxyAndPreservesBody(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.RequestURI != "http://alice.ton/api?x=1" || r.Host != "alice.ton" || r.Method != "POST" || string(body) != "payload" {
			t.Errorf("incorrect next-hop request: %s %s %s %q", r.Method, r.RequestURI, r.Host, body)
		}
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("leaked proxy credentials")
		}
		io.WriteString(w, "TON response")
	}))
	defer up.Close()
	c := httpConfig()
	c.TONProxy = up.URL
	h, r := newHandler(t, c)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://alice.ton/api?x=1", strings.NewReader("payload"))
	req.Header.Set("Proxy-Authorization", "secret")
	h.ServeHTTP(w, req)
	if w.Code != 200 || w.Body.String() != "TON response" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if r.calls.Load() != 0 {
		t.Fatal("TON reached blockchain resolver")
	}
}

func TestBrowserStyleForwardRequest(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.Host+r.URL.Path) }))
	defer up.Close()
	c := httpConfig()
	c.IPFSGateways = []string{strings.Replace(up.URL, "127.0.0.1", "localhost", 1)}
	h, _ := newHandler(t, c)
	listener := httptest.NewServer(h)
	defer listener.Close()
	u, _ := url.Parse(listener.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
	defer client.CloseIdleConnections()
	resp, err := client.Get("http://alice.eth/assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), ".ipfs.localhost:") || !strings.HasSuffix(string(body), "/assets/app.js") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}
