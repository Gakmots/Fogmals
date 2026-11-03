package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"dwebproxy/internal/config"
)

// All destinations enter through one real HTTP proxy connection configuration.
// Only the server selects content, TON, or fallback; no PAC/client rules exist.
func TestInternalRoutingThroughSingleProxyListener(t *testing.T) {
	var contentCalls, tonCalls, fallbackCalls atomic.Int32
	content := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentCalls.Add(1)
		if !strings.Contains(r.Host, ".ipfs.localhost:") {
			t.Errorf("content gateway Host=%s", r.Host)
		}
		io.WriteString(w, "content:"+r.URL.RequestURI())
	}))
	defer content.Close()
	ton := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tonCalls.Add(1)
		io.WriteString(w, "ton:"+r.RequestURI)
	}))
	defer ton.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalls.Add(1)
		io.WriteString(w, "fallback:"+r.RequestURI)
	}))
	defer fallback.Close()
	c := config.Default()
	c.IPFSGateways = []string{strings.Replace(content.URL, "127.0.0.1", "localhost", 1)}
	c.TONProxy = ton.URL
	c.FallbackProxy = fallback.URL
	h, resolver := newHandler(t, c)
	entry := httptest.NewServer(h)
	defer entry.Close()
	proxyURL, _ := url.Parse(entry.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	defer client.CloseIdleConnections()
	for _, tc := range []struct{ target, want string }{
		{"http://Example.ETH/docs?x=1", "content:/docs?x=1"},
		{"http://example.sns/assets/app.js", "content:/assets/app.js"},
		{"http://example.ton/api?x=1", "ton:http://example.ton/api?x=1"},
		{"http://example.com/", "fallback:http://example.com/"},
		{"http://192.0.2.1:8080/api", "fallback:http://192.0.2.1:8080/api"},
		{"http://example.eth.evil/", "fallback:http://example.eth.evil/"},
		{"http://example.sol/", "fallback:http://example.sol/"},
	} {
		resp, err := client.Get(tc.target)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || string(body) != tc.want {
			t.Fatalf("%s: status=%d body=%s err=%v", tc.target, resp.StatusCode, body, err)
		}
	}
	if contentCalls.Load() != 2 || tonCalls.Load() != 1 || fallbackCalls.Load() != 4 || resolver.calls.Load() != 2 {
		t.Fatalf("incorrect routes: content=%d ton=%d fallback=%d resolver=%d", contentCalls.Load(), tonCalls.Load(), fallbackCalls.Load(), resolver.calls.Load())
	}
}

func TestLocalToolsStayOutsideDestinationRouting(t *testing.T) {
	var upstreamCalls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
	}))
	defer up.Close()
	c := config.Default()
	c.FallbackProxy = up.URL
	h, resolver := newHandler(t, c)
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/healthz", 200},
		{"/proxy.pac", 404},
		{"/missing", 404},
	} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.Host = c.Listen
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("%s: status=%d body=%s", tc.path, w.Code, w.Body.String())
		}
	}
	if upstreamCalls.Load() != 0 || resolver.calls.Load() != 0 {
		t.Fatal("local utility request entered destination routing")
	}
}
