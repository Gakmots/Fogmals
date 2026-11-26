package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dwebproxy/internal/config"
)

func TestUpstreamFailuresUseSharedStatusAcrossRoutes(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		name, want := "connection failure", http.StatusBadGateway
		if timeout {
			name, want = "response header timeout", http.StatusGatewayTimeout
		}
		t.Run(name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
			defer up.Close()
			if !timeout {
				up.Close()
			}
			c := httpConfig()
			c.ResponseHeaderTimeout = config.Duration(100 * time.Millisecond)
			c.IPFSGateways = []string{strings.Replace(up.URL, "127.0.0.1", "localhost", 1)}
			c.TONProxy, c.FallbackProxy = up.URL, up.URL
			h, _ := newHandler(t, c)
			for _, host := range []string{"example.eth", "example.sns", "example.ton", "example.com"} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil))
				if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
					t.Errorf("%s: status=%d, headers=%v", host, w.Code, w.Header())
				}
			}
		})
	}
}

func TestFallbackConnectTimeoutReturns504(t *testing.T) {
	next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer next.Close()
	c := httpConfig()
	c.FallbackProxy = next.URL
	c.HTTPS.HandshakeTimeout = config.Duration(100 * time.Millisecond)
	h, _ := newHandler(t, c)
	entry := httptest.NewServer(h)
	defer entry.Close()
	defer h.Close()
	conn, resp := rawConnect(t, entry.URL, "example.com:443")
	defer conn.Close()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%s %v", resp.Status, resp.Header)
	}
	waitNoTunnels(t, h)
}

func TestWeb3HTTPSDisabledSkipsCAAndKeepsConnect(t *testing.T) {
	c := httpConfig()
	c.HTTPS.CACert, c.HTTPS.CAKey = "", ""
	h, _ := newHandler(t, c)
	if h.connect == nil || h.connect.ca != nil {
		t.Fatal("CONNECT needs a manager but disabled Web3 HTTPS must not load a CA")
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Host = c.Listen
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodConnect, "example.eth:443", nil))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("disabled Web3 CONNECT: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodConnect, "example.com:443", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("ordinary CONNECT without fallback: %d", w.Code)
	}
}

func TestFallbackConnectPreservesNextHopTimeout(t *testing.T) {
	for _, status := range []int{http.StatusGatewayTimeout, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer next.Close()
			c := httpConfig()
			enableHTTPS(t, &c)
			c.FallbackProxy = next.URL
			h, _ := newHandler(t, c)
			entry := httptest.NewServer(h)
			defer entry.Close()
			defer h.Close()
			conn, resp := rawConnect(t, entry.URL, "example.com:443")
			defer conn.Close()
			defer resp.Body.Close()
			want := http.StatusBadGateway
			if status == http.StatusGatewayTimeout {
				want = http.StatusGatewayTimeout
			}
			if resp.StatusCode != want {
				t.Fatalf("next hop=%d, proxy=%d", status, resp.StatusCode)
			}
			waitNoTunnels(t, h)
		})
	}
}
