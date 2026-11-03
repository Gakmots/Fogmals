package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"dwebproxy/internal/config"
	"dwebproxy/internal/content"
	"dwebproxy/internal/resolve"
)

func TestFallbackPreservesUnmatchedHTTPRequests(t *testing.T) {
	for _, target := range []string{
		"http://example.com/api/a%20b?x=1&uri=unchanged",
		"http://example.com:8080/api/a%20b?x=1&uri=unchanged",
		"http://example.eth.evil/api/a%20b?x=1&uri=unchanged",
		"http://example.sol/api/a%20b?x=1&uri=unchanged",
		"http://192.0.2.1:8080/api/a%20b?x=1&uri=unchanged",
		"http://[2001:db8::1]:8080/api/a%20b?x=1&uri=unchanged",
	} {
		t.Run(target, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if r.RequestURI != target || r.Host != r.URL.Host || r.Method != "POST" || string(body) != "payload" {
					t.Errorf("incorrect fallback request: %s %s %s %q", r.Method, r.RequestURI, r.Host, body)
				}
				if r.Header.Get("Authorization") != "Bearer site-token" || r.Header.Get("Cookie") != "session=1" {
					t.Error("site authentication was lost")
				}
				if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Forwarded-Host") != "" {
					t.Error("incoming proxy credentials or forwarded headers leaked")
				}
				w.Header().Set("Set-Cookie", "session=2")
				w.WriteHeader(http.StatusAccepted)
				io.WriteString(w, "fallback response")
			}))
			defer up.Close()
			c := config.Default()
			c.FallbackProxy = up.URL
			h, resolver := newHandler(t, c)
			req := httptest.NewRequest("POST", target, strings.NewReader("payload"))
			req.Header.Set("Authorization", "Bearer site-token")
			req.Header.Set("Cookie", "session=1")
			req.Header.Set("Proxy-Authorization", "Basic secret")
			req.Header.Set("X-Forwarded-Host", "untrusted")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusAccepted || w.Body.String() != "fallback response" || w.Header().Get("Set-Cookie") != "session=2" {
				t.Fatalf("%d %s %v", w.Code, w.Body.String(), w.Header())
			}
			if resolver.calls.Load() != 0 {
				t.Fatal("unmatched destination reached a chain resolver")
			}
		})
	}
}

type missingResolver struct{}

func (missingResolver) Resolve(context.Context, string) (content.Target, error) {
	return content.Target{}, resolve.ErrNotFound
}

func TestFallbackDoesNotHandleMatchedFailuresOrInvalidRequests(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, "unexpected fallback")
	}))
	defer up.Close()
	c := config.Default()
	c.FallbackProxy = up.URL
	h, _ := newHandler(t, c)
	h.resolver = missingResolver{}
	for _, tc := range []struct {
		method, target string
		status         int
	}{
		{"GET", "http://example.eth/", 404},
		{"GET", "http://example.sns/", 404},
		{"GET", "http://example.ton/", 503},
		{"GET", "http://bad..eth/", 400},
		{"GET", "http://example.eth:8080/", 400},
		{"GET", "http://example.sns/?uri=evil", 400},
		{"GET", "http://example.com:0/", 400},
		{"GET", "https://example.com/", 400},
		{"CONNECT", "http://example.com:443/", 501},
		{"TRACE", "http://example.com/", 405},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.target, nil))
		if w.Code != tc.status {
			t.Errorf("%s %s: %d %s", tc.method, tc.target, w.Code, w.Body.String())
		}
	}
	if calls.Load() != 0 {
		t.Fatal("matched failure or invalid request reached fallback")
	}
}

func TestMatchedGatewayAndTONKeepPriority(t *testing.T) {
	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalls.Add(1)
	}))
	defer fallback.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "matched upstream")
	}))
	defer up.Close()
	c := config.Default()
	c.FallbackProxy = fallback.URL
	c.TONProxy = up.URL
	c.IPFSGateways = []string{strings.Replace(up.URL, "127.0.0.1", "localhost", 1)}
	h, _ := newHandler(t, c)
	for _, host := range []string{"example.eth", "example.sns", "example.ton"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "http://"+host+"/", nil))
		if w.Code != 503 || w.Body.String() != "matched upstream" {
			t.Fatalf("%s: %d %s", host, w.Code, w.Body.String())
		}
	}
	if fallbackCalls.Load() != 0 {
		t.Fatal("matched upstream failure reached fallback")
	}
}

func TestFallbackFailureDoesNotConnectDirectly(t *testing.T) {
	var directCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directCalls.Add(1)
	}))
	defer target.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	up.Close()
	c := config.Default()
	c.FallbackProxy = up.URL
	h, _ := newHandler(t, c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", target.URL+"/", nil))
	if w.Code != 502 || directCalls.Load() != 0 {
		t.Fatalf("fallback failure: status=%d direct=%d", w.Code, directCalls.Load())
	}
}

func TestHTTPSFallbackProxy(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "http://example.com/path" {
			t.Errorf("request URI=%s", r.RequestURI)
		}
		io.WriteString(w, "secure next hop")
	}))
	defer up.Close()
	c := config.Default()
	c.FallbackProxy = up.URL
	h, _ := newHandler(t, c)
	// Trust only the httptest server's test certificate.
	h.fallback.transport.TLSClientConfig = up.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://example.com/path", nil))
	if w.Code != 200 || w.Body.String() != "secure next hop" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
