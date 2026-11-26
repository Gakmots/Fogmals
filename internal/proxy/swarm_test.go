package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"dwebproxy/internal/config"
	"dwebproxy/internal/content"
	"dwebproxy/internal/testutil"
)

const swarmRoot = "d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162"

type swarmResolver struct{}

func (swarmResolver) Resolve(context.Context, string) (content.Target, error) {
	return content.Parse(content.Swarm, "bzz://"+swarmRoot)
}

func swarmHandler(t *testing.T, c config.Config) *Handler {
	t.Helper()
	h, err := New(c, swarmResolver{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h
}

func TestSwarmHTTPAndSOCKSIngressWithWeb3TLS(t *testing.T) {
	bee := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "/bzz/" + swarmRoot
		if !strings.HasPrefix(r.URL.Path, prefix+"/") {
			t.Errorf("request left Swarm root: %s", r.RequestURI)
		}
		if r.URL.Path == prefix+"/docs" {
			w.Header().Set("Location", prefix+"/docs/")
			w.WriteHeader(308)
			return
		}
		if r.URL.Path == prefix+"/file name" && r.RequestURI != prefix+"/file%20name?x=1&x=2" {
			t.Errorf("lost Swarm path/query: %s", r.RequestURI)
		}
		if r.Header.Get("Range") == "bytes=0-3" {
			w.WriteHeader(206)
		}
		if r.Method != "HEAD" {
			io.WriteString(w, "data")
		}
	}))
	defer bee.Close()
	for _, ingress := range []string{"http", "socks5"} {
		t.Run(ingress, func(t *testing.T) {
			c := config.Default()
			roots := enableHTTPS(t, &c)
			c.SwarmGateways = []string{bee.URL}
			h := swarmHandler(t, c)
			var entry string
			if ingress == "http" {
				server := httptest.NewServer(h)
				defer server.Close()
				entry = server.URL
			} else {
				entry = socksEntry(t, h)
			}
			for _, tc := range []struct {
				scheme string
				h2     bool
			}{{"http", false}, {"https", false}, {"https", true}} {
				client := httpsClient(entry, roots, tc.h2)
				if ingress == "socks5" {
					client = socksClient(t, entry, roots, tc.h2)
				}
				defer client.CloseIdleConnections()
				for _, method := range []string{"GET", "HEAD"} {
					r, _ := http.NewRequest(method, tc.scheme+"://example.eth/file%20name?x=1&x=2", nil)
					r.Header.Set("Range", "bytes=0-3")
					resp, err := client.Do(r)
					if err != nil {
						t.Fatal(err)
					}
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					wantProto := 1
					if tc.h2 {
						wantProto = 2
					}
					if resp.StatusCode != 206 || resp.ProtoMajor != wantProto || method == "GET" && string(body) != "data" || method == "HEAD" && len(body) != 0 {
						t.Fatalf("%s %s: %s %s %q", method, r.URL, resp.Status, resp.Proto, body)
					}
				}
				resp, err := client.Get(tc.scheme + "://example.eth/docs")
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != 308 || resp.Header.Get("Location") != tc.scheme+"://example.eth/docs/" {
					t.Fatalf("Bee redirect: %s %v", resp.Status, resp.Header)
				}
			}
		})
	}
}

func TestSwarmGatewayUsesProgramProxy(t *testing.T) {
	bee := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "bee.invalid:1633" || r.RequestURI != "/bzz/"+swarmRoot+"/" {
			t.Errorf("proxied Bee target: %s %s", r.Host, r.RequestURI)
		}
		fmt.Fprint(w, "index")
	}))
	defer bee.Close()
	u, _ := url.Parse(bee.URL)
	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			program := testutil.NewProxy(t, scheme, func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "bee.invalid:1633" {
					return nil, fmt.Errorf("unexpected proxy destination: %s", address)
				}
				return (&net.Dialer{}).DialContext(ctx, network, u.Host)
			})
			c := httpConfig()
			c.SwarmGateways = []string{"http://bee.invalid:1633"}
			c.ProgramProxy = config.ProgramProxy{Enabled: true, URL: program.URL}
			h := swarmHandler(t, c)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "http://example.eth/", nil))
			if w.Code != 200 || w.Body.String() != "index" || len(program.Requests) != 1 {
				t.Fatalf("Swarm program proxy: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestSwarmFailuresAndInvalidPathsNeverUseFallback(t *testing.T) {
	var fallbackCalls, beeCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fallbackCalls.Add(1) }))
	defer fallback.Close()
	bee := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { beeCalls.Add(1); w.WriteHeader(503) }))
	defer bee.Close()
	c := httpConfig()
	c.SwarmGateways = []string{bee.URL}
	c.FallbackProxy = fallback.URL
	h := swarmHandler(t, c)
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", "/", 503}, {"GET", "/%2e%2e/stamps", 400}, {"GET", "/%252e%252e/stamps", 400}, {"GET", "/?uri=bzz://other", 400}, {"POST", "/", 405}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, "http://example.eth"+tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s %s: %d", tc.method, tc.path, w.Code)
		}
	}
	if beeCalls.Load() != 1 || fallbackCalls.Load() != 0 {
		t.Fatalf("Swarm failed open: Bee=%d fallback=%d", beeCalls.Load(), fallbackCalls.Load())
	}
}
