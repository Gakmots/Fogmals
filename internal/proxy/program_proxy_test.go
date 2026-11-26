package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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

func TestProgramProxyCoversGatewaysAndExplicitNextHops(t *testing.T) {
	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			var gatewayCalls, nextCalls atomic.Int32
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gatewayCalls.Add(1)
				if !strings.Contains(r.Host, ".ipfs.gateway.invalid") && r.Host != "arweave.invalid" {
					t.Errorf("gateway content Host was lost: %s", r.Host)
				}
				io.WriteString(w, "content")
			}))
			defer gateway.Close()
			next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalls.Add(1)
				body, _ := io.ReadAll(r.Body)
				if r.RequestURI != "http://"+r.Host+"/a%2fb?x=1;x=2&bad=%zz" || string(body) != "payload" {
					t.Errorf("program proxy altered next-hop HTTP: %s %q", r.RequestURI, body)
				}
				io.WriteString(w, "forwarded")
			}))
			defer next.Close()
			gatewayURL, _ := url.Parse(gateway.URL)
			nextURL, _ := url.Parse(next.URL)
			program := testutil.NewProxy(t, scheme, func(ctx context.Context, network, address string) (net.Conn, error) {
				var actual string
				switch address {
				case "gateway.invalid:80", "arweave.invalid:80":
					actual = gatewayURL.Host
				case "next.invalid:8081":
					actual = nextURL.Host
				default:
					return nil, fmt.Errorf("unexpected program-proxy target: %s", address)
				}
				return (&net.Dialer{}).DialContext(ctx, network, actual)
			})
			c := httpConfig()
			c.ProgramProxy = config.ProgramProxy{Enabled: true, URL: program.URL}
			c.IPFSGateways = []string{"http://gateway.invalid"}
			c.ArweaveGateways = []string{"http://arweave.invalid"}
			c.TONProxy, c.FallbackProxy = "http://next.invalid:8081", "http://next.invalid:8081"
			h, _ := newHandler(t, c)
			for _, host := range []string{"example.eth", "example.sns", "example.ton", "ordinary.invalid"} {
				method, path := "GET", "/file?x=1"
				var body io.Reader
				if strings.HasSuffix(host, ".ton") || host == "ordinary.invalid" {
					method, path, body = "POST", "/a%2fb?x=1;x=2&bad=%zz", strings.NewReader("payload")
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(method, "http://"+host+path, body))
				if w.Code != 200 {
					t.Fatalf("%s: %d %s", host, w.Code, w.Body.String())
				}
			}
			// Exercise the same outbound injection for the Arweave pool too.
			w := httptest.NewRecorder()
			h.gateways[content.Arweave].Serve(w, httptest.NewRequest("GET", "http://example.eth/file", nil), content.Target{Kind: content.Arweave, ID: strings.Repeat("a", 43)})
			if w.Code != 200 || gatewayCalls.Load() != 3 || nextCalls.Load() != 2 || len(program.Requests) != 4 {
				t.Fatalf("outbound coverage: Arweave=%d gateway=%d next=%d tunnels=%d", w.Code, gatewayCalls.Load(), nextCalls.Load(), len(program.Requests))
			}
		})
	}
}

func TestLocalGatewaysAndNextHopsBypassProgramProxy(t *testing.T) {
	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			program := testutil.NewProxy(t, scheme, func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("local upstream reached program proxy")
			})
			var gatewayCalls, nextCalls atomic.Int32
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gatewayCalls.Add(1); fmt.Fprint(w, "content") }))
			defer gateway.Close()
			next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalls.Add(1); fmt.Fprint(w, "forwarded") }))
			defer next.Close()
			c := httpConfig()
			c.ProgramProxy = config.ProgramProxy{Enabled: true, URL: program.URL}
			c.IPFSGateways = []string{strings.Replace(gateway.URL, "127.0.0.1", "localhost", 1)}
			c.ArweaveGateways, c.SwarmGateways = []string{gateway.URL}, []string{gateway.URL}
			c.TONProxy, c.FallbackProxy = next.URL, next.URL
			h, _ := newHandler(t, c)
			for _, host := range []string{"example.eth", "example.sns", "example.ton", "ordinary.invalid"} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest("GET", "http://"+host+"/file", nil))
				if w.Code != 200 {
					t.Fatalf("local upstream %s: %d %s", host, w.Code, w.Body.String())
				}
			}
			for _, target := range []content.Target{{Kind: content.Arweave, ID: strings.Repeat("A", 43)}, {Kind: content.Swarm, ID: swarmRoot}} {
				w := httptest.NewRecorder()
				h.gateways[target.Kind].Serve(w, httptest.NewRequest("GET", "http://example.eth/file", nil), target)
				if w.Code != 200 {
					t.Fatalf("local %s gateway: %d %s", target.Kind, w.Code, w.Body.String())
				}
			}
			if gatewayCalls.Load() != 4 || nextCalls.Load() != 2 || len(program.Requests) != 0 {
				t.Fatalf("local bypass: gateway=%d next=%d program=%d", gatewayCalls.Load(), nextCalls.Load(), len(program.Requests))
			}
		})
	}
}

func TestProgramProxyChainsNextHopsAndOrdinaryTLS(t *testing.T) {
	for _, tc := range []struct{ outer, next string }{{"http", "http"}, {"http", "socks5"}, {"socks5", "http"}, {"socks5", "socks5"}} {
		t.Run(tc.outer+"/"+tc.next, func(t *testing.T) {
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "origin") }))
			origin.EnableHTTP2 = true
			origin.StartTLS()
			defer origin.Close()
			u, _ := url.Parse(origin.URL)
			next := testutil.NewProxy(t, tc.next, func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, u.Host)
			})
			nextURL, _ := url.Parse(next.URL)
			program := testutil.NewProxy(t, tc.outer, func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "next.invalid:1081" {
					return nil, fmt.Errorf("program proxy skipped next hop: %s", address)
				}
				return (&net.Dialer{}).DialContext(ctx, network, nextURL.Host)
			})
			c := httpConfig()
			c.ProgramProxy = config.ProgramProxy{Enabled: true, URL: program.URL}
			c.FallbackProxy = tc.next + "://next.invalid:1081"
			h, _ := newHandler(t, c)
			entry := httptest.NewServer(h)
			defer entry.Close()
			client := httpsClient(entry.URL, origin.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, true)
			defer client.CloseIdleConnections()
			// The mock next hop maps a standard port to the offline TLS origin.
			resp, err := client.Get("https://127.0.0.1/file")
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.ProtoMajor != 2 || !bytes.Equal(resp.TLS.PeerCertificates[0].Raw, origin.Certificate().Raw) {
				t.Fatal("chained program proxy changed end-to-end TLS")
			}
			if <-next.Requests != "127.0.0.1:443" || len(program.Requests) != 1 {
				t.Fatal("program proxy or configured next hop was bypassed")
			}
		})
	}
}
