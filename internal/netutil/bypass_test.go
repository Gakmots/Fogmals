package netutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"dwebproxy/internal/testutil"
)

func TestLocalIPRoutingRanges(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1", "127.255.255.254", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.0.1",
		"169.254.169.254", "100.64.0.1", "100.127.255.254", "0.0.0.0", "0.1.2.3", "255.255.255.255", "224.0.0.1",
		"::", "::1", "fc00::1", "fd12::abcd", "fe80::1", "fe80::1%eth0", "fec0::1", "ff02::1",
		"::ffff:127.0.0.1", "::ffff:192.168.1.1", "::ffff:100.64.1.1",
	} {
		if !LocalIP(netip.MustParseAddr(raw)) {
			t.Errorf("local address uses proxy: %s", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1", "192.169.0.1", "198.18.0.1", "192.0.2.1", "203.0.113.1", "2001:db8::1", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if LocalIP(netip.MustParseAddr(raw)) {
			t.Errorf("non-local address bypasses proxy: %s", raw)
		}
	}
	if LocalIP(netip.Addr{}) {
		t.Fatal("invalid address treated as a local route")
	}
}

func TestLocalBypassRouteSelectionAndPinnedDNS(t *testing.T) {
	for _, tc := range []struct {
		target string
		ips    []string
		direct []string
		proxy  bool
		lookup bool
	}{
		{target: "127.0.0.1:1633", direct: []string{"127.0.0.1:1633"}},
		{target: "[::ffff:192.168.1.1]:80", direct: []string{"[::ffff:192.168.1.1]:80"}},
		{target: "[fe80::1%eth0]:80", direct: []string{"[fe80::1%eth0]:80"}},
		{target: "203.0.113.7:443", direct: []string{"203.0.113.7:443"}}, // Test host's assigned address.
		{target: "LOCALHOST.:1633", direct: []string{"[::1]:1633", "127.0.0.1:1633"}},
		{target: "assets.localhost:8080", direct: []string{"[::1]:8080", "127.0.0.1:8080"}},
		{target: "router:80", direct: []string{"router:80"}},
		{target: "nas.local:80", direct: []string{"nas.local:80"}},
		{target: "node.home.arpa:80", direct: []string{"node.home.arpa:80"}},
		{target: "db.lan:80", direct: []string{"db.lan:80"}},
		{target: "rpc.internal:80", direct: []string{"rpc.internal:80"}},
		{target: "rpc.example:8545", ips: []string{"10.0.0.7"}, direct: []string{"10.0.0.7:8545"}, lookup: true},
		{target: "mapped.example:80", ips: []string{"::ffff:192.168.1.7"}, direct: []string{"192.168.1.7:80"}, lookup: true},
		{target: "own.example:443", ips: []string{"203.0.113.7"}, direct: []string{"203.0.113.7:443"}, lookup: true},
		{target: "mixed.example:443", ips: []string{"8.8.8.8", "192.168.1.7", "fd00::7", "1.1.1.1"}, direct: []string{"192.168.1.7:443", "[fd00::7]:443"}, lookup: true},
		{target: "remote.example:443", ips: []string{"1.1.1.1", "2606:4700:4700::1111"}, proxy: true, lookup: true},
		{target: "remote-only.invalid:443", proxy: true, lookup: true},
		{target: "8.8.8.8:443", proxy: true},
	} {
		t.Run(tc.target, func(t *testing.T) {
			var directCalls []string
			var proxyCalls, lookups int
			failed := errors.New("connection unavailable")
			direct := DialContextFunc(func(_ context.Context, _, target string) (net.Conn, error) {
				directCalls = append(directCalls, target)
				return nil, failed
			})
			proxy := DialContextFunc(func(_ context.Context, _, target string) (net.Conn, error) {
				proxyCalls++
				if target != tc.target {
					t.Errorf("proxy-side DNS target changed: %s", target)
				}
				return nil, failed
			})
			lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
				lookups++
				if lookups > 1 {
					t.Error("re-resolved a pinned destination")
				}
				var ips []netip.Addr
				for _, ip := range tc.ips {
					ips = append(ips, netip.MustParseAddr(ip))
				}
				if len(ips) == 0 {
					return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
				}
				return ips, nil
			}
			dial := bypassLocal(direct, proxy, lookup, map[netip.Addr]bool{netip.MustParseAddr("203.0.113.7"): true})
			if _, err := dial(context.Background(), "tcp", tc.target); !errors.Is(err, failed) {
				t.Fatalf("route failure lost: %v", err)
			}
			wantProxy, wantLookups := 0, 0
			if tc.proxy {
				wantProxy = 1
			}
			if tc.lookup {
				wantLookups = 1
			}
			if !reflect.DeepEqual(directCalls, tc.direct) || proxyCalls != wantProxy || lookups != wantLookups {
				t.Fatalf("route mismatch: direct=%v proxy=%d DNS=%d", directCalls, proxyCalls, lookups)
			}
		})
	}
}

func TestLocalDNSBypassPreservesHTTPSAuthority(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Host, "example.com:") || r.TLS.ServerName != "example.com" || r.RequestURI != "/rpc?x=a%2fb" {
			t.Errorf("local routing altered TLS/HTTP authority: %s %s %s", r.Host, r.TLS.ServerName, r.RequestURI)
		}
		fmt.Fprint(w, "local")
	}))
	defer origin.Close()
	u, _ := url.Parse(origin.URL)
	var lookups int
	dial := bypassLocal(directDialer(), func(context.Context, string, string) (net.Conn, error) {
		t.Error("private DNS result reached program proxy")
		return nil, errors.New("must not proxy")
	}, func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}, nil)
	client := Client(time.Second, dial)
	defer client.CloseIdleConnections()
	client.Transport.(*http.Transport).TLSClientConfig = origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	resp, err := client.Get("https://example.com:" + u.Port() + "/rpc?x=a%2fb")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "local" || lookups != 1 {
		t.Fatalf("local HTTPS: body=%s DNS=%d", body, lookups)
	}
}

func TestProgramProxyIsNeverContactedForLoopback(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "local") }))
	defer origin.Close()
	u, _ := url.Parse(origin.URL)
	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			p := testutil.NewProxy(t, scheme, func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("local requests must not reach proxy")
			})
			endpoint, _ := url.Parse(p.URL)
			dial, err := NewDialer(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			client := Client(time.Second, dial)
			defer client.CloseIdleConnections()
			for _, host := range []string{"127.0.0.1", "localhost", "LOCALHOST.", "assets.localhost"} {
				resp, err := client.Get("http://" + net.JoinHostPort(host, u.Port()))
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if string(body) != "local" || len(p.Requests) != 0 {
					t.Fatalf("loopback used %s proxy: body=%s requests=%d", scheme, body, len(p.Requests))
				}
			}
		})
	}
}

func TestLocalDNSLookupCancellationDoesNotChangeRoute(t *testing.T) {
	dial := bypassLocal(func(context.Context, string, string) (net.Conn, error) {
		t.Error("direct connection after DNS cancellation")
		return nil, nil
	}, func(context.Context, string, string) (net.Conn, error) {
		t.Error("proxy connection after DNS cancellation")
		return nil, nil
	}, func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := dial(ctx, "tcp", "intranet.example:80"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost DNS cancellation: %v", err)
	}
}
