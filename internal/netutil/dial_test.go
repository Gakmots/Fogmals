package netutil

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dwebproxy/internal/testutil"
)

func TestProgramProxyHTTPAndSOCKSRemoteTargets(t *testing.T) {
	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI != "/rpc?token=a%2fb" || r.Host != "rpc.invalid" {
					t.Errorf("RPC destination changed: %s %s", r.Host, r.RequestURI)
				}
				io.WriteString(w, "response")
			}))
			defer origin.Close()
			u, _ := url.Parse(origin.URL)
			p := testutil.NewProxy(t, scheme, func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, u.Host)
			})
			endpoint, _ := url.Parse(p.URL)
			dial, err := NewDialer(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			if scheme == "https" {
				// A private test CA substitutes for a publicly trusted proxy cert.
				// Production NewDialer uses the normal system trust store.
				dial = func(ctx context.Context, network, address string) (net.Conn, error) {
					return HTTPConnect(ctx, endpoint, address, directDialer(), &tls.Config{RootCAs: p.Roots})
				}
			}
			client := Client(2*time.Second, dial)
			defer client.CloseIdleConnections()
			tr := client.Transport.(*http.Transport)
			tr.TLSClientConfig = origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			tr.TLSClientConfig.ServerName = "example.com"
			resp, err := client.Get("https://rpc.invalid/rpc?token=a%2fb")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "response" {
				t.Fatalf("unexpected body: %s", body)
			}
			select {
			case address := <-p.Requests:
				if address != "rpc.invalid:443" {
					t.Fatalf("remote target=%q", address)
				}
			default:
				t.Fatal("request bypassed the program proxy")
			}
		})
	}
}

func TestProgramProxyDisabledIgnoresEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "direct") }))
	defer origin.Close()
	dial, _ := NewDialer(nil)
	client := Client(time.Second, dial)
	defer client.CloseIdleConnections()
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if body, _ := io.ReadAll(resp.Body); string(body) != "direct" {
		t.Fatalf("disabled proxy: %q", body)
	}
}

func TestProgramProxyFailureNeverDialsOrigin(t *testing.T) {
	var calls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer origin.Close()
	closed := httptest.NewServer(nil)
	closed.Close()
	for _, scheme := range []string{"http", "https", "socks5"} {
		u, _ := url.Parse(strings.Replace(closed.URL, "http:", scheme+":", 1))
		dial, _ := NewDialer(u)
		client := Client(time.Second, dial)
		if resp, err := client.Get(strings.Replace(origin.URL, "127.0.0.1", "origin.invalid", 1)); err == nil {
			resp.Body.Close()
			t.Fatalf("unreachable %s proxy bypassed", scheme)
		}
		client.CloseIdleConnections()
	}
	if calls.Load() != 0 {
		t.Fatal("failed proxy led to direct origin traffic")
	}
}

func TestProgramProxyNegotiationRespectsCancellation(t *testing.T) {
	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
			defer stalled.Close()
			u, _ := url.Parse(strings.Replace(stalled.URL, "http:", scheme+":", 1))
			dial, _ := NewDialer(u)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			conn, err := dial(ctx, "tcp", "rpc.invalid:443")
			if err == nil {
				conn.Close()
				t.Fatal("stalled negotiation succeeded")
			}
			// The socket deadline may fire just before the context timer; either
			// error must retain timeout semantics across the proxy adapter.
			if ProxyErrorStatus(ctx, err) != 504 {
				t.Fatalf("lost timeout classification: %v", err)
			}
			canceled, stop := context.WithCancel(context.Background())
			stop()
			if conn, err := dial(canceled, "tcp", "rpc.invalid:443"); !errors.Is(err, context.Canceled) {
				if conn != nil {
					conn.Close()
				}
				t.Fatalf("lost explicit cancellation: %v", err)
			}
		})
	}
}

func TestProgramProxyDoesNotTrustUnknownHTTPSCertificate(t *testing.T) {
	p := testutil.NewProxy(t, "https", directDialer())
	u, _ := url.Parse(p.URL)
	dial, _ := NewDialer(u)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if conn, err := dial(ctx, "tcp", "rpc.invalid:443"); err == nil {
		conn.Close()
		t.Fatal("untrusted HTTPS proxy certificate accepted")
	}
}

func TestSOCKSProgramProxyPreservesHalfClose(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		body, _ := io.ReadAll(conn)
		conn.Write(append([]byte("reply:"), body...))
	}()
	p := testutil.NewProxy(t, "socks5", func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, l.Addr().String())
	})
	u, _ := url.Parse(p.URL)
	dial, _ := NewDialer(u)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", "target.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	conn.Write([]byte("payload"))
	writer, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("SOCKS adapter hid the TCP half-close capability")
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(conn)
	if err != nil || string(body) != "reply:payload" {
		t.Fatalf("SOCKS half-close lost final response: %q %v", body, err)
	}
	<-done
}
