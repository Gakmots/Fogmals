package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dwebproxy/internal/config"
	"dwebproxy/internal/testutil"

	"github.com/things-go/go-socks5/statute"
	xproxy "golang.org/x/net/proxy"
)

func socksEntry(t *testing.T, h *Handler) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.ServeSOCKS5(l) }()
	t.Cleanup(func() {
		l.Close()
		h.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("SOCKS ingress did not stop")
		}
		waitNoTunnels(t, h)
	})
	return l.Addr().String()
}

func socksDialer(t *testing.T, address string) xproxy.ContextDialer {
	t.Helper()
	d, err := xproxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return d.(xproxy.ContextDialer)
}

func socksClient(t *testing.T, entry string, roots *x509.CertPool, h2 bool) *http.Client {
	t.Helper()
	tr := &http.Transport{DialContext: socksDialer(t, entry).DialContext, TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: h2}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// A real SOCKS server maps every requested remote name to an offline origin.
// Recording an unresolvable .invalid/.ton name proves it arrived without DNS.
func socksNextHop(t *testing.T, origin string) (string, <-chan string) {
	t.Helper()
	next := testutil.NewProxy(t, "socks5", func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, origin)
	})
	return next.URL, next.Requests
}

func TestSOCKSNextHopPreservesTONAndFallbackRequests(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if r.Method != "POST" || string(body) != "payload" || r.Header.Get("Authorization") != "Bearer site" || r.Header.Get("Cookie") != "session=ok" || r.Header.Get("Proxy-Authorization") != "" {
					t.Errorf("request lost or leaked credentials: %s %q %v", r.Method, body, r.Header)
				}
				w.Header().Set("Cache-Control", "max-age=123")
				fmt.Fprintf(w, "%s %s", r.Host, r.RequestURI)
			}))
			defer origin.Close()
			u, _ := url.Parse(origin.URL)
			next, targets := socksNextHop(t, u.Host)
			next = strings.Replace(next, "socks5:", scheme+":", 1)
			c := httpConfig()
			c.TONProxy, c.FallbackProxy = next, next
			h, resolver := newHandler(t, c)
			for _, host := range []string{"alice.ton", "remote.invalid:8088"} {
				for _, path := range []string{"/a%2fb/100%25?x=1&x=2;z=3&bad=%zz&plus=+&esc=%2f", "/?"} {
					r := httptest.NewRequest("POST", "http://"+host+path, strings.NewReader("payload"))
					r.Header.Set("Authorization", "Bearer site")
					r.Header.Set("Cookie", "session=ok")
					r.Header.Set("Proxy-Authorization", "private")
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					if w.Code != 200 || w.Body.String() != host+" "+path || w.Header().Get("Cache-Control") != "max-age=123" {
						t.Fatalf("SOCKS forwarding: %d %q %v", w.Code, w.Body.String(), w.Header())
					}
				}
			}
			for _, want := range []string{"alice.ton:80", "remote.invalid:8088"} {
				select {
				case got := <-targets:
					if got != want {
						t.Fatalf("SOCKS target=%q, want %q", got, want)
					}
				case <-time.After(time.Second):
					t.Fatal("next hop never received remote name")
				}
			}
			if resolver.calls.Load() != 0 {
				t.Fatal("TON/fallback used the chain resolver")
			}
		})
	}
}

func TestSOCKSIngressWeb3HTTPAndHTTPS(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Host, ".ipfs.localhost:") || r.RequestURI != "/asset?x=1" {
			t.Errorf("gateway target: %s %s", r.Host, r.RequestURI)
		}
		if r.Header.Get("Range") == "bytes=0-3" {
			w.WriteHeader(206)
		}
		io.WriteString(w, "data")
	}))
	defer up.Close()
	c := config.Default()
	c.ListenProtocol = "socks5"
	roots := enableHTTPS(t, &c)
	c.IPFSGateways = []string{strings.Replace(up.URL, "127.0.0.1", "localhost", 1)}
	h, _ := newHandler(t, c)
	entry := socksEntry(t, h)
	for _, h2 := range []bool{false, true} {
		client := socksClient(t, entry, roots, h2)
		for _, scheme := range []string{"http", "https"} {
			for _, host := range []string{"example.eth", "example.sns"} {
				r, _ := http.NewRequest("GET", scheme+"://"+host+"/asset?x=1", nil)
				r.Header.Set("Range", "bytes=0-3")
				resp, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				wantProto := 1
				if scheme == "https" && h2 {
					wantProto = 2
				}
				if resp.StatusCode != 206 || string(body) != "data" || resp.ProtoMajor != wantProto {
					t.Fatalf("%s: %s %s %q", r.URL, resp.Status, resp.Proto, body)
				}
			}
		}
	}
}

func TestSOCKSIngressTONAndFallbackHTTPNextHops(t *testing.T) {
	for _, socksNext := range []bool{false, true} {
		t.Run(fmt.Sprint("socks-next=", socksNext), func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.RequestURI, "/a%2fb?x=1;x=2&bad=%zz") {
					t.Errorf("request target=%q", r.RequestURI)
				}
				fmt.Fprint(w, r.Host)
			}))
			defer up.Close()
			c := config.Default()
			roots := enableHTTPS(t, &c)
			c.TONProxy, c.FallbackProxy = up.URL, up.URL
			if socksNext {
				u, _ := url.Parse(up.URL)
				next, _ := socksNextHop(t, u.Host)
				c.TONProxy, c.FallbackProxy = next, next
			}
			h, resolver := newHandler(t, c)
			client := socksClient(t, socksEntry(t, h), roots, true)
			for _, target := range []string{"http://example.ton", "https://example.ton", "http://remote.invalid"} {
				resp, err := client.Get(target + "/a%2fb?x=1;x=2&bad=%zz")
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 || string(body) != strings.Split(target, "://")[1] {
					t.Fatalf("%s: %s %q", target, resp.Status, body)
				}
			}
			if resolver.calls.Load() != 0 {
				t.Fatal("next-hop HTTP routes contacted chain resolver")
			}
		})
	}
}

func TestSOCKSFallbackHTTPSRemainsEndToEnd(t *testing.T) {
	for _, ingress := range []string{"http", "socks5"} {
		t.Run(ingress, func(t *testing.T) {
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "origin") }))
			origin.EnableHTTP2 = true
			origin.StartTLS()
			defer origin.Close()
			u, _ := url.Parse(origin.URL)
			next, targets := socksNextHop(t, u.Host)
			c := httpConfig()
			c.HTTPS.CACert, c.HTTPS.CAKey = "", ""
			c.FallbackProxy = next
			port, _ := strconv.Atoi(u.Port())
			c.HTTPS.ConnectPorts = append(c.HTTPS.ConnectPorts, port)
			h, resolver := newHandler(t, c)
			roots := origin.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
			var client *http.Client
			if ingress == "http" {
				entry := httptest.NewServer(h)
				defer entry.Close()
				client = httpsClient(entry.URL, roots, true)
			} else {
				client = socksClient(t, socksEntry(t, h), roots, true)
			}
			defer client.CloseIdleConnections()
			resp, err := client.Get(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "origin" || resp.ProtoMajor != 2 || !bytes.Equal(resp.TLS.PeerCertificates[0].Raw, origin.Certificate().Raw) {
				t.Fatal("SOCKS next hop did not preserve end-to-end TLS/h2")
			}
			if resolver.calls.Load() != 0 || h.connect.ca != nil {
				t.Fatal("ordinary TLS used Web3 resolver or CA")
			}
			if got := <-targets; got != u.Host {
				t.Fatalf("tunnel target=%s", got)
			}
		})
	}
}

func TestSOCKSIngressAuthorityAndDisabledHTTPS(t *testing.T) {
	c := httpConfig()
	// Neither disabled Web3 HTTPS nor a forbidden port may contact this hop.
	c.FallbackProxy = "http://127.0.0.1:1"
	h, resolver := newHandler(t, c)
	entry := socksEntry(t, h)
	dialer := socksDialer(t, entry)
	for _, target := range []string{"example.eth:443", "example.sns:443", "example.ton:443", "remote.invalid:22"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := dialer.DialContext(ctx, "tcp", target)
		cancel()
		if err == nil {
			conn.Close()
			t.Fatalf("accepted forbidden SOCKS destination %s", target)
		}
		if !strings.Contains(err.Error(), "connection not allowed by ruleset") {
			t.Fatalf("%s did not fail at policy boundary: %v", target, err)
		}
	}
	for _, request := range []string{
		"GET / HTTP/1.1\r\nHost: other.eth\r\n\r\n",
		"GET http://other.eth/ HTTP/1.1\r\nHost: example.eth\r\n\r\n",
		"GET https://example.eth/ HTTP/1.1\r\nHost: example.eth\r\n\r\n",
	} {
		conn, err := dialer.DialContext(context.Background(), "tcp", "example.eth:80")
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		fmt.Fprint(conn, request)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		conn.Close()
		if resp.StatusCode != 421 || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("authority escaped binding: %s %v", resp.Status, resp.Header)
		}
	}
	if resolver.calls.Load() != 0 {
		t.Fatal("rejected connections reached resolver")
	}
}

func TestSOCKSAdmissionTimeoutAndShutdown(t *testing.T) {
	c := httpConfig()
	c.HTTPS.MaxTunnels = 1
	c.HTTPS.HandshakeTimeout = config.Duration(200 * time.Millisecond)
	h, _ := newHandler(t, c)
	entry := socksEntry(t, h)
	first, err := net.Dial("tcp", entry)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	// Complete greeting so admission is known to have happened.
	fmt.Fprint(first, "\x05\x01\x00")
	greeting := make([]byte, 2)
	first.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(first, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 0}) {
		t.Fatalf("greeting: %v %v", greeting, err)
	}
	second, err := net.Dial("tcp", entry)
	if err != nil {
		t.Fatal(err)
	}
	second.SetDeadline(time.Now().Add(time.Second))
	defer second.Close()
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("over-capacity connection stayed open")
	}
	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("incomplete SOCKS request escaped handshake deadline")
	}
	waitNoTunnels(t, h)
	third, err := net.Dial("tcp", entry)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	fmt.Fprint(third, "\x05\x01\x00")
	third.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(third, greeting); err != nil {
		t.Fatal(err)
	}
	h.Close()
	if _, err := third.Read(make([]byte, 1)); err == nil {
		t.Fatal("shutdown left negotiating session open")
	}
	waitNoTunnels(t, h)
}

func TestSOCKSUnsupportedCommandsAndBufferedHTTP(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "site") }))
	defer up.Close()
	c := httpConfig()
	c.FallbackProxy = up.URL
	h, _ := newHandler(t, c)
	entry := socksEntry(t, h)
	for _, command := range []byte{statute.CommandBind, statute.CommandAssociate, statute.CommandConnect} {
		conn, err := net.Dial("tcp", entry)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		fmt.Fprint(conn, "\x05\x01\x00")
		greeting := make([]byte, 2)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			t.Fatal(err)
		}
		host := "site.invalid"
		request := append([]byte{5, command, 0, 3, byte(len(host))}, []byte(host)...)
		request = append(request, 0, 80)
		if command == statute.CommandConnect {
			// Early HTTP bytes after CONNECT must survive the library's buffering.
			request = append(request, []byte("GET / HTTP/1.1\r\nHost: site.invalid\r\n\r\nGET / HTTP/1.1\r\nHost: other.invalid\r\nConnection: close\r\n\r\n")...)
		}
		conn.Write(request)
		reader := bufio.NewReader(conn)
		reply, err := statute.ParseReply(reader)
		if err != nil {
			t.Fatal(err)
		}
		if command != statute.CommandConnect {
			if reply.Response != statute.RepCommandNotSupported {
				t.Fatalf("unsupported command %d: %+v", command, reply)
			}
		} else {
			if reply.Response != statute.RepSuccess {
				t.Fatalf("CONNECT: %+v", reply)
			}
			for _, status := range []int{200, 421} {
				resp, err := http.ReadResponse(reader, nil)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != status {
					t.Fatalf("buffered request: %s, want %d", resp.Status, status)
				}
			}
		}
		conn.Close()
	}
}

func TestSOCKSNextHopTimeoutsUseSharedStatus(t *testing.T) {
	// An HTTP listener never replies to a SOCKS greeting, stalling negotiation.
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected HTTP request") }))
	defer stalled.Close()
	c := httpConfig()
	c.TONProxy = strings.Replace(stalled.URL, "http:", "socks5:", 1)
	c.FallbackProxy = c.TONProxy
	c.HTTPS.HandshakeTimeout = config.Duration(100 * time.Millisecond)
	h, _ := newHandler(t, c)
	h.ton.transport.TLSHandshakeTimeout = 100 * time.Millisecond
	h.fallback.transport.TLSHandshakeTimeout = 100 * time.Millisecond
	for _, host := range []string{"alice.ton", "remote.invalid"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "http://"+host+"/", nil))
		if w.Code != 504 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s stalled negotiation: %d %s", host, w.Code, w.Body.String())
		}
	}
	entry := httptest.NewServer(h)
	defer entry.Close()
	conn, resp := rawConnect(t, entry.URL, "remote.invalid:443")
	resp.Body.Close()
	conn.Close()
	if resp.StatusCode != 504 {
		t.Fatalf("CONNECT timeout: %s", resp.Status)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, err := socksDialer(t, socksEntry(t, h)).DialContext(ctx, "tcp", "remote.invalid:443"); err == nil {
		conn.Close()
		t.Fatal("stalled next hop succeeded")
	} else if !strings.Contains(err.Error(), "TTL expired") {
		t.Fatalf("SOCKS timeout response lost: %v", err)
	}
}

func TestSOCKSFailedNextHopNeverDialsOrigin(t *testing.T) {
	var calls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer origin.Close()
	closed := httptest.NewServer(nil)
	closed.Close()
	c := httpConfig()
	c.FallbackProxy = strings.Replace(closed.URL, "http:", "socks5:", 1)
	h, _ := newHandler(t, c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", origin.URL, strings.NewReader("payload")))
	if w.Code != 502 || calls.Load() != 0 {
		t.Fatalf("SOCKS failure escaped next hop: status=%d origin calls=%d", w.Code, calls.Load())
	}
}
