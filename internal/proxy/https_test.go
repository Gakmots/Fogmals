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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dwebproxy/internal/certstore"
	"dwebproxy/internal/config"
)

func enableHTTPS(t *testing.T, c *config.Config) *x509.CertPool {
	t.Helper()
	dir := t.TempDir()
	c.HTTPS.Enabled = true
	c.HTTPS.CACert = filepath.Join(dir, "ca.pem")
	c.HTTPS.CAKey = filepath.Join(dir, "ca-key.pem")
	if err := certstore.Init(c.HTTPS.CACert, c.HTTPS.CAKey); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(c.HTTPS.CACert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(b) {
		t.Fatal("invalid CA")
	}
	return roots
}

func httpsClient(entry string, roots *x509.CertPool, h2 bool) *http.Client {
	u, _ := url.Parse(entry)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: h2}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestWeb3HTTPSNegotiationAndExistingHTTPUpstreams(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint("h2=", h2), func(t *testing.T) {
			content := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS != nil || r.ProtoMajor != 1 || !strings.Contains(r.Host, ".ipfs.localhost:") {
					t.Errorf("unexpected gateway connection: %s %s", r.Proto, r.Host)
				}
				if r.URL.Path == "/docs" {
					http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
					return
				}
				if r.Header.Get("Range") != "" {
					w.Header().Set("Content-Range", "bytes 0-3/100")
					w.WriteHeader(206)
				}
				io.WriteString(w, "data")
			}))
			defer content.Close()
			ton := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI != "http://example.ton/api" || r.Host != "example.ton" {
					t.Errorf("TON destination=%s Host=%s", r.RequestURI, r.Host)
				}
				body, _ := io.ReadAll(r.Body)
				if string(body) != "payload" {
					t.Errorf("TON body=%s", body)
				}
				w.Header().Set("Location", "http://example.ton/next")
				w.WriteHeader(302)
			}))
			defer ton.Close()
			c := config.Default()
			roots := enableHTTPS(t, &c)
			c.TONProxy = ton.URL
			c.IPFSGateways = []string{strings.Replace(content.URL, "127.0.0.1", "localhost", 1)}
			h, _ := newHandler(t, c)
			entry := httptest.NewServer(h)
			defer entry.Close()
			defer h.Close()
			client := httpsClient(entry.URL, roots, h2)
			defer client.CloseIdleConnections()
			for _, target := range []string{"https://example.eth/file", "https://example.sns/file"} {
				resp, err := client.Get(target)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				want := 1
				if h2 {
					want = 2
				}
				if resp.StatusCode != 200 || string(body) != "data" || resp.ProtoMajor != want {
					t.Fatalf("status=%d protocol=%s body=%s", resp.StatusCode, resp.Proto, body)
				}
				if resp.Header.Get("Cache-Control") != "no-cache" || len(resp.Header.Values("Cache-Control")) != 1 {
					t.Fatalf("duplicate or incorrect cache policy: %v", resp.Header.Values("Cache-Control"))
				}
				if h2 && resp.TLS.NegotiatedProtocol != "h2" {
					t.Fatal("h2 was not negotiated")
				}
				if err := resp.TLS.PeerCertificates[0].VerifyHostname(strings.TrimSuffix(strings.TrimPrefix(target, "https://"), "/file")); err != nil {
					t.Fatal(err)
				}
			}
			resp, err := client.Get("https://example.eth/docs")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 301 || resp.Header.Get("Location") != "https://example.eth/docs/" {
				t.Fatalf("HTTPS redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
			}
			req, _ := http.NewRequest("GET", "https://example.eth/file", nil)
			req.Header.Set("Range", "bytes=0-3")
			resp, err = client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 206 {
				t.Fatal("Range lost")
			}
			resp, err = client.Head("https://example.eth/file")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if len(body) != 0 {
				t.Fatal("HEAD body was not empty")
			}
			resp, err = client.Post("https://example.ton:443/api", "text/plain", strings.NewReader("payload"))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 302 || resp.Header.Get("Location") != "https://example.ton/next" {
				t.Fatalf("TON redirect %d %s", resp.StatusCode, resp.Header.Get("Location"))
			}
		})
	}
}

func TestH2ConcurrentStreamsAndCancellation(t *testing.T) {
	cancelled := make(chan struct{}, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "start\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			cancelled <- struct{}{}
			return
		}
		io.WriteString(w, "fast")
	}))
	defer up.Close()
	c := config.Default()
	roots := enableHTTPS(t, &c)
	c.IPFSGateways = []string{strings.Replace(up.URL, "127.0.0.1", "localhost", 1)}
	h, _ := newHandler(t, c)
	var connections atomic.Int32
	entry := httptest.NewUnstartedServer(h)
	entry.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	entry.Start()
	defer entry.Close()
	defer h.Close()
	client := httpsClient(entry.URL, roots, true)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.eth/slow", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatal(resp.Proto)
	}
	if _, err := io.ReadFull(resp.Body, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := client.Get("https://example.eth/fast")
			if err != nil {
				t.Error(err)
				return
			}
			defer r.Body.Close()
			b, _ := io.ReadAll(r.Body)
			if r.ProtoMajor != 2 || string(b) != "fast" {
				t.Error("wrong concurrent response")
			}
		}()
	}
	wg.Wait()
	cancel()
	resp.Body.Close()
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled stream did not cancel its gateway request")
	}
	resp, err = client.Get("https://example.eth/fast")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if connections.Load() != 1 {
		t.Fatalf("stream cancellation closed the shared connection: %d", connections.Load())
	}
}

func rawConnect(t *testing.T, entry, target string) (net.Conn, *http.Response) {
	t.Helper()
	u, _ := url.Parse(entry)
	conn, err := net.DialTimeout("tcp", u.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	return &bufferedConn{Conn: conn, reader: reader}, resp
}

func TestHTTPSAuthorityAndTrustBoundaries(t *testing.T) {
	c := config.Default()
	roots := enableHTTPS(t, &c)
	h, resolver := newHandler(t, c)
	entry := httptest.NewServer(h)
	defer entry.Close()
	defer h.Close()
	for _, h2 := range []bool{false, true} {
		client := httpsClient(entry.URL, roots, h2)
		req, _ := http.NewRequest("GET", "https://example.eth/", nil)
		req.Host = "example.com"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 421 {
			t.Fatalf("authority mismatch accepted: %d", resp.StatusCode)
		}
		client.CloseIdleConnections()
	}
	conn, resp := rawConnect(t, entry.URL, "example.eth:443")
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	secured := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "other.eth"})
	if err := secured.Handshake(); err == nil {
		t.Fatal("mismatched SNI accepted")
	}
	conn.Close()
	client := httpsClient(entry.URL, x509.NewCertPool(), true)
	if resp, err := client.Get("https://example.eth/"); err == nil {
		resp.Body.Close()
		t.Fatal("untrusted CA accepted")
	}
	client.CloseIdleConnections()
	for _, tc := range []struct {
		target string
		status int
	}{{"example.eth:80", 403}, {"example.com:443", 503}, {"example.ton:443", 503}} {
		conn, resp := rawConnect(t, entry.URL, tc.target)
		if resp.StatusCode != tc.status {
			t.Errorf("%s: %d", tc.target, resp.StatusCode)
		}
		resp.Body.Close()
		conn.Close()
	}
	if resolver.calls.Load() != 0 {
		t.Fatal("rejected HTTPS reached resolver")
	}
}

// The mock next hop alone resolves/dials the origin. This verifies that the
// local proxy sends CONNECT and preserves the remote certificate unchanged.
func TestOrdinaryHTTPSUsesFallbackWithoutInterception(t *testing.T) {
	for _, secureProxy := range []bool{false, true} {
		t.Run(fmt.Sprint("secure-proxy=", secureProxy), func(t *testing.T) {
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin") }))
			origin.EnableHTTP2 = true
			origin.StartTLS()
			defer origin.Close()
			originURL, _ := url.Parse(origin.URL)
			var calls atomic.Int32
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "CONNECT" || r.Host != originURL.Host {
					t.Errorf("next hop: %s %s", r.Method, r.Host)
					http.Error(w, "bad target", 400)
					return
				}
				if r.Header.Get("Proxy-Authorization") != "" {
					t.Error("client proxy credentials leaked")
				}
				up, err := net.Dial("tcp", originURL.Host)
				if err != nil {
					t.Error(err)
					return
				}
				client, buf, err := w.(http.Hijacker).Hijack()
				if err != nil {
					up.Close()
					return
				}
				fmt.Fprint(buf, "HTTP/1.1 200 OK\r\n\r\n")
				buf.Flush()
				go func() { io.Copy(up, buf); up.Close() }()
				io.Copy(client, up)
				client.Close()
				up.Close()
			})
			next := httptest.NewUnstartedServer(nextHandler)
			if secureProxy {
				next.StartTLS()
			} else {
				next.Start()
			}
			defer next.Close()
			c := config.Default()
			enableHTTPS(t, &c)
			p, _ := strconv.Atoi(originURL.Port())
			c.HTTPS.ConnectPorts = append(c.HTTPS.ConnectPorts, p)
			c.FallbackProxy = next.URL
			h, resolver := newHandler(t, c)
			if secureProxy {
				h.fallback.transport.TLSClientConfig = next.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			}
			entry := httptest.NewServer(h)
			defer entry.Close()
			defer h.Close()
			client := httpsClient(entry.URL, origin.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, true)
			defer client.CloseIdleConnections()
			resp, err := client.Get(origin.URL + "/file")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "origin" || resp.ProtoMajor != 2 || !bytes.Equal(resp.TLS.PeerCertificates[0].Raw, origin.Certificate().Raw) {
				t.Fatal("ordinary HTTPS was not an unchanged TLS tunnel")
			}
			if calls.Load() != 1 || resolver.calls.Load() != 0 {
				t.Fatal("ordinary HTTPS routing is incorrect")
			}
		})
	}
}

func waitNoTunnels(t *testing.T, h *Handler) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.https.mu.Lock()
		n := len(h.https.connections)
		h.https.mu.Unlock()
		if n == 0 && len(h.https.slots) == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("HTTPS session did not release its connection or slot")
}

func TestHandshakeTimeoutLimitAndShutdown(t *testing.T) {
	c := config.Default()
	enableHTTPS(t, &c)
	c.HTTPS.MaxTunnels = 1
	c.HTTPS.HandshakeTimeout = config.Duration(300 * time.Millisecond)
	h, _ := newHandler(t, c)
	entry := httptest.NewServer(h)
	defer entry.Close()
	defer h.Close()
	conn, resp := rawConnect(t, entry.URL, "example.eth:443")
	defer conn.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	other, resp := rawConnect(t, entry.URL, "example.eth:443")
	other.Close()
	if resp.StatusCode != 503 {
		t.Fatal("tunnel limit not enforced")
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("unstarted TLS handshake did not expire")
	}
	waitNoTunnels(t, h)
	conn, resp = rawConnect(t, entry.URL, "example.eth:443")
	defer conn.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	h.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("shutdown left handshake open")
	}
	waitNoTunnels(t, h)
}

func TestShutdownCancelsActiveH2Streams(t *testing.T) {
	started, cancelled := make(chan struct{}), make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "hello\n")
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer up.Close()
	c := config.Default()
	roots := enableHTTPS(t, &c)
	c.IPFSGateways = []string{strings.Replace(up.URL, "127.0.0.1", "localhost", 1)}
	h, _ := newHandler(t, c)
	entry := httptest.NewServer(h)
	defer entry.Close()
	defer h.Close()
	client := httpsClient(entry.URL, roots, true)
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://example.eth/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	<-started
	h.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel active request")
	}
	waitNoTunnels(t, h)
}

func TestFallbackTunnelFailureNeverDialsOrigin(t *testing.T) {
	var originCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { originCalls.Add(1) }))
	defer origin.Close()
	next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "CONNECT denied", http.StatusForbidden) }))
	defer next.Close()
	c := config.Default()
	enableHTTPS(t, &c)
	c.FallbackProxy = next.URL
	u, _ := url.Parse(origin.URL)
	port, _ := strconv.Atoi(u.Port())
	c.HTTPS.ConnectPorts = append(c.HTTPS.ConnectPorts, port)
	h, _ := newHandler(t, c)
	entry := httptest.NewServer(h)
	defer entry.Close()
	defer h.Close()
	conn, resp := rawConnect(t, entry.URL, u.Host)
	defer conn.Close()
	defer resp.Body.Close()
	if resp.StatusCode != 502 || originCalls.Load() != 0 {
		t.Fatal("failed fallback tunnel connected directly")
	}
	waitNoTunnels(t, h)
}

func TestTunnelBufferedBytesAndHalfClose(t *testing.T) {
	next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		// A successful CONNECT response may already contain tunnel bytes.
		fmt.Fprint(rw, "HTTP/1.1 200 OK\r\n\r\nbanner\n")
		rw.Flush()
		b, _ := io.ReadAll(rw)
		conn.Write(append([]byte("reply:"), b...))
	}))
	defer next.Close()
	c := config.Default()
	enableHTTPS(t, &c)
	c.FallbackProxy = next.URL
	h, _ := newHandler(t, c)
	entry := httptest.NewServer(h)
	defer entry.Close()
	defer h.Close()
	conn, resp := rawConnect(t, entry.URL, "example.com:443")
	defer conn.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	banner := make([]byte, 7)
	if _, err := io.ReadFull(conn, banner); err != nil || string(banner) != "banner\n" {
		t.Fatal("buffered banner lost:", err)
	}
	conn.Write([]byte("payload"))
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(conn)
	if err != nil || string(b) != "reply:payload" {
		t.Fatalf("half close lost response: %q %v", b, err)
	}
	waitNoTunnels(t, h)
}
