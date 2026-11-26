package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"dwebproxy/internal/config"
)

func streamClient(t *testing.T, up string, h2 bool, host string, idle time.Duration) (*Handler, *http.Client, string) {
	t.Helper()
	c := httpConfig()
	c.MaxConcurrent = 2
	c.StreamIdleTimeout = config.Duration(idle)
	c.ResponseHeaderTimeout = config.Duration(5 * time.Second)
	c.IPFSGateways = []string{strings.Replace(up, "127.0.0.1", "localhost", 1)}
	c.TONProxy, c.FallbackProxy = up, up
	var client *http.Client
	scheme := "http"
	if h2 {
		roots := enableHTTPS(t, &c)
		h, _ := newHandler(t, c)
		entry := httptest.NewServer(h)
		t.Cleanup(entry.Close)
		t.Cleanup(h.Close)
		client = httpsClient(entry.URL, roots, true)
		t.Cleanup(client.CloseIdleConnections)
		return h, client, "https://" + host
	}
	h, _ := newHandler(t, c)
	entry := httptest.NewServer(h)
	t.Cleanup(entry.Close)
	u, _ := url.Parse(entry.URL)
	client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 6 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	return h, client, scheme + "://" + host
}

func TestStalledResponseReleasesRequestAdmission(t *testing.T) {
	for _, tc := range []struct {
		host string
		h2   bool
	}{
		{"example.eth", false}, {"example.eth", true}, {"example.ton", false}, {"example.com", false},
	} {
		t.Run(fmt.Sprint(tc.host, tc.h2), func(t *testing.T) {
			cancelled := make(chan struct{})
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/stall" {
					io.WriteString(w, "start")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					close(cancelled)
					return
				}
				io.WriteString(w, "fast")
			}))
			defer up.Close()
			h, client, base := streamClient(t, up.URL, tc.h2, tc.host, 200*time.Millisecond)
			resp, err := client.Get(base + "/stall")
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				t.Fatal("stalled body ended successfully")
			}
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("idle stream did not cancel upstream")
			}
			deadline := time.Now().Add(time.Second)
			for len(h.limit) != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if len(h.limit) != 0 {
				t.Fatal("idle stream retained request admission")
			}
			resp, err = client.Get(base + "/fast")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != 200 || string(b) != "fast" {
				t.Fatalf("%d %q %v", resp.StatusCode, b, err)
			}
		})
	}
}

func TestStreamProgressAndSeparateHeaderTimeout(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint(h2), func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/headers" {
					select {
					case <-time.After(1200 * time.Millisecond):
						io.WriteString(w, "headers")
					case <-r.Context().Done():
					}
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				ticker := time.NewTicker(40 * time.Millisecond)
				defer ticker.Stop()
				for range 40 {
					select {
					case <-ticker.C:
						io.WriteString(w, "x")
						w.(http.Flusher).Flush()
					case <-r.Context().Done():
						return
					}
				}
			}))
			defer up.Close()
			_, client, base := streamClient(t, up.URL, h2, "example.eth", time.Second)
			for _, path := range []string{"/headers", "/progress"} {
				resp, err := client.Get(base + path)
				if err != nil {
					t.Fatal(err)
				}
				b, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				want := "headers"
				if path == "/progress" {
					want = strings.Repeat("x", 40)
				}
				if err != nil || string(b) != want {
					t.Fatalf("%s: %q %v", path, b, err)
				}
			}
		})
	}
}

func TestSlowDownstreamWriteExpires(t *testing.T) {
	stopped := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(stopped)
		data := make([]byte, 64<<10)
		for {
			if _, err := w.Write(data); err != nil {
				return
			}
			if r.Context().Err() != nil {
				return
			}
		}
	}))
	defer up.Close()
	c := httpConfig()
	c.StreamIdleTimeout = config.Duration(200 * time.Millisecond)
	c.IPFSGateways = []string{strings.Replace(up.URL, "127.0.0.1", "localhost", 1)}
	h, _ := newHandler(t, c)
	entry := httptest.NewServer(h)
	defer entry.Close()
	address, _ := url.Parse(entry.URL)
	conn, err := net.DialTimeout("tcp", address.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Constrain the receive window and never consume the response.
	conn.(*net.TCPConn).SetReadBuffer(1024)
	fmt.Fprint(conn, "GET http://example.eth/slow HTTP/1.1\r\nHost: example.eth\r\n\r\n")
	select {
	case <-stopped:
	case <-time.After(4 * time.Second):
		t.Fatal("blocked downstream write did not release upstream")
	}
}

func TestIdleUploadTimesOut(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	}))
	defer up.Close()
	c := httpConfig()
	c.StreamIdleTimeout = config.Duration(200 * time.Millisecond)
	c.FallbackProxy = up.URL
	h, _ := newHandler(t, c)
	entry := httptest.NewServer(h)
	defer entry.Close()
	address, _ := url.Parse(entry.URL)
	conn, err := net.DialTimeout("tcp", address.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(conn, "POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1000000\r\n\r\nfirst bytes")
	// Waiting for a response must not leave a partial upload holding a slot.
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatal(resp.Status)
	}
}

func TestIdleH2StreamLeavesOtherStreamsUsable(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "x")
		w.(http.Flusher).Flush()
		if r.URL.Path == "/stall" {
			<-r.Context().Done()
			return
		}
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		for range 40 {
			select {
			case <-ticker.C:
				io.WriteString(w, "x")
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	}))
	defer up.Close()
	_, client, base := streamClient(t, up.URL, true, "example.eth", time.Second)
	stalled, err := client.Get(base + "/stall")
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Body.Close()
	healthy, err := client.Get(base + "/progress")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(healthy.Body)
	healthy.Body.Close()
	if err != nil || healthy.ProtoMajor != 2 || string(b) != strings.Repeat("x", 41) {
		t.Fatalf("healthy stream: %q %v", b, err)
	}
	if _, err = io.ReadAll(stalled.Body); err == nil {
		t.Fatal("idle stream did not expire")
	}
}

func TestIdleH2UploadReturns504AndLeavesClientUsable(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fast" {
			io.WriteString(w, "ok")
			return
		}
		io.Copy(io.Discard, r.Body)
	}))
	defer up.Close()
	_, client, base := streamClient(t, up.URL, true, "example.ton", 200*time.Millisecond)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	req, err := http.NewRequest(http.MethodPost, base+"/upload", reader)
	if err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	go func() { _, err := io.WriteString(writer, "first bytes"); sent <- err }()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout || resp.ProtoMajor != 2 {
		t.Fatalf("%s %s", resp.Proto, resp.Status)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	writer.Close()
	resp, err = client.Get(base + "/fast")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 || string(b) != "ok" {
		t.Fatalf("%s %q %v", resp.Status, b, err)
	}
}
