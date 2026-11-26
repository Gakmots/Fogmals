package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"dwebproxy/internal/config"
)

func TestWeb3HTTPSDisabledDoesNotFallThrough(t *testing.T) {
	var calls atomic.Int32
	next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.Error(w, "unexpected next hop", 502) }))
	defer next.Close()
	c := httpConfig()
	c.HTTPS.CACert, c.HTTPS.CAKey = "", ""
	c.TONProxy, c.FallbackProxy = next.URL, next.URL
	h, resolver := newHandler(t, c)
	entry := httptest.NewServer(h)
	defer entry.Close()
	defer h.Close()
	for _, tc := range []struct {
		target string
		status int
	}{
		{"example.eth:443", 501}, {"example.sns:443", 501}, {"example.ton:443", 501},
		{"example.ETH.:443", 501}, {"bad..eth:443", 400}, {"example.com:444", 403},
	} {
		conn, resp := rawConnect(t, entry.URL, tc.target)
		resp.Body.Close()
		conn.Close()
		if resp.StatusCode != tc.status {
			t.Errorf("%s: %d", tc.target, resp.StatusCode)
		}
	}
	if h.connect.ca != nil || calls.Load() != 0 || resolver.calls.Load() != 0 {
		t.Fatalf("disabled Web3 HTTPS escaped its route: CA=%v next-hop=%d resolver=%d", h.connect.ca, calls.Load(), resolver.calls.Load())
	}
}

func TestFallbackConnectLifecycleWithWeb3Disabled(t *testing.T) {
	var calls atomic.Int32
	next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(rw, "HTTP/1.1 200 OK\r\n\r\nready\n")
		if err := rw.Flush(); err != nil {
			return
		}
		io.Copy(io.Discard, rw)
	}))
	defer next.Close()
	c := httpConfig()
	c.HTTPS.CACert, c.HTTPS.CAKey = "", ""
	c.HTTPS.MaxTunnels = 1
	c.HTTPS.TunnelIdleTimeout = config.Duration(2 * time.Second)
	c.FallbackProxy = next.URL
	h, _ := newHandler(t, c)
	entry := httptest.NewServer(h)
	defer entry.Close()
	defer h.Close()
	first, resp := rawConnect(t, entry.URL, "example.com:443")
	defer first.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	if _, err := io.ReadFull(first, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	second, resp := rawConnect(t, entry.URL, "other.example:443")
	resp.Body.Close()
	second.Close()
	if resp.StatusCode != 503 || calls.Load() != 1 {
		t.Fatalf("capacity: status=%d next-hop=%d", resp.StatusCode, calls.Load())
	}
	first.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle ordinary tunnel did not expire")
	}
	waitNoTunnels(t, h)
	third, resp := rawConnect(t, entry.URL, "example.com:443")
	defer third.Close()
	if resp.StatusCode != 200 {
		t.Fatal("idle tunnel did not release capacity:", resp.Status)
	}
	if _, err := io.ReadFull(third, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	h.Close()
	third.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := third.Read(make([]byte, 1)); err == nil {
		t.Fatal("shutdown left ordinary tunnel open")
	}
	waitNoTunnels(t, h)
}
