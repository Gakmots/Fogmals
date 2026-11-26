package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"dwebproxy/internal/config"
)

func TestNextHopPreservesExactHTTPURL(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.RequestURI)
	}))
	defer up.Close()
	c := httpConfig()
	c.TONProxy, c.FallbackProxy = up.URL, up.URL
	h, _ := newHandler(t, c)
	entry := httptest.NewServer(h)
	defer entry.Close()
	address, _ := url.Parse(entry.URL)
	for _, target := range []string{
		"http://Example.com", "http://Example.com?", "HTTP://Example.com:80/?",
		"http://Example.com:8080//a/./b/../c%2fD?b=2&a=1&a=%41&x=a;b&bad=%zz&empty=&plus=a+b&space=%20&slash=%2f",
		"http://Example.ton:80/a%2Fb/../%252e?x=a;b&bad=%zz&x=2&x=%32",
		"http://[2001:db8::1]:8080?b=2&a=1", "http://Example.ton?",
	} {
		t.Run(target, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", address.Host, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			parsed, err := url.Parse(target)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target, parsed.Host)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != 200 || string(body) != target {
				t.Fatalf("%d %q: %v", resp.StatusCode, body, err)
			}
		})
	}
}

func TestForwardedCachePolicyIsUnchanged(t *testing.T) {
	for _, host := range []string{"example.ton", "example.com"} {
		for _, policy := range [][]string{nil, {"private", "max-age=600"}} {
			t.Run(host+strings.Join(policy, ","), func(t *testing.T) {
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for _, v := range policy {
						w.Header().Add("Cache-Control", v)
					}
					io.WriteString(w, "ok")
				}))
				defer up.Close()
				c := httpConfig()
				c.TONProxy, c.FallbackProxy = up.URL, up.URL
				h, _ := newHandler(t, c)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest("GET", "http://"+host+"/", nil))
				if w.Code != 200 || !reflect.DeepEqual(w.Header().Values("Cache-Control"), policy) {
					t.Fatalf("%d %v", w.Code, w.Header())
				}
			})
		}
	}
	h, _ := newHandler(t, httpConfig())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://example.com/", nil))
	if w.Code != 403 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("proxy error: %d %v", w.Code, w.Header())
	}
}

func TestTunnelUpstreamHalfCloseKeepsClientUpload(t *testing.T) {
	received := make(chan string, 1)
	next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprint(rw, "HTTP/1.1 200 OK\r\n\r\nearly response")
		rw.Flush()
		conn.(*net.TCPConn).CloseWrite()
		b, err := io.ReadAll(rw)
		if err != nil {
			received <- "error: " + err.Error()
			return
		}
		received <- string(b)
	}))
	defer next.Close()
	c := httpConfig()
	c.FallbackProxy = next.URL
	c.HTTPS.TunnelIdleTimeout = config.Duration(time.Second)
	h, _ := newHandler(t, c)
	entry := httptest.NewServer(h)
	defer entry.Close()
	defer h.Close()
	conn, resp := rawConnect(t, entry.URL, "example.com:443")
	defer conn.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	b, err := io.ReadAll(conn)
	if err != nil || string(b) != "early response" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := io.WriteString(conn, "upload after downstream EOF"); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if got != "upload after downstream EOF" {
			t.Fatal(got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream half-close truncated upload")
	}
	waitNoTunnels(t, h)
}

func TestTONHTTPSPreservesPathAndQuery(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint(h2), func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "private, max-age=60")
				io.WriteString(w, r.RequestURI)
			}))
			defer up.Close()
			c := httpConfig()
			roots := enableHTTPS(t, &c)
			c.TONProxy = up.URL
			h, _ := newHandler(t, c)
			entry := httptest.NewServer(h)
			defer entry.Close()
			defer h.Close()
			client := httpsClient(entry.URL, roots, h2)
			defer client.CloseIdleConnections()
			for _, path := range []string{"/a%2fb//c?x=a;b&x=%41&bad=%zz&empty=&plus=a+b", "/?"} {
				resp, err := client.Get("https://example.ton:443" + path)
				if err != nil {
					t.Fatal(err)
				}
				b, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != 200 || string(b) != "http://example.ton"+path {
					t.Fatalf("%d %q %v", resp.StatusCode, b, err)
				}
				if got := resp.Header.Values("Cache-Control"); len(got) != 1 || got[0] != "private, max-age=60" {
					t.Fatal(got)
				}
			}
		})
	}
}

func TestExactURLThroughHTTPSNextHop(t *testing.T) {
	const target = "http://Example.com?x=a;b&bad=%zz&x=%2f&x=%2F"
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.RequestURI) }))
	defer up.Close()
	c := httpConfig()
	c.FallbackProxy = up.URL
	h, _ := newHandler(t, c)
	h.fallback.transport.TLSClientConfig = up.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", target, nil))
	if w.Code != 200 || w.Body.String() != target {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
}
