// Package testutil provides offline protocol fixtures shared by network tests.
package testutil

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/things-go/go-socks5"
)

type Proxy struct {
	URL      string
	Roots    *x509.CertPool
	Requests chan string
}

type remoteNames struct{}

func (remoteNames) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

// NewProxy records the actual tunnel destination and delegates dialing to the
// test. Domains and public IPs can map to loopback origins without external DNS.
func NewProxy(t testing.TB, scheme string, dial func(context.Context, string, string) (net.Conn, error)) *Proxy {
	t.Helper()
	p := &Proxy{Requests: make(chan string, 128)}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var sessions sync.WaitGroup
	connections := make(map[net.Conn]bool)
	closed := false
	track := func(c net.Conn) bool {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			c.Close()
			return false
		}
		connections[c] = true
		sessions.Add(1)
		return true
	}
	release := func(c net.Conn) {
		c.Close()
		mu.Lock()
		delete(connections, c)
		mu.Unlock()
		sessions.Done()
	}
	connect := func(network, address string) (net.Conn, error) {
		p.Requests <- address
		return dial(ctx, network, address)
	}
	var stop func()
	if scheme == "socks5" || scheme == "socks5h" {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := socks5.NewServer(socks5.WithResolver(remoteNames{}), socks5.WithDial(func(_ context.Context, network, address string) (net.Conn, error) { return connect(network, address) }))
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				if !track(c) {
					continue
				}
				go func() { defer release(c); _ = server.ServeConn(c) }()
			}
		}()
		p.URL = scheme + "://" + l.Addr().String()
		stop = func() { l.Close(); <-done }
	} else {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "CONNECT" {
				http.Error(w, "expected CONNECT", 400)
				return
			}
			upstream, err := connect("tcp", r.Host)
			if err != nil {
				http.Error(w, "unreachable", 502)
				return
			}
			defer upstream.Close()
			client, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			if !track(client) {
				return
			}
			defer release(client)
			fmt.Fprint(buffer, "HTTP/1.1 200 Connection Established\r\n\r\n")
			if buffer.Flush() != nil {
				return
			}
			done := make(chan struct{})
			go func() { io.Copy(upstream, buffer); upstream.Close(); close(done) }()
			io.Copy(client, upstream)
			client.Close()
			<-done
		}))
		if scheme == "https" {
			server.StartTLS()
			p.Roots = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
		} else {
			server.Start()
		}
		p.URL, stop = server.URL, server.Close
	}
	t.Cleanup(func() {
		cancel()
		mu.Lock()
		closed = true
		for c := range connections {
			c.Close()
		}
		mu.Unlock()
		stop()
		sessions.Wait()
	})
	return p
}
