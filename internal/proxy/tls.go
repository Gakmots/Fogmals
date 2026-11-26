package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func (s *connectIngress) serveTLS(conn net.Conn, certificate *tls.Certificate, name string, h http.Handler) {
	settings := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}, Certificates: []tls.Certificate{*certificate}}
	settings.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if strings.TrimSuffix(strings.ToLower(hello.ServerName), ".") != name {
			return nil, fmt.Errorf("TLS SNI differs from CONNECT authority")
		}
		return nil, nil
	}
	secured := tls.Server(conn, settings)
	ctx, cancel := context.WithTimeout(s.root, time.Duration(s.settings.HandshakeTimeout))
	err := secured.HandshakeContext(ctx)
	cancel()
	if err != nil {
		return
	}
	secured.SetDeadline(time.Time{})
	s.serveHTTPConnection(secured, boundRequestHandler(name, 443, "https", h), settings)
}

// Both plain SOCKS5 HTTP sessions and locally terminated TLS use net/http.
func (s *connectIngress) serveHTTPConnection(conn net.Conn, handler http.Handler, settings *tls.Config) {
	listener := &singleListener{conn: conn, done: make(chan struct{})}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(settings != nil)
	server := &http.Server{
		Handler: handler, TLSConfig: settings, Protocols: protocols,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: 64},
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: time.Duration(s.settings.TunnelIdleTimeout), MaxHeaderBytes: 64 << 10,
		BaseContext: func(net.Listener) context.Context { return s.root },
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				listener.Close()
			}
		},
	}
	defer server.Close()
	// The standard server handles both ALPN results and streams directly into
	// the existing handler. No response recorder or body buffering is involved.
	_ = server.Serve(listener)
}

// The second Accept waits for this connection to close, so Serve owns the
// complete session lifetime instead of returning while its handlers run.
type singleListener struct {
	conn     net.Conn
	accepted bool
	done     chan struct{}
	once     sync.Once
}

func (l *singleListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *singleListener) Close() error {
	l.once.Do(func() { close(l.done); l.conn.Close() })
	return nil
}
func (l *singleListener) Addr() net.Addr { return l.conn.LocalAddr() }
