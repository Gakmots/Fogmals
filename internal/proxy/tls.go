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

func (s *httpsIngress) serveTLS(conn net.Conn, certificate *tls.Certificate, name string, h http.Handler) {
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
	listener := &singleListener{conn: secured, done: make(chan struct{})}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	server := &http.Server{
		Handler: boundTLSHandler(name, h), TLSConfig: settings, Protocols: protocols,
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

func boundTLSHandler(name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, port, err := authority(r.Host, 443)
		if err != nil || host != name || port != 443 || (r.URL.Scheme != "" && r.URL.Scheme != "https") {
			http.Error(w, "request authority differs from CONNECT", http.StatusMisdirectedRequest)
			return
		}
		if r.URL.Host != "" {
			uHost, uPort, e := authority(r.URL.Host, 443)
			if e != nil || uHost != name || uPort != 443 {
				http.Error(w, "URL authority differs from CONNECT", 421)
				return
			}
		}
		if r.Method == http.MethodConnect {
			http.Error(w, "nested CONNECT is not supported", http.StatusMethodNotAllowed)
			return
		}
		r = r.Clone(context.WithValue(r.Context(), tlsAuthorityKey{}, name))
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
		next.ServeHTTP(w, r)
	})
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
