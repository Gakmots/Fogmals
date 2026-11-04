package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"dwebproxy/internal/certstore"
	"dwebproxy/internal/config"
)

type tlsAuthorityKey struct{}

type httpsIngress struct {
	settings    config.HTTPS
	ca          *certstore.Authority
	root        context.Context
	cancel      context.CancelFunc
	slots       chan struct{}
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closed      bool
}

func newHTTPS(c config.Config) (*httpsIngress, error) {
	if !c.HTTPS.Enabled {
		return nil, nil
	}
	ca, err := certstore.Load(c.HTTPS.CACert, c.HTTPS.CAKey, c.CacheSize)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &httpsIngress{settings: c.HTTPS, ca: ca, root: ctx, cancel: cancel, slots: make(chan struct{}, c.HTTPS.MaxTunnels), connections: make(map[net.Conn]struct{})}, nil
}

func (s *httpsIngress) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		c.Close()
		return false
	}
	s.connections[c] = struct{}{}
	return true
}

func (s *httpsIngress) release(c net.Conn) {
	c.Close()
	s.mu.Lock()
	delete(s.connections, c)
	s.mu.Unlock()
}

func (s *httpsIngress) Close() {
	if s == nil {
		return
	}
	s.cancel()
	s.mu.Lock()
	s.closed = true
	connections := make([]net.Conn, 0, len(s.connections))
	for c := range s.connections {
		connections = append(connections, c)
	}
	s.mu.Unlock()
	for _, c := range connections {
		c.Close()
	}
}

func authority(raw string, defaultPort int) (string, int, error) {
	if raw == "" || strings.ContainsAny(raw, "/@?#\\\x00\r\n\t ") {
		return "", 0, fmt.Errorf("invalid authority")
	}
	u, err := url.Parse("https://" + raw)
	if err != nil || u.Host != raw || u.Hostname() == "" || u.User != nil {
		return "", 0, fmt.Errorf("invalid authority")
	}
	port := defaultPort
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid port")
		}
	}
	if strings.HasSuffix(raw, ":") {
		return "", 0, fmt.Errorf("empty port")
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), "."), port, nil
}

func (h *Handler) serveConnect(w http.ResponseWriter, r *http.Request) {
	s := h.https
	if s == nil {
		http.Error(w, "HTTPS CONNECT is disabled", http.StatusNotImplemented)
		return
	}
	if r.ProtoMajor != 1 {
		http.Error(w, "outer CONNECT requires HTTP/1.1", http.StatusHTTPVersionNotSupported)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.URL.Opaque != "" || r.URL.Scheme != "" || r.URL.Path != "" || r.URL.RawQuery != "" || r.Host != r.URL.Host {
		http.Error(w, "invalid CONNECT request", http.StatusBadRequest)
		return
	}
	name, port, err := authority(r.Host, 0)
	if err != nil || port == 0 {
		http.Error(w, "CONNECT requires host:port", http.StatusBadRequest)
		return
	}
	allowed := false
	for _, p := range s.settings.ConnectPorts {
		if port == p {
			allowed = true
		}
	}
	if !allowed {
		http.Error(w, "CONNECT port is not allowed", http.StatusForbidden)
		return
	}
	destination, err := classifyName(name)
	if err != nil {
		http.Error(w, "invalid CONNECT domain", http.StatusBadRequest)
		return
	}
	var certificate *tls.Certificate
	if destination.kind != routeFallback {
		if port != 443 {
			http.Error(w, "special domains require HTTPS port 443", http.StatusForbidden)
			return
		}
		if destination.kind == routeTON && h.ton == nil {
			http.Error(w, "TON proxy is not configured", http.StatusServiceUnavailable)
			return
		}
		certificate, err = s.ca.Certificate(destination.name)
		if err != nil {
			http.Error(w, "cannot issue domain certificate", http.StatusBadRequest)
			return
		}
	} else if h.fallback == nil {
		http.Error(w, "fallback proxy is not configured", http.StatusServiceUnavailable)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "too many HTTPS tunnels", http.StatusServiceUnavailable)
		return
	}
	// Dial the next hop before acknowledging a regular HTTPS tunnel.
	var upstream net.Conn
	if destination.kind == routeFallback {
		upstream, err = h.fallback.dialTunnel(s.root, net.JoinHostPort(name, strconv.Itoa(port)), time.Duration(s.settings.HandshakeTimeout))
		if err != nil {
			h.logger.Warn("CONNECT upstream failed", "host", r.Host, "error", err)
			http.Error(w, "fallback CONNECT unavailable", http.StatusBadGateway)
			return
		}
		if !s.track(upstream) {
			return
		}
		defer s.release(upstream)
	}
	client, buffer, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	if !s.track(client) {
		return
	}
	defer s.release(client)
	client.SetDeadline(time.Time{}) // discard the outer HTTP server's deadline
	if _, err = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = buffer.Flush(); err != nil {
		return
	}
	conn := &bufferedConn{Conn: client, reader: buffer.Reader}
	if destination.kind == routeFallback {
		relay(conn, upstream, time.Duration(s.settings.TunnelIdleTimeout))
		return
	}
	s.serveTLS(conn, certificate, destination.name, h)
}
