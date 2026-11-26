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
	"dwebproxy/internal/netutil"
)

type tlsAuthorityKey struct{}

type certificateAuthority interface {
	Certificate(string) (*tls.Certificate, error)
}

type connectIngress struct {
	settings    config.HTTPS
	ca          certificateAuthority
	root        context.Context
	cancel      context.CancelFunc
	slots       chan struct{}
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closed      bool
}

func newConnect(c config.Config) (*connectIngress, error) {
	// Every proxy instance owns CONNECT sessions. Only Web3 TLS termination
	// needs a signing authority; ordinary HTTPS always stays a byte tunnel.
	var ca certificateAuthority
	if c.HTTPS.Enabled {
		authority, err := certstore.Load(c.HTTPS.CACert, c.HTTPS.CAKey, c.CacheSize)
		if err != nil {
			return nil, err
		}
		ca = authority
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &connectIngress{settings: c.HTTPS, ca: ca, root: ctx, cancel: cancel, slots: make(chan struct{}, c.HTTPS.MaxTunnels), connections: make(map[net.Conn]struct{})}, nil
}

func (s *connectIngress) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		c.Close()
		return false
	}
	s.connections[c] = struct{}{}
	return true
}

func (s *connectIngress) release(c net.Conn) {
	c.Close()
	s.mu.Lock()
	delete(s.connections, c)
	s.mu.Unlock()
}

func (s *connectIngress) Close() {
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
	s := h.connect
	if r.ProtoMajor != 1 {
		netutil.Error(w, "outer CONNECT requires HTTP/1.1", http.StatusHTTPVersionNotSupported)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.URL.Opaque != "" || r.URL.Scheme != "" || r.URL.Path != "" || r.URL.RawQuery != "" || r.Host != r.URL.Host {
		netutil.Error(w, "invalid CONNECT request", http.StatusBadRequest)
		return
	}
	name, port, err := authority(r.Host, 0)
	if err != nil || port == 0 {
		netutil.Error(w, "CONNECT requires host:port", http.StatusBadRequest)
		return
	}
	destination, err := h.connectDestination(name, port)
	if err != nil {
		status, message := connectionFailure(s.root, err)
		netutil.Error(w, message, status)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		netutil.Error(w, "too many HTTPS tunnels", http.StatusServiceUnavailable)
		return
	}
	certificate, upstream, err := h.openConnection(destination, port)
	if err != nil {
		h.logger.Warn("CONNECT setup failed", "host", r.Host, "error", err)
		status, message := connectionFailure(s.root, err)
		netutil.Error(w, message, status)
		return
	}
	if upstream != nil {
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
	conn := &netutil.BufferedConn{Conn: client, Reader: buffer.Reader}
	s.serveConnection(conn, certificate, upstream, destination.name, h)
}
