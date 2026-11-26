package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"slices"
	"strconv"
	"time"

	"dwebproxy/internal/netutil"
)

type connectionRejection struct {
	status  int
	message string
}

func (e *connectionRejection) Error() string { return e.message }

// HTTP CONNECT and SOCKS5 use one destination policy and setup path.
func (h *Handler) connectDestination(name string, port int) (route, error) {
	s := h.connect
	if !slices.Contains(s.settings.ConnectPorts, port) {
		return route{}, &connectionRejection{403, "CONNECT port is not allowed"}
	}
	destination, err := classifyName(name)
	if err != nil {
		return route{}, &connectionRejection{400, "invalid CONNECT domain"}
	}
	if destination.kind != routeFallback {
		if !s.settings.Enabled {
			return route{}, &connectionRejection{501, "Web3 HTTPS is disabled"}
		}
		if port != 443 {
			return route{}, &connectionRejection{403, "special domains require HTTPS port 443"}
		}
		if destination.kind == routeTON && h.ton == nil {
			return route{}, &connectionRejection{503, "TON proxy is not configured"}
		}
	} else if h.fallback == nil {
		return route{}, &connectionRejection{503, "fallback proxy is not configured"}
	}
	return destination, nil
}

func (h *Handler) openConnection(destination route, port int) (*tls.Certificate, net.Conn, error) {
	if destination.kind != routeFallback {
		certificate, err := h.connect.ca.Certificate(destination.name)
		if err != nil {
			return nil, nil, &connectionRejection{400, "cannot issue domain certificate"}
		}
		return certificate, nil, nil
	}
	upstream, err := h.fallback.dialTunnel(h.connect.root, net.JoinHostPort(destination.name, strconv.Itoa(port)), time.Duration(h.connect.settings.HandshakeTimeout))
	return nil, upstream, err
}

func connectionFailure(ctx context.Context, err error) (int, string) {
	var rejected *connectionRejection
	if errors.As(err, &rejected) {
		return rejected.status, rejected.message
	}
	return netutil.ProxyErrorStatus(ctx, err), "fallback CONNECT unavailable"
}

func (s *connectIngress) serveConnection(client net.Conn, certificate *tls.Certificate, upstream net.Conn, name string, h http.Handler) {
	if upstream != nil {
		relay(client, upstream, time.Duration(s.settings.TunnelIdleTimeout))
		return
	}
	s.serveTLS(client, certificate, name, h)
}

// Keep every HTTP request bound to its SOCKS/CONNECT destination, including
// subsequent keep-alive requests and concurrent HTTP/2 streams.
func boundRequestHandler(name string, port int, scheme string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, p, err := authority(r.Host, port)
		if err != nil || host != name || p != port || (r.URL.Scheme != "" && r.URL.Scheme != scheme) {
			netutil.Error(w, "request authority differs from proxy destination", http.StatusMisdirectedRequest)
			return
		}
		if r.URL.Host != "" {
			uHost, uPort, err := authority(r.URL.Host, port)
			if err != nil || uHost != name || uPort != port {
				netutil.Error(w, "URL authority differs from proxy destination", http.StatusMisdirectedRequest)
				return
			}
		}
		if r.Method == http.MethodConnect {
			netutil.Error(w, "nested CONNECT is not supported", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "" && r.URL.Path[0] != '/' {
			netutil.Error(w, "expected an HTTP path", http.StatusBadRequest)
			return
		}
		ctx := r.Context()
		if scheme == "https" {
			ctx = context.WithValue(ctx, tlsAuthorityKey{}, name)
		}
		r = r.Clone(ctx)
		r.URL.Scheme = scheme
		r.URL.Host = r.Host
		next.ServeHTTP(w, r)
	})
}
