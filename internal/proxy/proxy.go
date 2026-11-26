package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"dwebproxy/internal/config"
	"dwebproxy/internal/content"
	"dwebproxy/internal/gateway"
	"dwebproxy/internal/netutil"
	"dwebproxy/internal/resolve"
)

type Handler struct {
	resolver      resolve.Resolver
	gateways      map[content.Kind]*gateway.Pool
	ton, fallback *forwardProxy
	connect       *connectIngress
	limit         chan struct{}
	timeout       time.Duration
	streamIdle    time.Duration
	logger        *slog.Logger
	listen        string
}

func New(c config.Config, resolver resolve.Resolver, logger *slog.Logger) (*Handler, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	u, err := c.ProgramProxy.Endpoint()
	if err != nil {
		return nil, err
	}
	dial, err := netutil.NewDialer(u)
	if err != nil {
		return nil, err
	}
	h := &Handler{gateways: make(map[content.Kind]*gateway.Pool), resolver: resolver, limit: make(chan struct{}, c.MaxConcurrent), timeout: time.Duration(c.ResolveTimeout), streamIdle: time.Duration(c.StreamIdleTimeout), logger: logger, listen: c.Listen}
	for kind, origins := range map[content.Kind][]string{
		content.IPFS: c.IPFSGateways, content.Arweave: c.ArweaveGateways, content.Swarm: c.SwarmGateways,
	} {
		pool, err := gateway.New(origins, time.Duration(c.ResponseHeaderTimeout), logger, dial)
		if err != nil {
			h.Close()
			return nil, err
		}
		h.gateways[kind] = pool
	}
	h.ton, err = newForwardProxy(c.TONProxy, "TON", time.Duration(c.ResponseHeaderTimeout), logger, dial)
	if err != nil {
		h.Close()
		return nil, err
	}
	h.fallback, err = newForwardProxy(c.FallbackProxy, "fallback", time.Duration(c.ResponseHeaderTimeout), logger, dial)
	if err != nil {
		h.Close()
		return nil, err
	}
	h.connect, err = newConnect(c)
	if err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

func (h *Handler) Close() {
	h.connect.Close()
	for _, pool := range h.gateways {
		pool.Close()
	}
	h.ton.Close()
	h.fallback.Close()
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.serveConnect(w, r)
		return
	}
	// Local utility endpoints are only available in origin-form requests to the
	// listener, never as paths on a proxied website.
	if !r.URL.IsAbs() && r.Host == h.listen {
		switch r.URL.Path {
		case "/healthz":
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				netutil.Error(w, "method not allowed", 405)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintln(w, "ok")
		default:
			netutil.Error(w, "404 page not found", http.StatusNotFound)
		}
		return
	}
	destination, err := routeRequest(r)
	if err != nil {
		netutil.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if destination.kind == routeFallback && h.fallback == nil {
		netutil.Error(w, "unsupported domain suffix", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodTrace || r.Header.Get("Upgrade") != "" {
		netutil.Error(w, "method or protocol upgrade not supported", http.StatusMethodNotAllowed)
		return
	}
	select {
	case h.limit <- struct{}{}:
		defer func() { <-h.limit }()
	default:
		netutil.Error(w, "too many concurrent requests", http.StatusServiceUnavailable)
		return
	}
	w, r, finish := streamRequest(w, r, h.streamIdle)
	defer finish()
	switch destination.kind {
	case routeFallback:
		h.fallback.ServeHTTP(w, r)
		return
	case routeTON:
		if h.ton == nil {
			netutil.Error(w, "TON proxy is not configured", http.StatusServiceUnavailable)
			return
		}
		h.ton.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		netutil.Error(w, "static content supports GET and HEAD only", http.StatusMethodNotAllowed)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		netutil.Error(w, "static content requests cannot contain a body", http.StatusBadRequest)
		return
	}
	if err := gateway.ValidatePath(r.URL); err != nil {
		netutil.Error(w, "invalid content path or query", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	target, err := h.resolver.Resolve(ctx, destination.name)
	cancel()
	if err != nil {
		status := netutil.ProxyErrorStatus(ctx, err)
		switch {
		case errors.Is(err, resolve.ErrNotFound):
			status = http.StatusNotFound
		case errors.Is(err, resolve.ErrUnavailable), errors.Is(err, resolve.ErrBusy):
			status = http.StatusServiceUnavailable
		case errors.Is(err, content.ErrUnsupported):
			status = http.StatusNotImplemented
		}
		h.logger.Warn("resolution failed", "name", destination.name, "error", err)
		netutil.Error(w, http.StatusText(status), status)
		return
	}
	kind := target.Kind
	if kind == content.IPNS {
		kind = content.IPFS
	}
	pool := h.gateways[kind]
	if pool == nil {
		netutil.Error(w, "unsupported content protocol", http.StatusNotImplemented)
		return
	}
	pool.Serve(w, r, target)
}
