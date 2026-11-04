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
	"dwebproxy/internal/resolve"
)

type Handler struct {
	resolver      resolve.Resolver
	ipfs, arweave *gateway.Pool
	ton, fallback *forwardProxy
	https         *httpsIngress
	limit         chan struct{}
	timeout       time.Duration
	logger        *slog.Logger
	listen        string
}

func New(c config.Config, resolver resolve.Resolver, logger *slog.Logger) (*Handler, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	h := &Handler{resolver: resolver, limit: make(chan struct{}, c.MaxConcurrent), timeout: time.Duration(c.ResolveTimeout), logger: logger, listen: c.Listen}
	var err error
	h.ipfs, err = gateway.New(c.IPFSGateways, time.Duration(c.ResponseHeaderTimeout), logger)
	if err != nil {
		return nil, err
	}
	h.arweave, err = gateway.New(c.ArweaveGateways, time.Duration(c.ResponseHeaderTimeout), logger)
	if err != nil {
		h.ipfs.Close()
		return nil, err
	}
	h.ton, err = newForwardProxy(c.TONProxy, "TON", time.Duration(c.ResponseHeaderTimeout), logger)
	if err != nil {
		h.Close()
		return nil, err
	}
	h.fallback, err = newForwardProxy(c.FallbackProxy, "fallback", time.Duration(c.ResponseHeaderTimeout), logger)
	if err != nil {
		h.Close()
		return nil, err
	}
	h.https, err = newHTTPS(c)
	if err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

func (h *Handler) Close() {
	h.https.Close()
	h.ipfs.Close()
	h.arweave.Close()
	h.ton.Close()
	h.fallback.Close()
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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
				http.Error(w, "method not allowed", 405)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintln(w, "ok")
		default:
			http.NotFound(w, r)
		}
		return
	}
	destination, err := routeRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if destination.kind == routeFallback && h.fallback == nil {
		http.Error(w, "unsupported domain suffix", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodTrace || r.Header.Get("Upgrade") != "" {
		http.Error(w, "method or protocol upgrade not supported", http.StatusMethodNotAllowed)
		return
	}
	select {
	case h.limit <- struct{}{}:
		defer func() { <-h.limit }()
	default:
		http.Error(w, "too many concurrent requests", http.StatusServiceUnavailable)
		return
	}
	switch destination.kind {
	case routeFallback:
		h.fallback.ServeHTTP(w, r)
		return
	case routeTON:
		if h.ton == nil {
			http.Error(w, "TON proxy is not configured", http.StatusServiceUnavailable)
			return
		}
		h.ton.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "static content supports GET and HEAD only", http.StatusMethodNotAllowed)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		http.Error(w, "static content requests cannot contain a body", http.StatusBadRequest)
		return
	}
	if err := gateway.ValidatePath(r.URL); err != nil {
		http.Error(w, "invalid content path or query", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	target, err := h.resolver.Resolve(ctx, destination.name)
	cancel()
	if err != nil {
		status := http.StatusBadGateway
		switch {
		case errors.Is(err, resolve.ErrNotFound):
			status = http.StatusNotFound
		case errors.Is(err, resolve.ErrUnavailable):
			status = http.StatusServiceUnavailable
		case errors.Is(err, context.DeadlineExceeded):
			status = http.StatusGatewayTimeout
		case errors.Is(err, content.ErrUnsupported):
			status = http.StatusNotImplemented
		}
		h.logger.Warn("resolution failed", "name", destination.name, "error", err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	switch target.Kind {
	case content.IPFS, content.IPNS:
		h.ipfs.Serve(w, r, target)
	case content.Arweave:
		h.arweave.Serve(w, r, target)
	default:
		http.Error(w, "unsupported content protocol", http.StatusNotImplemented)
	}
}
