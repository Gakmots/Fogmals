package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
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
	return h, nil
}

func (h *Handler) Close() {
	h.ipfs.Close()
	h.arweave.Close()
	h.ton.Close()
	h.fallback.Close()
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodConnect {
		http.Error(w, "HTTPS CONNECT is not supported", http.StatusNotImplemented)
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
			return
		case "/proxy.pac":
			w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
			fmt.Fprintf(w, pac, h.fallback != nil, h.listen)
			return
		}
	}
	name, err := requestName(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	matched := strings.HasSuffix(name, ".eth") || strings.HasSuffix(name, ".sns") || strings.HasSuffix(name, ".ton")
	if !matched && h.fallback == nil {
		http.Error(w, "unsupported domain suffix", http.StatusForbidden)
		return
	}
	if matched {
		if r.URL.Port() != "" && r.URL.Port() != "80" {
			http.Error(w, "only target port 80 is supported for matched domains", http.StatusBadRequest)
			return
		}
		name, err = resolve.Normalize(name)
		if err != nil {
			http.Error(w, "invalid domain name", http.StatusBadRequest)
			return
		}
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
	if !matched {
		h.fallback.ServeHTTP(w, r)
		return
	}
	if strings.HasSuffix(name, ".ton") {
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
	target, err := h.resolver.Resolve(ctx, name)
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
		h.logger.Warn("resolution failed", "name", name, "error", err)
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

func requestName(r *http.Request) (string, error) {
	if !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.Opaque != "" || r.URL.User != nil || r.URL.Fragment != "" {
		return "", fmt.Errorf("expected an absolute http proxy URL")
	}
	if !strings.EqualFold(r.URL.Host, r.Host) {
		return "", fmt.Errorf("URL and Host disagree")
	}
	if port := r.URL.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid target port")
		}
	}
	host := strings.TrimSuffix(strings.ToLower(r.URL.Hostname()), ".")
	if host == "" || len(host) > 253 {
		return "", fmt.Errorf("invalid target hostname")
	}
	return host, nil
}

const pac = `function FindProxyForURL(url, host) {
  host = host.toLowerCase().replace(/\.$/, "");
  if (url.substring(0, 5).toLowerCase() === "http:" &&
      (dnsDomainIs(host, ".eth") || dnsDomainIs(host, ".sns") || dnsDomainIs(host, ".ton") || %t)) {
    return "PROXY %s";
  }
  return "DIRECT";
}
`
