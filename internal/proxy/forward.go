package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"time"

	"dwebproxy/internal/config"
	"dwebproxy/internal/netutil"
)

// forwardProxy preserves the original destination while the Transport connects
// to an explicit HTTP(S) next hop. TON and unmatched HTTP requests share it.
type forwardProxy struct {
	*httputil.ReverseProxy
	transport *http.Transport
}

func newForwardProxy(raw, name string, timeout time.Duration, logger *slog.Logger) (*forwardProxy, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := config.Endpoint(raw)
	if err != nil {
		return nil, err
	}
	t := netutil.Transport(timeout)
	t.Proxy = http.ProxyURL(u)
	p := &httputil.ReverseProxy{
		Transport: t,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = pr.In.Host
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Del("Proxy-Authorization")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Warn(name+" proxy request failed", "host", r.Host, "error", err)
			http.Error(w, name+" proxy unavailable", http.StatusBadGateway)
		},
	}
	return &forwardProxy{p, t}, nil
}

func (p *forwardProxy) Close() {
	if p != nil {
		p.transport.CloseIdleConnections()
	}
}
