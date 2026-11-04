package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"dwebproxy/internal/config"
	"dwebproxy/internal/netutil"
)

// forwardProxy preserves the original destination while the Transport connects
// to an explicit HTTP(S) next hop. TON and unmatched HTTP requests share it.
type forwardProxy struct {
	*httputil.ReverseProxy
	transport *http.Transport
	endpoint  *url.URL
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
			if pr.In.Context().Value(tlsAuthorityKey{}) != nil {
				pr.Out.URL.Host = pr.In.URL.Hostname()
				pr.Out.Host = pr.Out.URL.Host
			}
			pr.Out.Header.Del("Proxy-Authorization")
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.Request == nil {
				return nil
			}
			host, _ := resp.Request.Context().Value(tlsAuthorityKey{}).(string)
			if host == "" {
				return nil
			}
			resp.Header.Del("Alt-Svc")
			loc, err := url.Parse(resp.Header.Get("Location"))
			if err == nil && loc.Scheme == "http" && strings.EqualFold(loc.Hostname(), host) && (loc.Port() == "" || loc.Port() == "80") {
				loc.Scheme = "https"
				loc.Host = host
				resp.Header.Set("Location", loc.String())
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Warn(name+" proxy request failed", "host", r.Host, "error", err)
			http.Error(w, name+" proxy unavailable", http.StatusBadGateway)
		},
	}
	p.Transport = forwardTransport{t}
	return &forwardProxy{p, t, u}, nil
}

type forwardTransport struct{ base *http.Transport }

func (t forwardTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if resp != nil {
		resp.Request = r
	}
	return resp, err
}

func (p *forwardProxy) Close() {
	if p != nil {
		p.transport.CloseIdleConnections()
	}
}
