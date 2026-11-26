package proxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"dwebproxy/internal/config"
	"dwebproxy/internal/netutil"
	xproxy "golang.org/x/net/proxy"
)

// forwardProxy preserves the original destination while the Transport connects
// to an explicit HTTP(S) or SOCKS5 next hop. TON and unmatched HTTP share it.
type forwardProxy struct {
	*httputil.ReverseProxy
	transport *http.Transport
	endpoint  *url.URL
	socks     xproxy.ContextDialer
}

func newForwardProxy(raw, name string, timeout time.Duration, logger *slog.Logger, dial netutil.DialContextFunc) (*forwardProxy, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := config.ProxyEndpoint(raw)
	if err != nil {
		return nil, err
	}
	t := netutil.Transport(timeout, dial)
	var socks xproxy.ContextDialer
	if netutil.IsSOCKS(u) {
		socks, err = netutil.SOCKSDialer(u, t.DialContext)
		if err != nil {
			return nil, err
		}
		t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, t.TLSHandshakeTimeout)
			defer cancel()
			return socks.DialContext(ctx, network, address)
		}
	} else {
		t.Proxy = http.ProxyURL(u)
	}
	p := &httputil.ReverseProxy{
		Transport: t,
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Rewrite normally receives a sanitized query. Start again from the
			// incoming URL and preserve the original HTTP request-target verbatim.
			u := *pr.In.URL
			pr.Out.URL = &u
			pr.Out.Host = pr.In.Host
			target := pr.In.RequestURI
			if pr.In.Context().Value(tlsAuthorityKey{}) != nil {
				// TON's existing ingress contract terminates browser TLS locally;
				// the TON next hop still receives an HTTP destination on port 80.
				pr.Out.URL.Scheme = "http"
				pr.Out.URL.Host = pr.In.URL.Hostname()
				pr.Out.Host = pr.Out.URL.Host
				target = "http://" + pr.Out.Host + pr.In.URL.RequestURI()
			} else if strings.HasPrefix(target, "/") {
				target = "http://" + pr.Out.Host + target
			} else if target == "" {
				target = pr.In.URL.String()
			}
			// net/http's proxy serializer uses Opaque as an exact request-target.
			// Keep the parsed scheme/host for connection routing. This also avoids
			// inserting a slash in an originally empty path or changing escapes.
			if socks == nil {
				pr.Out.URL.Opaque = target
				pr.Out.URL.RawQuery = ""
				pr.Out.URL.ForceQuery = false
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
			netutil.Error(w, name+" proxy unavailable", netutil.ProxyErrorStatus(r.Context(), err))
		},
	}
	return &forwardProxy{ReverseProxy: p, transport: t, endpoint: u, socks: socks}, nil
}

func (p *forwardProxy) Close() {
	if p != nil {
		p.transport.CloseIdleConnections()
	}
}
