// Package gateway maps validated content roots to explicitly configured origins.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"dwebproxy/internal/config"
	"dwebproxy/internal/content"
	"dwebproxy/internal/netutil"
)

type endpoint struct {
	base      *url.URL
	transport *http.Transport
}

type Pool struct {
	endpoints []endpoint
	logger    *slog.Logger
}

func New(origins []string, timeout time.Duration, logger *slog.Logger) (*Pool, error) {
	p := &Pool{logger: logger}
	for _, raw := range origins {
		base, err := config.Endpoint(raw)
		if err != nil {
			return nil, err
		}
		t := netutil.Transport(timeout)
		port := base.Port()
		if port == "" {
			if base.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		// URL and Host use the content subdomain. The socket uses the configured
		// gateway host, so *.ipfs.localhost needs no OS DNS or hosts entries.
		address := net.JoinHostPort(base.Hostname(), port)
		t.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, address)
		}
		p.endpoints = append(p.endpoints, endpoint{base, t})
	}
	return p, nil
}

func (p *Pool) Close() {
	for _, e := range p.endpoints {
		e.transport.CloseIdleConnections()
	}
}

func ValidatePath(u *url.URL) error {
	if u.Path != "" && !strings.HasPrefix(u.Path, "/") {
		return fmt.Errorf("path must be absolute")
	}
	// Reject encoded separators and dot segments rather than relying on differing
	// interpretations in a gateway and its reverse proxy.
	for _, part := range strings.Split(u.EscapedPath(), "/") {
		s, err := url.PathUnescape(part)
		if err != nil {
			return err
		}
		if s == "." || s == ".." || strings.ContainsAny(s, "/\\\x00\r\n") {
			return fmt.Errorf("unsafe path segment")
		}
		// Nested percent encodings are ambiguous across proxy stacks. v1 rejects
		// them rather than guessing how often an upstream will decode a path.
		if strings.Contains(s, "%") {
			return fmt.Errorf("nested percent encoding is not supported")
		}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("invalid query encoding")
	}
	for key := range q {
		if strings.EqualFold(key, "uri") {
			return fmt.Errorf("gateway uri override is disabled")
		}
	}
	return nil
}

func targetURL(base *url.URL, t content.Target, in *url.URL) *url.URL {
	u := *base
	u.Path = in.Path
	u.RawPath = in.RawPath
	if u.Path == "" {
		u.Path = "/"
	}
	u.RawQuery = in.RawQuery
	u.ForceQuery = in.ForceQuery
	if t.Kind == content.Arweave {
		u.Path = "/" + t.ID + u.Path
		if in.RawPath != "" {
			u.RawPath = "/" + t.ID + in.RawPath
		}
	} else {
		u.Host = t.ID + "." + string(t.Kind) + "." + base.Host
	}
	return &u
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (p *Pool) Serve(w http.ResponseWriter, r *http.Request, t content.Target) {
	if len(p.endpoints) == 0 {
		http.Error(w, "content gateway not configured", http.StatusServiceUnavailable)
		return
	}
	var chosen endpoint
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = targetURL(p.endpoints[0].base, t, pr.In.URL)
			pr.Out.Host = pr.Out.URL.Host
			for _, h := range []string{"Cookie", "Authorization", "Proxy-Authorization", "Referer", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
				pr.Out.Header.Del(h)
			}
		},
		Transport: roundTripper(func(out *http.Request) (*http.Response, error) {
			for i, e := range p.endpoints {
				chosen = e
				req := out.Clone(out.Context())
				req.URL = targetURL(e.base, t, r.URL)
				req.Host = req.URL.Host
				resp, err := e.fetch(req, t)
				if err != nil {
					if i+1 < len(p.endpoints) && out.Context().Err() == nil {
						continue
					}
					return nil, err
				}
				if i+1 < len(p.endpoints) && (resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504) {
					resp.Body.Close()
					continue
				}
				return resp, nil
			}
			return nil, errors.New("all gateways failed")
		}),
		ModifyResponse: func(resp *http.Response) error {
			if location := resp.Header.Get("Location"); location != "" {
				loc, err := rewriteLocation(location, chosen.base, resp.Request.URL, r.URL, r.Host, t)
				if err != nil {
					return err
				}
				resp.Header.Set("Location", loc)
			}
			for _, h := range []string{"Set-Cookie", "Strict-Transport-Security", "Age", "Expires", "Surrogate-Control", "CDN-Cache-Control"} {
				resp.Header.Del(h)
			}
			// The browser URL names a mutable domain even when its upstream root
			// is an immutable CID. Keep validators, require revalidation.
			resp.Header.Set("Cache-Control", "no-cache")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			p.logger.Warn("gateway request failed", "host", r.Host, "error", err)
			status := http.StatusBadGateway
			var timeout net.Error
			if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
				status = http.StatusGatewayTimeout
			}
			http.Error(w, "content gateway unavailable", status)
		},
	}
	proxy.ServeHTTP(w, r)
}

func rewriteLocation(raw string, base, out, in *url.URL, host string, t content.Target) (string, error) {
	rel, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid gateway redirect")
	}
	// ResolveReference cleans dot segments. Validate before that information is
	// lost, including relative Location values.
	check := *rel
	if check.Path != "" && !strings.HasPrefix(check.Path, "/") {
		check.Path = "/" + check.Path
		if check.RawPath != "" {
			check.RawPath = "/" + check.RawPath
		}
	}
	if err := ValidatePath(&check); err != nil {
		return "", err
	}
	u := out.ResolveReference(rel)
	if u.Scheme != "http" && u.Scheme != "https" {
		return raw, nil
	}
	if u.User != nil {
		return "", fmt.Errorf("gateway redirect contains credentials")
	}
	if strings.EqualFold(u.Host, out.Host) || (t.Kind == content.Arweave && sameArweaveGateway(u, base)) {
		if t.Kind == content.Arweave {
			prefix := "/" + t.ID
			if u.Path != prefix && !strings.HasPrefix(u.Path, prefix+"/") {
				return "", fmt.Errorf("gateway redirect escapes Arweave content root")
			}
			u.Path = strings.TrimPrefix(u.Path, prefix)
			if u.RawPath != "" {
				u.RawPath = strings.TrimPrefix(u.RawPath, prefix)
			}
		}
	} else if strings.EqualFold(u.Host, base.Host) && t.Kind != content.Arweave {
		parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 3)
		if len(parts) < 2 || parts[0] != string(t.Kind) {
			return "", fmt.Errorf("gateway redirect escapes content root")
		}
		other, err := content.Parse(t.Kind, parts[1])
		if err != nil || other != t {
			return "", fmt.Errorf("gateway redirect changes content root")
		}
		prefix := "/" + parts[0] + "/" + parts[1]
		u.Path = strings.TrimPrefix(u.Path, prefix)
		if u.RawPath != "" {
			u.RawPath = strings.TrimPrefix(u.RawPath, prefix)
		}
	} else {
		// External website navigation is returned to the browser, never fetched
		// by the proxy. No redirect-controlled network dial occurs here.
		return raw, nil
	}
	if u.Path == "" {
		u.Path = "/"
	}
	if err := ValidatePath(u); err != nil {
		return "", err
	}
	u.Scheme = "http"
	u.Host = host
	if u.Path == in.Path && u.RawQuery == in.RawQuery && rel.Fragment == "" {
		return "", fmt.Errorf("gateway redirect would loop")
	}
	return u.String(), nil
}

func sameArweaveGateway(u, base *url.URL) bool {
	if u.Port() != base.Port() {
		return false
	}
	host := strings.ToLower(u.Hostname())
	origin := strings.ToLower(base.Hostname())
	if host == origin {
		return true
	}
	suffix := "." + origin
	label, ok := strings.CutSuffix(host, suffix)
	return ok && label != "" && !strings.Contains(label, ".")
}

// Arweave gateways may move a request to a sandbox subdomain with the same
// transaction ID and path. Consume only that transport-level redirect. The
// socket stays pinned to the configured gateway; TLS still verifies the new
// subdomain. All other redirects remain browser navigation.
func (e endpoint) fetch(req *http.Request, t content.Target) (*http.Response, error) {
	seen := map[string]bool{}
	for hops := 0; hops < 4; hops++ {
		if seen[req.URL.String()] {
			return nil, fmt.Errorf("gateway canonical redirect loop")
		}
		seen[req.URL.String()] = true
		resp, err := e.transport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		resp.Request = req
		if t.Kind != content.Arweave || resp.StatusCode < 300 || resp.StatusCode > 399 || resp.Header.Get("Location") == "" {
			return resp, nil
		}
		rel, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			return resp, nil
		}
		next := req.URL.ResolveReference(rel)
		canonical := next.User == nil && next.Scheme == e.base.Scheme && next.Port() == e.base.Port() &&
			sameArweaveGateway(next, e.base) &&
			next.Host != req.URL.Host && next.Path == req.URL.Path && next.RawQuery == req.URL.RawQuery && next.Fragment == ""
		if !canonical {
			return resp, nil
		}
		resp.Body.Close()
		if err := ValidatePath(next); err != nil {
			return nil, err
		}
		req = req.Clone(req.Context())
		req.URL = next
		req.Host = next.Host
	}
	return nil, fmt.Errorf("too many gateway canonical redirects")
}
