// Package netutil keeps explicit upstreams separate from untrusted CCIP URLs.
package netutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

func Transport(headerTimeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, MaxIdleConns: 128, MaxIdleConnsPerHost: 16, MaxConnsPerHost: 64,
		IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: headerTimeout, ExpectContinueTimeout: time.Second,
		MaxResponseHeaderBytes: 1 << 20, DisableCompression: true,
	}
}

func Client(timeout time.Duration) *http.Client {
	return &http.Client{Transport: Transport(timeout), Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type ccipTransport struct {
	base    *http.Transport
	enabled bool
}

func (t *ccipTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !t.enabled {
		return nil, errors.New("CCIP Read disabled")
	}
	if r.URL.Scheme != "https" || r.URL.User != nil {
		return nil, errors.New("CCIP Read requires HTTPS without URL credentials")
	}
	return t.base.RoundTrip(r)
}

func (t *ccipTransport) CloseIdleConnections() { t.base.CloseIdleConnections() }

// CCIPClient verifies public addresses at the socket boundary, including DNS
// results, so DNS rebinding cannot route a chain-supplied URL into the LAN.
func CCIPClient(enabled bool, timeout time.Duration) *http.Client {
	t := Transport(timeout)
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("CCIP host has no address")
		}
		for _, ip := range ips {
			if !PublicIP(ip) {
				return nil, errors.New("CCIP destination is not public")
			}
		}
		var last error
		for _, ip := range ips {
			conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
	return &http.Client{Timeout: timeout, Transport: &ccipTransport{t, enabled}, CheckRedirect: func(_ *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many CCIP HTTP redirects")
		}
		return nil
	}}
}

var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("64:ff9b::/96"),
}

func PublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range reserved {
		if p.Contains(ip) {
			return false
		}
	}
	// Public IPv6 currently uses 2000::/3. Reject local translation ranges.
	return !ip.Is6() || netip.MustParsePrefix("2000::/3").Contains(ip)
}
