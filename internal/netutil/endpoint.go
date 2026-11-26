package netutil

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// EndpointPort returns the numeric port of a parsed HTTP(S) or SOCKS5 endpoint, using the
// scheme's default when omitted. An explicit empty port is a configuration error.
func EndpointPort(u *url.URL) (int, error) {
	if u == nil || u.Hostname() == "" {
		return 0, fmt.Errorf("expected a proxy or HTTP(S) endpoint")
	}
	var fallback int
	switch u.Scheme {
	case "http":
		fallback = 80
	case "https":
		fallback = 443
	case "socks5", "socks5h":
		fallback = 1080
	default:
		return 0, fmt.Errorf("unsupported endpoint scheme")
	}
	if strings.HasSuffix(u.Host, ":") {
		return 0, fmt.Errorf("endpoint port must not be empty")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("invalid endpoint port")
		}
		return n, nil
	}
	return fallback, nil
}

// EndpointAddress is the socket address of an endpoint, including IPv6
// brackets and a canonical numeric port. It does not rewrite the request URL.
func EndpointAddress(u *url.URL) (string, error) {
	port, err := EndpointPort(u)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(u.Hostname(), strconv.Itoa(port)), nil
}
