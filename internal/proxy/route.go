package proxy

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"dwebproxy/internal/resolve"
)

type routeKind uint8

const (
	routeContent routeKind = iota
	routeTON
	routeFallback
)

type route struct {
	kind routeKind
	name string
}

// routeRequest is the sole destination-routing entrypoint. Clients send every
// HTTP request to the same listener; no client-side routing script is involved.
// A matched name remains on its route even when its resolver/upstream fails.
func routeRequest(r *http.Request) (route, error) {
	name, err := requestName(r)
	if err != nil {
		return route{}, err
	}
	kind := routeFallback
	switch {
	case strings.HasSuffix(name, ".eth"), strings.HasSuffix(name, ".sns"):
		kind = routeContent
	case strings.HasSuffix(name, ".ton"):
		kind = routeTON
	}
	if kind != routeFallback {
		if r.URL.Port() != "" && r.URL.Port() != "80" {
			return route{}, fmt.Errorf("only target port 80 is supported for matched domains")
		}
		name, err = resolve.Normalize(name)
		if err != nil {
			return route{}, fmt.Errorf("invalid domain name")
		}
	}
	return route{kind: kind, name: name}, nil
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
