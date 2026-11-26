package config

import (
	"fmt"
	"net/url"
)

// ProgramProxy is the outer proxy for non-local program-initiated connections.
// A disabled proxy may retain its URL without parsing or contacting it.
type ProgramProxy struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
}

func (p ProgramProxy) Endpoint() (*url.URL, error) {
	if !p.Enabled {
		return nil, nil
	}
	u, err := ProxyEndpoint(p.URL)
	if err != nil {
		return nil, fmt.Errorf("program_proxy: %w", err)
	}
	return u, nil
}
