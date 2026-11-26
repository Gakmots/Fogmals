package config

import (
	"fmt"
	"path/filepath"
)

type HTTPS struct {
	// Enabled controls local TLS termination for Web3 domains only. CONNECT
	// transport limits also apply to ordinary HTTPS when Enabled is false.
	Enabled           bool     `json:"enabled"`
	CACert            string   `json:"ca_cert"`
	CAKey             string   `json:"ca_key"`
	ConnectPorts      []int    `json:"connect_ports"`
	HandshakeTimeout  Duration `json:"handshake_timeout"`
	TunnelIdleTimeout Duration `json:"tunnel_idle_timeout"`
	MaxTunnels        int      `json:"max_tunnels"`
}

func (h HTTPS) Validate() error {
	if h.HandshakeTimeout <= 0 || h.TunnelIdleTimeout <= 0 || h.MaxTunnels < 1 || h.MaxTunnels > 10000 {
		return fmt.Errorf("invalid HTTPS timeout or max_tunnels")
	}
	if len(h.ConnectPorts) == 0 || len(h.ConnectPorts) > 32 {
		return fmt.Errorf("HTTPS connect_ports must contain 1..32 ports")
	}
	seen := make(map[int]bool)
	for _, p := range h.ConnectPorts {
		if p < 1 || p > 65535 || seen[p] {
			return fmt.Errorf("invalid or duplicate HTTPS connect port")
		}
		seen[p] = true
	}
	if h.Enabled && (h.CACert == "" || h.CAKey == "" || filepath.Clean(h.CACert) == filepath.Clean(h.CAKey)) {
		return fmt.Errorf("Web3 HTTPS requires distinct CA certificate and key paths")
	}
	return nil
}
