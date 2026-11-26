package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaultsAndJSON(t *testing.T) {
	c, err := Load("")
	if err != nil || c.TONProxy != "" || c.FallbackProxy != "" || c.IPFSGateways[0] != "http://localhost:8080" || c.ArweaveGateways[0] != "http://localhost:1984" || c.SwarmGateways[0] != "http://localhost:1633" {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	if c.EthereumRPC != "https://ethereum-rpc.publicnode.com" || c.SolanaRPC != "https://api.mainnet.solana.com" || c.ResponseHeaderTimeout != Duration(120*time.Second) || !c.HTTPS.Enabled {
		t.Fatalf("RPC, timeout or HTTPS defaults: %+v", c)
	}
	for _, tc := range []struct {
		json  string
		valid bool
	}{
		{`{}`, true}, {`{"ccip_read":false,"cache_ttl":"2m"}`, true},
		{`{"listen_protocol":"http"}`, true}, {`{"listen_protocol":"socks5"}`, true},
		{`{"listen_protocol":"https"}`, false}, {`{"listen_protocol":""}`, false},
		{`{"ipfs_gateways":["http://localhost:8080","https://gateway.example"]}`, true},
		{`{"swarm_gateways":["http://localhost:1633"]}`, true},
		{`{"swarm_gateways":["http://127.0.0.1:1633","https://swarm.example"]}`, true},
		{`{"swarm_gateways":[]}`, false}, {`{"swarm_gateways":null}`, false},
		{`{"swarm_gateways":["http://localhost:1633/bzz"]}`, false},
		{`{"swarm_gateways":["bzz://localhost:1633"]}`, false},
		{`{"swarm_gateways":["http://localhost:18080"]}`, false},
		{`{"swarm_gateways":["http://a","http://b","http://c"]}`, false},
		{`{"sns_v1":true}`, false}, {`{} {}`, false}, {`null`, false}, {`[]`, false},
		{`{"stream_idle_timeout":"0s"}`, false}, {`{"stream_idle_timeout":"-1s"}`, false}, {`{"stream_idle_timeout":"30s"}`, true},
		{`{"cache_ttl":"0s"}`, false}, {`{"listen":"0.0.0.0:18080"}`, false},
		{`{"ipfs_gateways":["http://127.0.0.1:8080"]}`, false},
		{`{"ton_proxy":"http://localhost:18080"}`, false},
		{`{"fallback_proxy":"http://127.0.0.1:7890"}`, true},
		{`{"fallback_proxy":"https://proxy.example:8443"}`, true},
		{`{"fallback_proxy":"http://localhost:18080"}`, false},
		{`{"fallback_proxy":"http://[::1]:18080"}`, false},
		{`{"fallback_proxy":"http://127.0.0.1:7890/path"}`, false},
		{`{"fallback_proxy":"socks5://127.0.0.1:7890"}`, true},
		{`{"ton_proxy":"socks5h://localhost"}`, true},
		{`{"ton_proxy":"socks5://[::1]:1081/"}`, true},
		{`{"fallback_proxy":"socks5://127.0.0.1:18080"}`, false},
		{`{"ton_proxy":"socks5://proxy.example/path"}`, false},
		{`{"fallback_proxy":"socks5://user:pass@proxy.example"}`, false},
		{`{"fallback_proxy":"socks4://proxy.example"}`, false},
		{`{"fallback_proxy":"socks5://proxy.example?"}`, false},
		{`{"fallback_proxy":"socks5://proxy.example#fragment"}`, false},
		{`{"ethereum_rpc":"socks5://proxy.example"}`, false},
		{`{"ipfs_gateways":["socks5://localhost"]}`, false},
		{`{"fallback_proxy":"http://user:password@proxy.example"}`, false},
		{`{"https":{"enabled":true}}`, true},
		{`{"https":{"connect_ports":[]}}`, false},
		{`{"https":{"connect_ports":[443,443]}}`, false},
		{`{"https":{"connect_ports":[65536]}}`, false},
		{`{"https":{"max_tunnels":0}}`, false},
		{`{"https":{"handshake_timeout":"0s"}}`, false},
		{`{"https":{"ca_cert":"same.pem","ca_key":"same.pem"}}`, false},
		{`{"ipfs_gateways":["http://localhost:8080/ipfs"]}`, false},
		{`{"arweave_gateways":[]}`, false}, {`{"max_concurrent":0}`, false},
	} {
		t.Run(tc.json, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(p, []byte(tc.json), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(p)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}

func TestCertificatePathsFollowConfigDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"https":{"ca_cert":"keys/root.pem","ca_key":"keys/root-key.pem"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPS.CACert != filepath.Join(dir, "keys/root.pem") || c.HTTPS.CAKey != filepath.Join(dir, "keys/root-key.pem") {
		t.Fatal("certificate paths are not relative to config")
	}
}

func TestCAValidationFollowsWeb3EnabledFlag(t *testing.T) {
	for _, fields := range []string{
		`"ca_cert":"","ca_key":""`,
		`"ca_cert":"same.pem","ca_key":"same.pem"`,
	} {
		for _, enabled := range []bool{false, true} {
			data := fmt.Sprintf(`{"https":{"enabled":%t,%s}}`, enabled, fields)
			t.Run(data, func(t *testing.T) {
				p := filepath.Join(t.TempDir(), "config.json")
				if err := os.WriteFile(p, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				_, err := Load(p)
				if (err != nil) != enabled {
					t.Fatalf("enabled=%v, error=%v", enabled, err)
				}
			})
		}
	}
	// Disabling Web3 TLS does not relax the shared JSON type/format rules.
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"https":{"enabled":false,"handshake_timeout":"invalid"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("accepted malformed duration string")
	}
}

func TestSelfReferenceUsesNumericPorts(t *testing.T) {
	for _, tc := range []struct{ listen, upstream string }{
		{"127.0.0.1:18080", "http://localhost:018080"},
		{"127.0.0.1:018080", "http://localhost:18080"},
		{"127.0.0.1:80", "http://localhost"},
		{"[::1]:443", "https://localhost"},
		{"127.0.0.1:1080", "socks5://localhost"},
		{"[::1]:1080", "socks5h://localhost:01080"},
	} {
		c := Default()
		c.Listen = tc.listen
		c.FallbackProxy = tc.upstream
		if err := c.Validate(); err == nil {
			t.Errorf("accepted self-reference: %s via %s", tc.listen, tc.upstream)
		}
	}
	for _, raw := range []string{"http://localhost:", "https://[::1]:", "http://host:0", "http://host:65536"} {
		if _, err := Endpoint(raw); err == nil {
			t.Errorf("accepted endpoint %s", raw)
		}
	}
}

func TestConnectSettingsValidatedRegardlessOfWeb3Flag(t *testing.T) {
	for _, fields := range []string{
		`"connect_ports":null`, `"connect_ports":[]`, `"connect_ports":[0]`, `"connect_ports":[65536]`, `"connect_ports":[443,443]`,
		`"handshake_timeout":"0s"`, `"tunnel_idle_timeout":"-1s"`, `"max_tunnels":0`,
	} {
		for _, enabled := range []bool{false, true} {
			data := fmt.Sprintf(`{"https":{"enabled":%t,%s}}`, enabled, fields)
			t.Run(data, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "config.json")
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := Load(path); err == nil {
					t.Fatal("accepted invalid active CONNECT setting")
				}
			})
		}
	}
}
