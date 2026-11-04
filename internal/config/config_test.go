package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsAndJSON(t *testing.T) {
	c, err := Load("")
	if err != nil || c.TONProxy != "" || c.FallbackProxy != "" || c.IPFSGateways[0] != "http://localhost:8080" || c.ArweaveGateways[0] != "http://localhost:1984" {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	for _, tc := range []struct {
		json  string
		valid bool
	}{
		{`{}`, true}, {`{"ccip_read":false,"cache_ttl":"2m"}`, true},
		{`{"ipfs_gateways":["http://localhost:8080","https://gateway.example"]}`, true},
		{`{"sns_v1":true}`, false}, {`{} {}`, false}, {`null`, false}, {`[]`, false},
		{`{"cache_ttl":"0s"}`, false}, {`{"listen":"0.0.0.0:18080"}`, false},
		{`{"ipfs_gateways":["http://127.0.0.1:8080"]}`, false},
		{`{"ton_proxy":"http://localhost:18080"}`, false},
		{`{"fallback_proxy":"http://127.0.0.1:7890"}`, true},
		{`{"fallback_proxy":"https://proxy.example:8443"}`, true},
		{`{"fallback_proxy":"http://localhost:18080"}`, false},
		{`{"fallback_proxy":"http://[::1]:18080"}`, false},
		{`{"fallback_proxy":"http://127.0.0.1:7890/path"}`, false},
		{`{"fallback_proxy":"socks5://127.0.0.1:7890"}`, false},
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
