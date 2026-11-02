package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsAndJSON(t *testing.T) {
	c, err := Load("")
	if err != nil || c.TONProxy != "" || c.IPFSGateways[0] != "http://localhost:8080" || c.ArweaveGateways[0] != "http://localhost:1984" {
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
