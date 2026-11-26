package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestProgramProxyConfiguration(t *testing.T) {
	for _, tc := range []struct {
		fields string
		valid  bool
	}{
		{`{}`, true},
		{`{"program_proxy":{"enabled":false,"url":"saved invalid URL"}}`, true},
		{`{"program_proxy":{"enabled":true}}`, false},
		{`{"program_proxy":{"enabled":true,"url":"http://127.0.0.1:7890"}}`, true},
		{`{"program_proxy":{"enabled":true,"url":"https://proxy.example"}}`, true},
		{`{"program_proxy":{"enabled":true,"url":"socks5://localhost"}}`, true},
		{`{"program_proxy":{"enabled":true,"url":"socks5h://[::1]:1080"}}`, true},
		{`{"program_proxy":{"enabled":true,"url":"socks4://localhost"}}`, false},
		{`{"program_proxy":{"enabled":true,"url":"http://localhost:018080"}}`, false},
		{`{"listen":"127.0.0.1:1080","program_proxy":{"enabled":true,"url":"socks5://localhost"}}`, false},
		{`{"program_proxy":{"enabled":true,"url":"http://user:pass@proxy.example"}}`, false},
		{`{"program_proxy":{"enabled":true,"url":"http://proxy.example/path"}}`, false},
		{`{"program_proxy":{"enabled":true,"url":"http://proxy.example?"}}`, false},
		{`{"program_proxy":{"enabled":true,"url":"http://proxy.example:0"}}`, false},
		{`{"program_proxy":{"enabled":true,"url":"http://proxy.example#fragment"}}`, false},
		{`{"program_proxy":{"enabled":"true"}}`, false},
		{`{"program_proxy":{"unexpected":true}}`, false},
	} {
		t.Run(tc.fields, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.fields), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
			if err != nil {
				return
			}
			endpoint, err := c.ProgramProxy.Endpoint()
			if err != nil || (endpoint != nil) != c.ProgramProxy.Enabled {
				t.Fatalf("effective endpoint=%v, error=%v", endpoint, err)
			}
			b, _ := json.Marshal(c)
			var roundtrip Config
			if err := json.Unmarshal(b, &roundtrip); err != nil || roundtrip.ProgramProxy != c.ProgramProxy {
				t.Fatalf("proxy settings did not round-trip: %v", err)
			}
		})
	}
}
