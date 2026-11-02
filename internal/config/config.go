package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err == nil {
		*d = Duration(v)
	}
	return err
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

type Config struct {
	Listen                string   `json:"listen"`
	EthereumRPC           string   `json:"ethereum_rpc"`
	SolanaRPC             string   `json:"solana_rpc"`
	IPFSGateways          []string `json:"ipfs_gateways"`
	ArweaveGateways       []string `json:"arweave_gateways"`
	TONProxy              string   `json:"ton_proxy"`
	CCIPRead              bool     `json:"ccip_read"`
	ResolveTimeout        Duration `json:"resolve_timeout"`
	ResponseHeaderTimeout Duration `json:"response_header_timeout"`
	CacheTTL              Duration `json:"cache_ttl"`
	NegativeCacheTTL      Duration `json:"negative_cache_ttl"`
	CacheSize             int      `json:"cache_size"`
	MaxConcurrent         int      `json:"max_concurrent"`
}

func Default() Config {
	return Config{
		Listen: "127.0.0.1:18080", EthereumRPC: "http://localhost:8545", SolanaRPC: "http://localhost:8899",
		IPFSGateways: []string{"http://localhost:8080"}, ArweaveGateways: []string{"http://localhost:1984"},
		CCIPRead: true, ResolveTimeout: Duration(15 * time.Second), ResponseHeaderTimeout: Duration(30 * time.Second),
		CacheTTL: Duration(time.Minute), NegativeCacheTTL: Duration(5 * time.Second), CacheSize: 1024, MaxConcurrent: 64,
	}
}

func Load(path string) (Config, error) {
	c := Default()
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return c, err
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if err != nil {
			return c, err
		}
		data = bytes.TrimSpace(data)
		if len(data) == 0 || len(data) > 1<<20 || data[0] != '{' {
			return c, fmt.Errorf("config must be a JSON object under 1 MiB")
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return c, fmt.Errorf("config: %w", err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return c, fmt.Errorf("config: expected one JSON object")
		}
	}
	return c, c.Validate()
}

// Endpoint accepts only an explicit HTTP(S) endpoint, never a credential-bearing URL.
func Endpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("endpoint must be an HTTP(S) URL without credentials, query, or fragment")
	}
	if u.Port() != "" {
		n, err := strconv.Atoi(u.Port())
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid endpoint port")
		}
	}
	return u, nil
}

func (c Config) Validate() error {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen must be a loopback IP and port: %w", err)
	}
	ip := net.ParseIP(host)
	p, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("listen must use a loopback IP and port 1..65535")
	}
	if c.CacheSize < 1 || c.CacheSize > 1_000_000 || c.MaxConcurrent < 1 || c.MaxConcurrent > 10000 {
		return fmt.Errorf("invalid cache_size or max_concurrent")
	}
	for _, d := range []Duration{c.ResolveTimeout, c.ResponseHeaderTimeout, c.CacheTTL, c.NegativeCacheTTL} {
		if d <= 0 {
			return fmt.Errorf("timeouts and cache TTLs must be positive")
		}
	}
	for key, raw := range map[string]string{"ethereum_rpc": c.EthereumRPC, "solana_rpc": c.SolanaRPC, "ton_proxy": c.TONProxy} {
		if raw == "" {
			continue
		}
		u, err := Endpoint(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		if key == "ton_proxy" && u.Path != "" && u.Path != "/" {
			return fmt.Errorf("ton_proxy cannot have a path")
		}
		if isSelf(u, host, port) {
			return fmt.Errorf("%s points back to the proxy listener", key)
		}
	}
	for key, list := range map[string][]string{"ipfs_gateways": c.IPFSGateways, "arweave_gateways": c.ArweaveGateways} {
		if len(list) == 0 || len(list) > 2 {
			return fmt.Errorf("%s must contain one or two ordered gateways", key)
		}
		for _, raw := range list {
			u, err := Endpoint(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
			if u.Path != "" && u.Path != "/" {
				return fmt.Errorf("%s must use a gateway origin without a path", key)
			}
			if key == "ipfs_gateways" && net.ParseIP(u.Hostname()) != nil {
				return fmt.Errorf("ipfs_gateways requires a DNS hostname, e.g. localhost, for subdomain addressing")
			}
			if strings.ContainsAny(u.Hostname(), "_%") {
				return fmt.Errorf("invalid gateway hostname")
			}
			if isSelf(u, host, port) {
				return fmt.Errorf("%s points back to the proxy listener", key)
			}
		}
	}
	return nil
}

func isSelf(u *url.URL, host, port string) bool {
	up := u.Port()
	if up == "" {
		if u.Scheme == "https" {
			up = "443"
		} else {
			up = "80"
		}
	}
	if up != port {
		return false
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	return h == host || h == "localhost" || (net.ParseIP(h) != nil && net.ParseIP(h).IsLoopback())
}
