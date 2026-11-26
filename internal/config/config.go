package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"dwebproxy/internal/netutil"
	"dwebproxy/internal/records"
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
	Listen                string           `json:"listen"`
	ListenProtocol        string           `json:"listen_protocol"`
	ProgramProxy          ProgramProxy     `json:"program_proxy"`
	EthereumRPC           string           `json:"ethereum_rpc"`
	SolanaRPC             string           `json:"solana_rpc"`
	IPFSGateways          []string         `json:"ipfs_gateways"`
	ArweaveGateways       []string         `json:"arweave_gateways"`
	SwarmGateways         []string         `json:"swarm_gateways"`
	TONProxy              string           `json:"ton_proxy"`
	FallbackProxy         string           `json:"fallback_proxy"`
	CCIPRead              bool             `json:"ccip_read"`
	ResolveTimeout        Duration         `json:"resolve_timeout"`
	ResponseHeaderTimeout Duration         `json:"response_header_timeout"`
	StreamIdleTimeout     Duration         `json:"stream_idle_timeout"`
	CacheTTL              Duration         `json:"cache_ttl"`
	NegativeCacheTTL      Duration         `json:"negative_cache_ttl"`
	CacheSize             int              `json:"cache_size"`
	MaxConcurrent         int              `json:"max_concurrent"`
	HTTPS                 HTTPS            `json:"https"`
	RecordPriority        records.Priority `json:"record_priority"`
}

func Default() Config {
	return Config{
		ListenProtocol: "http",
		Listen:         "127.0.0.1:18080", EthereumRPC: "https://ethereum-rpc.publicnode.com", SolanaRPC: "https://api.mainnet.solana.com",
		IPFSGateways: []string{"http://localhost:8080"}, ArweaveGateways: []string{"http://localhost:1984"},
		SwarmGateways: []string{"http://localhost:1633"},
		CCIPRead:      true, ResolveTimeout: Duration(15 * time.Second), ResponseHeaderTimeout: Duration(120 * time.Second),
		StreamIdleTimeout: Duration(120 * time.Second),
		CacheTTL:          Duration(time.Minute), NegativeCacheTTL: Duration(5 * time.Second), CacheSize: 1024, MaxConcurrent: 64,
		HTTPS:          HTTPS{Enabled: true, CACert: "certs/ca.pem", CAKey: "certs/ca-key.pem", ConnectPorts: []int{443}, HandshakeTimeout: Duration(10 * time.Second), TunnelIdleTimeout: Duration(5 * time.Minute), MaxTunnels: 64},
		RecordPriority: records.Default(),
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
		// Certificate paths are relative to the configuration file, not the shell.
		base, err := filepath.Abs(filepath.Dir(path))
		if err != nil {
			return c, err
		}
		if c.HTTPS.CACert != "" && !filepath.IsAbs(c.HTTPS.CACert) {
			c.HTTPS.CACert = filepath.Join(base, c.HTTPS.CACert)
		}
		if c.HTTPS.CAKey != "" && !filepath.IsAbs(c.HTTPS.CAKey) {
			c.HTTPS.CAKey = filepath.Join(base, c.HTTPS.CAKey)
		}
	}
	return c, c.Validate()
}

// Endpoint accepts only an explicit HTTP(S) endpoint, never a credential-bearing URL.
func Endpoint(raw string) (*url.URL, error) {
	return endpoint(raw, false)
}

// ProxyEndpoint accepts an explicit HTTP(S) or SOCKS5 next hop. RPCs and
// content gateways continue to use the HTTP-only Endpoint validator.
func ProxyEndpoint(raw string) (*url.URL, error) {
	u, err := endpoint(raw, true)
	if err != nil {
		return nil, err
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("proxy cannot have a path")
	}
	return u, nil
}

func endpoint(raw string, allowSOCKS bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint")
	}
	if (u.Scheme != "http" && u.Scheme != "https" && !(allowSOCKS && netutil.IsSOCKS(u))) || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("endpoint requires a supported scheme without credentials, query, or fragment")
	}
	if _, err := netutil.EndpointPort(u); err != nil {
		return nil, err
	}
	return u, nil
}

func (c Config) Validate() error {
	if c.ListenProtocol != "http" && c.ListenProtocol != "socks5" {
		return fmt.Errorf("listen_protocol must be http or socks5")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen must be a loopback IP and port: %w", err)
	}
	ip := net.ParseIP(host)
	p, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("listen must use a loopback IP and port 1..65535")
	}
	programProxy, err := c.ProgramProxy.Endpoint()
	if err != nil {
		return err
	}
	if programProxy != nil && isSelf(programProxy, host, p) {
		return fmt.Errorf("program_proxy points back to the proxy listener")
	}
	if c.CacheSize < 1 || c.CacheSize > 1_000_000 || c.MaxConcurrent < 1 || c.MaxConcurrent > 10000 {
		return fmt.Errorf("invalid cache_size or max_concurrent")
	}
	for _, d := range []Duration{c.ResolveTimeout, c.ResponseHeaderTimeout, c.StreamIdleTimeout, c.CacheTTL, c.NegativeCacheTTL} {
		if d <= 0 {
			return fmt.Errorf("timeouts and cache TTLs must be positive")
		}
	}
	if err := c.HTTPS.Validate(); err != nil {
		return err
	}
	if err := c.RecordPriority.Validate(); err != nil {
		return err
	}
	for key, raw := range map[string]string{"ethereum_rpc": c.EthereumRPC, "solana_rpc": c.SolanaRPC, "ton_proxy": c.TONProxy, "fallback_proxy": c.FallbackProxy} {
		if raw == "" {
			continue
		}
		parse := Endpoint
		if key == "ton_proxy" || key == "fallback_proxy" {
			parse = ProxyEndpoint
		}
		u, err := parse(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		if isSelf(u, host, p) {
			return fmt.Errorf("%s points back to the proxy listener", key)
		}
	}
	for key, list := range map[string][]string{"ipfs_gateways": c.IPFSGateways, "arweave_gateways": c.ArweaveGateways, "swarm_gateways": c.SwarmGateways} {
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
			if isSelf(u, host, p) {
				return fmt.Errorf("%s points back to the proxy listener", key)
			}
		}
	}
	return nil
}

func isSelf(u *url.URL, host string, port int) bool {
	up, err := netutil.EndpointPort(u)
	if err != nil || up != port {
		return false
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	return h == host || h == "localhost" || (net.ParseIP(h) != nil && net.ParseIP(h).IsLoopback())
}
