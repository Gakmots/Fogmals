package netutil

import (
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestCCIPNetworkBoundary(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "10.0.0.1", "172.16.0.2", "192.168.1.1", "169.254.169.254", "100.64.0.1", "224.0.0.1", "0.0.0.0", "198.18.1.1", "fc00::1", "fe80::1", "64:ff9b::a00:1", "2002:a00:1::"} {
		if PublicIP(netip.MustParseAddr(ip)) {
			t.Errorf("allowed %s", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !PublicIP(netip.MustParseAddr(ip)) {
			t.Errorf("rejected %s", ip)
		}
	}
	for _, tc := range []struct {
		enabled bool
		url     string
	}{{true, "http://example.com"}, {true, "https://127.0.0.1:1"}, {true, "https://[::1]:1"}, {false, "https://example.com"}} {
		c := CCIPClient(tc.enabled, time.Second)
		r, _ := http.NewRequest(http.MethodGet, tc.url, nil)
		if resp, err := c.Do(r); err == nil {
			resp.Body.Close()
			t.Fatalf("allowed %v", tc)
		}
		c.CloseIdleConnections()
	}
}
