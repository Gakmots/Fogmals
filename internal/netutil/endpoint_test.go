package netutil

import (
	"net/url"
	"testing"
)

func TestEndpointAddresses(t *testing.T) {
	for _, tc := range []struct {
		raw, address string
		port         int
	}{
		{"http://localhost", "localhost:80", 80},
		{"https://gateway.example", "gateway.example:443", 443},
		{"http://localhost:00080", "localhost:80", 80},
		{"https://gateway.example:00443", "gateway.example:443", 443},
		{"http://localhost:1", "localhost:1", 1},
		{"https://gateway.example:65535", "gateway.example:65535", 65535},
		{"http://[::1]", "[::1]:80", 80},
		{"https://[::1]:08443", "[::1]:8443", 8443},
		{"socks5://localhost", "localhost:1080", 1080},
		{"socks5h://[::1]:01081", "[::1]:1081", 1081},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			u, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			before := u.String()
			port, err := EndpointPort(u)
			if err != nil || port != tc.port {
				t.Fatalf("port=%d, err=%v", port, err)
			}
			address, err := EndpointAddress(u)
			if err != nil || address != tc.address {
				t.Fatalf("address=%q, err=%v", address, err)
			}
			if u.String() != before {
				t.Fatal("socket helper rewrote endpoint URL")
			}
		})
	}
	for _, raw := range []string{"http://host:", "https://[::1]:", "http://host:0", "http://host:65536", "ftp://host", "http:///missing"} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := EndpointAddress(u); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	if _, err := EndpointPort(nil); err == nil {
		t.Fatal("accepted nil endpoint")
	}
}
