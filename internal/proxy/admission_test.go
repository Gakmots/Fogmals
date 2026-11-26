package proxy

import (
	"crypto/tls"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"dwebproxy/internal/config"
)

type countingAuthority struct {
	certificateAuthority
	calls atomic.Int32
}

func (a *countingAuthority) Certificate(name string) (*tls.Certificate, error) {
	a.calls.Add(1)
	return a.certificateAuthority.Certificate(name)
}

func TestTunnelAdmissionPrecedesCertificateWork(t *testing.T) {
	c := config.Default()
	enableHTTPS(t, &c)
	c.HTTPS.MaxTunnels = 1
	h, _ := newHandler(t, c)
	signer := &countingAuthority{certificateAuthority: h.connect.ca}
	h.connect.ca = signer
	entry := httptest.NewServer(h)
	defer entry.Close()
	defer h.Close()
	first, resp := rawConnect(t, entry.URL, "first.eth:443")
	defer first.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	for _, name := range []string{"second.eth:443", "third.sns:443"} {
		conn, response := rawConnect(t, entry.URL, name)
		response.Body.Close()
		conn.Close()
		if response.StatusCode != 503 {
			t.Fatal(response.Status)
		}
	}
	if signer.calls.Load() != 1 {
		t.Fatalf("overloaded CONNECT performed certificate work: %d", signer.calls.Load())
	}
}
