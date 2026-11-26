package netutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"dwebproxy/internal/testutil"
)

func TestCCIPProxyPinsValidatedPublicIP(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("1.1.1.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "1.1.1.1" {
			t.Errorf("CCIP Host changed: %s", r.Host)
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://127.0.0.1/private", 302)
			return
		}
		io.WriteString(w, "offchain data")
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	origin.StartTLS()
	defer origin.Close()
	address, _ := url.Parse(origin.URL)
	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			p := testutil.NewProxy(t, scheme, func(ctx context.Context, network, target string) (net.Conn, error) {
				if target != "1.1.1.1:443" {
					t.Errorf("unvalidated/unpinned CCIP target reached proxy: %s", target)
				}
				return (&net.Dialer{}).DialContext(ctx, network, address.Host)
			})
			endpoint, _ := url.Parse(p.URL)
			dial, _ := NewDialer(endpoint)
			client := CCIPClient(true, 2*time.Second, dial)
			defer client.CloseIdleConnections()
			client.Transport.(*ccipTransport).base.TLSClientConfig = &tls.Config{RootCAs: roots}
			resp, err := client.Get("https://1.1.1.1/data")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "offchain data" || len(p.Requests) != 1 {
				t.Fatalf("CCIP proxy not used: body=%q connections=%d", body, len(p.Requests))
			}
			for _, target := range []string{"https://1.1.1.1/redirect", "https://127.0.0.1/private", "https://[::1]/", "https://10.0.0.1/", "http://1.1.1.1/", "https://user:pass@1.1.1.1/"} {
				if resp, err := client.Get(target); err == nil {
					resp.Body.Close()
					t.Errorf("unsafe CCIP destination accepted: %s", target)
				}
			}
			if len(p.Requests) != 1 {
				t.Fatal("unsafe CCIP destination reached program proxy")
			}
		})
	}
}
