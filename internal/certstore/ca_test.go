package certstore

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateCAAndRestrictedCachedCertificates(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if err := Init(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(keyPath)
	if err := Init(certPath, keyPath); err == nil {
		t.Fatal("existing CA was overwritten")
	}
	after, _ := os.ReadFile(keyPath)
	if !bytes.Equal(before, after) {
		t.Fatal("existing key changed")
	}
	a, err := Load(certPath, keyPath, 2)
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := os.ReadFile(certPath)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("invalid CA PEM")
	}
	for _, name := range []string{"example.eth", "sub.example.sns", "example.ton"} {
		cert, err := a.Certificate(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Fatal(err)
		}
		cached, err := a.Certificate(name)
		if err != nil || cached != cert {
			t.Fatal("certificate was not reused")
		}
	}
	for _, name := range []string{"example.com", "example.eth.evil", "*.eth", "a..eth", "bad/host.eth", "Example.eth"} {
		if _, err := a.Certificate(name); err == nil {
			t.Errorf("CA signed %s", name)
		}
	}
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(certPath, keyPath, 2); err == nil {
		t.Fatal("publicly readable private key accepted")
	}
}

func TestSharedHostnameRulesKeepCertificatePolicy(t *testing.T) {
	for _, name := range []string{"example.eth", "a.b.c.sns", "a.b.c.ton"} {
		if !validName(name) {
			t.Errorf("rejected %s", name)
		}
	}
	for _, name := range []string{"Example.eth", "é.eth", "example.com", "*.eth", "a..eth", "a_b.ton"} {
		if validName(name) {
			t.Errorf("accepted %s", name)
		}
	}
}

func TestInitRequiresPathsEvenWhenHTTPSIsNotUsed(t *testing.T) {
	for _, emptyCert := range []bool{false, true} {
		dir := t.TempDir()
		cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "key.pem")
		if emptyCert {
			cert = ""
		} else {
			key = ""
		}
		if err := Init(cert, key); err == nil {
			t.Fatal("accepted empty CA path")
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("invalid CA initialization wrote files: %v %v", entries, err)
		}
	}
}
