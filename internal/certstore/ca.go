// Package certstore manages an installation-specific CA and bounded leaf cache.
// It never changes the operating system or browser trust store.
package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

type Authority struct {
	ca    tls.Certificate
	cache *lru.Cache[string, *tls.Certificate]
	mu    sync.Mutex
}

func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }

// Init creates a new CA exclusively; an existing key or certificate is never
// replaced. Only ca.pem should be imported into a user's trust store.
func Init(certPath, keyPath string) error {
	if filepath.Clean(certPath) == filepath.Clean(keyPath) {
		return fmt.Errorf("CA certificate and key paths must differ")
	}
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("CA file already exists: %s", p)
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	n, err := serial()
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: n, Subject: pkix.Name{CommonName: "dwebproxy Local Web3 CA"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{".eth", ".sns", ".ton"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeExclusive(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600); err != nil {
		return err
	}
	if err := writeExclusive(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		os.Remove(keyPath)
		return err
	}
	return nil
}

func writeExclusive(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	closeErr := f.Close()
	if err != nil {
		os.Remove(path)
		return err
	}
	if closeErr != nil {
		os.Remove(path)
		return closeErr
	}
	return nil
}

func Load(certPath, keyPath string, size int) (*Authority, error) {
	info, err := os.Lstat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load CA key (run -init-ca first): %w", err)
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, fmt.Errorf("CA key must be a regular private file (0600)")
	}
	ca, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}
	ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if !ca.Leaf.IsCA || ca.Leaf.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(ca.Leaf.NotBefore) || !now.Before(ca.Leaf.NotAfter) {
		return nil, fmt.Errorf("CA certificate is not a currently valid signing CA")
	}
	cache, err := lru.New[string, *tls.Certificate](size)
	if err != nil {
		return nil, err
	}
	return &Authority{ca: ca, cache: cache}, nil
}

func validName(name string) bool {
	if name != strings.ToLower(name) || !(strings.HasSuffix(name, ".eth") || strings.HasSuffix(name, ".sns") || strings.HasSuffix(name, ".ton")) {
		return false
	}
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func (a *Authority) Certificate(name string) (*tls.Certificate, error) {
	if !validName(name) {
		return nil, fmt.Errorf("CA only signs ASCII .eth, .sns and .ton names")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if now.Before(a.ca.Leaf.NotBefore) || !now.Before(a.ca.Leaf.NotAfter) {
		return nil, fmt.Errorf("CA expired or not yet valid")
	}
	if cert, ok := a.cache.Get(name); ok && cert.Leaf.NotAfter.After(now.Add(time.Minute)) {
		return cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	n, err := serial()
	if err != nil {
		return nil, err
	}
	expires := now.Add(24 * time.Hour)
	if expires.After(a.ca.Leaf.NotAfter) {
		expires = a.ca.Leaf.NotAfter
	}
	template := &x509.Certificate{SerialNumber: n, DNSNames: []string{name}, NotBefore: now.Add(-time.Minute), NotAfter: expires,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, a.ca.Leaf, &key.PublicKey, a.ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	a.cache.Add(name, cert)
	return cert, nil
}
