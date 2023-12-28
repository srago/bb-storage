package spiffebundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/buildbarn/bb-storage/pkg/clock"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func newSPIFFECaCertAndKey(td spiffeid.TrustDomain) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	u, err := url.Parse(td.IDString())
	if err != nil {
		return nil, nil, err
	}
	now := clock.SystemClock.Now()
	name := pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"Acme Corp."},
	}
	cert := &x509.Certificate{
		Subject:               name,
		Issuer:                name,
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{u},
	}
	cert, key, err := signCert(cert)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func signCert(req *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	publicKey := privateKey.Public()
	req.SerialNumber, _ = rand.Int(rand.Reader, big.NewInt(666))

	certData, err := x509.CreateCertificate(rand.Reader, req, req, publicKey, privateKey)  // self-sign
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, nil, err
	}
	return cert, privateKey, nil
}

func makeCaPemFile(t *testing.T, spiffeId string) (string) {
	td, err := spiffeid.TrustDomainFromString(spiffeId)
	if err != nil {
		t.Errorf("can't extract SPIFFE ID: %v", err)
	}
	caCert, _, err := newSPIFFECaCertAndKey(td)
	if err != nil {
		t.Errorf("can't create CA cert & key: %v", err)
	}
	certPath := t.TempDir() + "/ca_cert.pem"
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Errorf("can't create %s: %v", certPath, err)
	}
	defer certFile.Close()
	err = pem.Encode(certFile, &pem.Block{
		Type:   "CERTIFICATE",
		Bytes:  caCert.Raw,
	})
	if err != nil {
		t.Errorf("can't encode cert to %s: %v", certPath, err)
	}
	return certPath
}

func TestGCPCertSucceeds(t *testing.T) {
	filename := makeCaPemFile(t, "spiffe://acme.com.svc.id.goog/ns/project-id/sa/system-acct")
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Errorf("can't read creds: %v", err)
	}
	td, err := spiffeid.TrustDomainFromString("spiffe://acme.com.svc.id.goog/ns/project-id/sa/system-acct")
	if err != nil {
		t.Errorf("can't convert string to trust domain: %v", err)
	}
	src := New()
	bundle, err := x509bundle.Parse(td, b)
	if err != nil {
		t.Errorf("can't parse bundle: %v", err)
	}
	src.Add(bundle, ".svc.id.goog")

	foundBundle, err := src.GetX509BundleForTrustDomain(td)
	if err != nil {
		t.Errorf("GetX509BundleForTrustDomain failed: %v", err)
	}
	if !bundle.Equal(foundBundle) {
		t.Error("Found different bundle")
	}
}

func TestGCPCertFails(t *testing.T) {
	filename := makeCaPemFile(t, "spiffe://acme.com.svc.id.goog/ns/project-id/sa/system-acct")
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Errorf("can't read creds: %v", err)
	}
	td, err := spiffeid.TrustDomainFromString("spiffe://acme.com.svc.id.goog/ns/project-id/sa/system-acct")
	if err != nil {
		t.Errorf("can't convert string to trust domain: %v", err)
	}
	src := New()
	bundle, err := x509bundle.Parse(td, b)
	if err != nil {
		t.Errorf("can't parse bundle: %v", err)
	}
	src.Add(bundle, ".onprem.signed.goog")

	foundBundle, err := src.GetX509BundleForTrustDomain(td)
	if err == nil {
		t.Errorf("GetX509BundleForTrustDomain should have failed")
	}
	if foundBundle != nil {
		t.Error("Found a bundle but shouldn't have")
	}
}

func TestMultiGCPCertSucceeds(t *testing.T) {
	filename := makeCaPemFile(t, "spiffe://acme.com.svc.id.goog/ns/project-id/sa/system-acct")
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Errorf("can't read creds: %v", err)
	}
	td1, err := spiffeid.TrustDomainFromString("spiffe://acme.com.svc.id.goog/ns/project-id/sa/system-acct")
	if err != nil {
		t.Errorf("can't convert string to trust domain: %v", err)
	}
	td2, err := spiffeid.TrustDomainFromString("spiffe://acme.com.onprem.signed.goog/ns/project-id/sa/system-acct")

	if err != nil {
		t.Errorf("can't convert string to trust domain: %v", err)
	}
	src := New()
	bundle, err := x509bundle.Parse(td1, b)
	if err != nil {
		t.Errorf("can't parse bundle: %v", err)
	}
	src.Add(bundle, ".svc.id.goog", ".onprem.signed.goog")

	foundBundle, err := src.GetX509BundleForTrustDomain(td1)
	if err != nil {
		t.Errorf("GetX509BundleForTrustDomain failed: %v", err)
	}
	if !bundle.Equal(foundBundle) {
		t.Error("Found different bundle")
	}
	foundBundle, err = src.GetX509BundleForTrustDomain(td2)
	if err != nil {
		t.Errorf("GetX509BundleForTrustDomain failed: %v", err)
	}
	if !bundle.Equal(foundBundle) {
		t.Error("Found different bundle")
	}
}

func TestSubstringMatchesAtMostOneTrustDomain(t *testing.T) {
	var tds []string
	patterns := [...]string{".svc.id.goog", ".onprem.signed.goog"}
	td, err := spiffeid.TrustDomainFromString("spiffe://acme.com.svc.id.goog/ns/project-id/sa/system-acct")
	if err != nil {
		t.Errorf("can't convert string to trust domain: %v", err)
	}
	tds = append(tds, td.String())
	td, err = spiffeid.TrustDomainFromString("spiffe://acme.com.onprem.signed.goog/ns/project-id/sa/system-acct")
	if err != nil {
		t.Errorf("can't convert string to trust domain: %v", err)
	}
	tds = append(tds, td.String())
	for _, p := range patterns {
		match := 0
		for _, ts := range tds {
			if strings.Contains(ts, p) {
				match++
			}
		}
		if match > 1 {
			t.Error("pattern matched more than one trust domain")
		}
		if match == 0 {
			t.Error("pattern didn't match any trust domain")
		}
	}
}
