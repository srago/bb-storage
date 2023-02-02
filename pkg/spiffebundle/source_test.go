package spiffebundle

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func TestGCPCertSucceeds(t *testing.T) {
	b, err := ioutil.ReadFile("/run/secrets/workload-spiffe-credentials/ca_certificates.pem")
	if err != nil {
		t.Errorf("can't read creds: %v", err)
	}
	td, err := spiffeid.TrustDomainFromString("spiffe://sky-did-82840-desktop-6.svc.id.goog/ns/projector-ragost/sa/projector-ragost")
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
	b, err := ioutil.ReadFile("/run/secrets/workload-spiffe-credentials/ca_certificates.pem")
	if err != nil {
		t.Errorf("can't read creds: %v", err)
	}
	td, err := spiffeid.TrustDomainFromString("spiffe://sky-did-82840-desktop-6.svc.id.goog/ns/projector-ragost/sa/projector-ragost")
	if err != nil {
		t.Errorf("can't convert string to trust domain: %v", err)
	}
	src := New()
	bundle, err := x509bundle.Parse(td, b)
	if err != nil {
		t.Errorf("can't parse bundle: %v", err)
	}
	src.Add(bundle, ".global.workload.id.goog")

	foundBundle, err := src.GetX509BundleForTrustDomain(td)
	if err == nil {
		t.Errorf("GetX509BundleForTrustDomain should have failed")
	}
	if foundBundle != nil {
		t.Error("Found a bundle but shouldn't have")
	}
}

func TestMultiGCPCertSucceeds(t *testing.T) {
	b, err := ioutil.ReadFile("/run/secrets/workload-spiffe-credentials/ca_certificates.pem")
	if err != nil {
		t.Errorf("can't read creds: %v", err)
	}
	td1, err := spiffeid.TrustDomainFromString("spiffe://sky-did-82840-desktop-6.svc.id.goog/ns/projector-ragost/sa/projector-ragost")
	if err != nil {
		t.Errorf("can't convert string to trust domain: %v", err)
	}
	td2, err := spiffeid.TrustDomainFromString("spiffe://gsinet-gcp-wif-v1.60151081759.global.workload.id.goog/subject/ragost")
	if err != nil {
		t.Errorf("can't convert string to trust domain: %v", err)
	}
	src := New()
	bundle, err := x509bundle.Parse(td1, b)
	if err != nil {
		t.Errorf("can't parse bundle: %v", err)
	}
	src.Add(bundle, ".svc.id.goog", ".global.workload.id.goog")

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
	patterns := [...]string{".svc.id.goog", ".global.workload.id.goog"}
	td, err := spiffeid.TrustDomainFromString("spiffe://sky-did-82840-desktop-6.svc.id.goog/ns/projector-ragost/sa/projector-ragost")
	if err != nil {
		t.Errorf("can't convert string to trust domain: %v", err)
	}
	tds = append(tds, td.String())
	td, err = spiffeid.TrustDomainFromString("spiffe://gsinet-gcp-wif-v1.60151081759.global.workload.id.goog/subject/ragost")
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
