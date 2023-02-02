package bb_tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"sync"
	"time"

	"github.com/buildbarn/bb-storage/pkg/authenticator"
	"github.com/buildbarn/bb-storage/pkg/clock"
	"github.com/buildbarn/bb-storage/pkg/spiffebundle"
	"github.com/buildbarn/bb-storage/pkg/util"
	configuration "github.com/buildbarn/bb-storage/pkg/proto/configuration/tls"
	grpc_cfg "github.com/buildbarn/bb-storage/pkg/proto/configuration/grpc"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TLS management with support for SPIFFE mTLS.  If you're using SPIFFE mTLS, it assumes:
// 1. Certs and keys are stored in PEM files, so the configuration strings are pathnames to these
//    objects rather than the inlined objects themselves.
// 2. Workload Identity (or some other entity) is rotating certificates on whatever basis makes
//    sense for your organization.
// 3. The spiffebundle.GCPSource object holds the certificate chain for the certificate authorities.
//    This assumes you share a common certificate authority across your organization, regardless
//    of how many trust domains are in use.

type certInfo struct {
	mu      sync.Mutex
	svid    *x509svid.SVID
	td      spiffeid.TrustDomain
	bundle  *spiffebundle.GCPSource
}

var cipherSuiteIDs = map[string]uint16{}

func init() {
	// Initialize the map of cipher suite IDs based on the ciphers
	// supported by the Go TLS library.
	for _, cipherSuite := range tls.CipherSuites() {
		cipherSuiteIDs[cipherSuite.Name] = cipherSuite.ID
	}
}

func getBaseTLSConfig(cipherSuites []string) (*tls.Config, error) {
	tlsConfig := tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Resolve all provided cipher suite names.
	for _, cipherSuite := range cipherSuites {
		id, ok := cipherSuiteIDs[cipherSuite]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "Unsupported cipher suite: %#v", cipherSuite)
		}
		tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, id)
	}

	return &tlsConfig, nil
}

// NewTLSConfigFromClientConfiguration creates a TLS configuration
// object based on parameters specified in a Protobuf message for use
// with a TLS client. This Protobuf message is embedded in Buildbarn
// configuration files.
func NewTLSConfigFromClientConfiguration(configuration *configuration.ClientConfiguration) (*tls.Config, error) {
	if configuration == nil {
		return nil, nil
	}

	tlsConfig, err := getBaseTLSConfig(configuration.CipherSuites)
	if err != nil {
		return nil, err
	}
	tlsConfig.ServerName = configuration.ServerName

	var ci *certInfo
	if configuration.ClientCertificate != "" && configuration.ClientPrivateKey != "" {
		if util.IsPEMFile(configuration.ClientCertificate) && util.IsPEMFile(configuration.ClientPrivateKey) && util.IsPEMFile(configuration.ServerCertificateAuthorities) {
			ci, err = newCertInfo(configuration.ClientCertificate, configuration.ClientPrivateKey, configuration.ServerCertificateAuthorities)
			if err != nil {
				return nil, util.StatusWrapWithCode(err, codes.InvalidArgument, "Invalid client certificate or private key")
			}
		} else {
			// Serve a client certificate when provided.
			cert, err := tls.X509KeyPair([]byte(configuration.ClientCertificate), []byte(configuration.ClientPrivateKey))
			if err != nil {
				return nil, util.StatusWrapWithCode(err, codes.InvalidArgument, "Invalid client certificate or private key")
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	if util.IsPEMFile(configuration.ServerCertificateAuthorities) {
		if configuration.Spiffe != nil {
			caPool, err := ci.getCACertPool()
			if err != nil {
				return nil, err
			}
			verifier := authenticator.NewMTLSCertificateVerifier(caPool, clock.SystemClock, configuration.Spiffe, configuration.ServerCertificateAuthorities)
			tlsConfig.VerifyPeerCertificate = verifier.GetVerifyCertificate(x509.ExtKeyUsageServerAuth)
			tlsconfig.HookMTLSClientConfig(tlsConfig, ci.svid, ci.bundle, tlsconfig.AuthorizeAny())
			tlsConfig.GetClientCertificate = ci.getClientCertificate(configuration.ClientCertificate, configuration.ClientPrivateKey,
				configuration.ServerCertificateAuthorities)
		}
	} else {
		if serverCAs := configuration.ServerCertificateAuthorities; serverCAs != "" {
			// Don't use the default root CA list. Use the ones
			// provided in the configuration instead.
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(serverCAs)) {
				return nil, status.Error(codes.InvalidArgument, "Invalid server certificate authorities")
			}
			tlsConfig.RootCAs = pool
		}
	}

	return tlsConfig, nil
}

// NewTLSConfigFromServerConfiguration creates a TLS configuration
// object based on parameters specified in a Protobuf message for use
// with a TLS server. This Protobuf message is embedded in Buildbarn
// configuration files.
func NewTLSConfigFromServerConfiguration(configuration *configuration.ServerConfiguration, authConfig *grpc_cfg.AuthenticationPolicy) (*tls.Config, error) {
	if configuration == nil {
		return nil, nil
	}

	tlsConfig, err := getBaseTLSConfig(configuration.CipherSuites)
	if err != nil {
		return nil, err
	}
	tlsConfig.ClientAuth = tls.RequestClientCert

	// Require the use of server-side certificates.
	if util.IsPEMFile(configuration.ServerCertificate) && util.IsPEMFile(configuration.ServerPrivateKey) {
		// Note: Server specifies CA using The grpcServers config authenticationPolicy:
		// { tlsClientCertificate: { clientCertificateAuthorities: "/path/to/ca_certificates.pem" } }
		ci, err := newCertInfo(configuration.ServerCertificate, configuration.ServerPrivateKey, "")
		if err != nil {
			return nil, util.StatusWrapWithCode(err, codes.InvalidArgument, "Invalid server certificate or private key")
		}
		if configuration.ValidateClientCerts {
			// Use mTLS.  AuthConfig has CA and SPIFFE matcher,
			tlsClientCert := authConfig.GetTlsClientCertificate()
			if tlsClientCert != nil {
				if tlsClientCert.Spiffe == nil {
					return nil, fmt.Errorf("MTLS configuration requires SPIFFE")
				}
				caPool := x509.NewCertPool()
				var caPathName string
				if util.IsPEMFile(tlsClientCert.ClientCertificateAuthorities) {
					// Read and parse the CA certificates file.
					caPathName = tlsClientCert.ClientCertificateAuthorities
					b, err := ioutil.ReadFile(caPathName)
					if err != nil {
						return nil, status.Errorf(codes.FailedPrecondition, "Can't read CA certs: %v", err)
					}
					if !caPool.AppendCertsFromPEM(b) {
						return nil, status.Error(codes.InvalidArgument, "Invalid server certificate authorities")
					}
					bdl, err := x509bundle.Parse(ci.td, b)
					if err != nil {
						return nil, err
					}
					// TODO(ragost): make these strings configurable
					ci.bundle.Add(bdl, ".svc.id.goog", ".global.workload.id.goog")
				} else {
					if !caPool.AppendCertsFromPEM([]byte(tlsClientCert.ClientCertificateAuthorities)) {
						return nil, status.Error(codes.InvalidArgument, "Failed to parse client certificate authorities")
					}
				}
				verifier := authenticator.NewMTLSCertificateVerifier(caPool, clock.SystemClock, tlsClientCert.Spiffe, caPathName)
				tlsConfig.VerifyPeerCertificate = verifier.GetVerifyCertificate(x509.ExtKeyUsageClientAuth)
				tlsconfig.HookMTLSServerConfig(tlsConfig, ci.svid, ci.bundle, tlsconfig.AuthorizeAny())
				tlsConfig.GetCertificate = ci.getCertificate(configuration.ServerCertificate, configuration.ServerPrivateKey, "")
			} else {
				// Possible config error.
				return nil, util.StatusWrapWithCode(err, codes.InvalidArgument, "Invalid server tls config")
			}
		}
	} else {
		cert, err := tls.X509KeyPair([]byte(configuration.ServerCertificate), []byte(configuration.ServerPrivateKey))
		if err != nil {
			return nil, util.StatusWrapWithCode(err, codes.InvalidArgument, "Invalid server certificate or private key")
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

func newCertInfo(certFile, keyFile, caCertFile string) (*certInfo, error) {
	ci := &certInfo{
		bundle: spiffebundle.New(),
	}
	err := ci.loadNewCerts(certFile, keyFile, caCertFile)
	if err != nil {
		return nil, err
	}
	log.Printf("CI: created %p\n", ci)
	return ci, nil
}

func (ci *certInfo) getClientCertificate(certFile, keyFile, caCertFile string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		ci.mu.Lock()
		defer ci.mu.Unlock()
		log.Printf("CI: %p getClientCert not before %v not after %v\n", ci, ci.svid.Certificates[0].NotBefore, ci.svid.Certificates[0].NotAfter)
		if time.Now().After(ci.svid.Certificates[0].NotAfter.Add(time.Minute * -15)) {
			// Cert is about to expire.  Some external entity is responsible for rotating Certs.
			// Reload the new ones.
			if err := ci.loadNewCerts(certFile, keyFile, caCertFile); err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "Can't reload certs: %v\n", err)
			}
			log.Printf("CI: %p Reload: getClientCert not before %v not after %v\n", ci, ci.svid.Certificates[0].NotBefore, ci.svid.Certificates[0].NotAfter)
		}
		c := ci.getTLSCert()
		return c, nil
	}
}

func (ci *certInfo) getCertificate(certFile, keyFile, caCertFile string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		ci.mu.Lock()
		defer ci.mu.Unlock()
		log.Printf("ClientHelloInfo: %#v\n", info)
		log.Printf("CI: %p getCert not before %v not after %v\n", ci, ci.svid.Certificates[0].NotBefore, ci.svid.Certificates[0].NotAfter)
		if time.Now().After(ci.svid.Certificates[0].NotAfter.Add(time.Minute * -15)) {
			// Cert is about to expire.  Some external entity is responsible for rotating Certs.
			// Reload the new ones.
			if err := ci.loadNewCerts(certFile, keyFile, caCertFile); err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "Can't reload certs: %v\n", err)
			}
			log.Printf("CI: %p Reload: getCert not before %v not after %v\n", ci, ci.svid.Certificates[0].NotBefore, ci.svid.Certificates[0].NotAfter)
		}
		c := ci.getTLSCert()
		return c, nil
	}
}

// Load new certs from the file system.  Caller must hold the mutex except in the special case
// where the certInfo object is being created and thus can't be accessed from other threads.
func (ci *certInfo) loadNewCerts(certFile, keyFile, caCertFile string) error {
	cb, err := ioutil.ReadFile(certFile)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "Can't read certificate: %v", err)
	}
	kb, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "Can't read key: %v", err)
	}
	ci.svid, err = x509svid.Parse(cb, kb)
	if err != nil {
		return err
	}
	certID, err := x509svid.IDFromCert(ci.svid.Certificates[0])
	if err != nil {
		return err
	}
	ci.td = certID.TrustDomain()

	if caCertFile != "" {
		b, err := ioutil.ReadFile(caCertFile)
		if err != nil {
			return status.Errorf(codes.FailedPrecondition, "Can't read CA certs: %v", err)
		}
		bdl, err := x509bundle.Parse(ci.td, b)
		if err != nil {
			return err
		}
		// TODO(ragost): make these strings configurable
		ci.bundle.Add(bdl, ".svc.id.goog", ".global.workload.id.goog")
	}
	log.Printf("CI: %p updated certs\n", ci)
	return nil
}

func (ci *certInfo) getTLSCert() *tls.Certificate {
	cert := &tls.Certificate{
		Certificate: make([][]byte, 0, len(ci.svid.Certificates)),
		PrivateKey:  ci.svid.PrivateKey,
	}
	for _, c := range ci.svid.Certificates {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	log.Printf("CI: %p ret certs\n", ci)
	return cert
}

func (ci *certInfo) getCACertPool() (*x509.CertPool, error) {
	p := x509.NewCertPool()
	bundle, err := ci.bundle.GetX509BundleForTrustDomain(ci.td)
	if err != nil { // shouldn't happen
		return nil, err
	}
	for _, cert := range bundle.X509Authorities() {
		p.AddCert(cert)
	}
	return p, nil
}
