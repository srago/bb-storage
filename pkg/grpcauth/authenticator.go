package grpcauth

import (
	"context"
	"crypto/x509"

	"github.com/buildbarn/bb-storage/pkg/auth"
	"github.com/buildbarn/bb-storage/pkg/clock"
	"github.com/buildbarn/bb-storage/pkg/jwt"
	"github.com/buildbarn/bb-storage/pkg/program"
	configuration "github.com/buildbarn/bb-storage/pkg/proto/configuration/grpc"
	"github.com/buildbarn/bb-storage/pkg/util"
	"github.com/jmespath/go-jmespath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Authenticator can be used to grant or deny access to a gRPC server.
// Implementations may grant access based on TLS connection state,
// provided headers, source IP address ranges, etc. etc. etc.
type Authenticator interface {
	Authenticate(ctx context.Context) (*auth.AuthenticationMetadata, error)
}

// NewAuthenticatorFromConfiguration creates a tree of Authenticator
// objects based on a configuration file.
func NewAuthenticatorFromConfiguration(policy *configuration.AuthenticationPolicy, group program.Group) (Authenticator, bool, bool, error) {
	if policy == nil {
		return nil, false, false, status.Error(codes.InvalidArgument, "Authentication policy not specified")
	}
	switch policyKind := policy.Policy.(type) {
	case *configuration.AuthenticationPolicy_Allow:
		authenticationMetadata, err := auth.NewAuthenticationMetadataFromProto(policyKind.Allow)
		if err != nil {
			return nil, false, false, status.Error(codes.InvalidArgument, "Failed to create authentication metadata")
		}
		return NewAllowAuthenticator(authenticationMetadata), false, false, nil
	case *configuration.AuthenticationPolicy_Any:
		children := make([]Authenticator, 0, len(policyKind.Any.Policies))
		needsPeerTransportCredentials := false
		requestTLSClientCertificate := false
		for _, childConfiguration := range policyKind.Any.Policies {
			child, childNeedsPeerTransportCredentials, childRequestTLSClientCertificate, err := NewAuthenticatorFromConfiguration(childConfiguration, group)
			if err != nil {
				return nil, false, false, err
			}
			children = append(children, child)
			needsPeerTransportCredentials = needsPeerTransportCredentials || childNeedsPeerTransportCredentials
			requestTLSClientCertificate = requestTLSClientCertificate || childRequestTLSClientCertificate
		}
		return NewAnyAuthenticator(children), needsPeerTransportCredentials, requestTLSClientCertificate, nil
	case *configuration.AuthenticationPolicy_All:
		children := make([]Authenticator, 0, len(policyKind.All.Policies))
		needsPeerTransportCredentials := false
		requestTLSClientCertificate := false
		for _, childConfiguration := range policyKind.All.Policies {
			child, childNeedsPeerTransportCredentials, childRequestTLSClientCertificate, err := NewAuthenticatorFromConfiguration(childConfiguration, group)
			if err != nil {
				return nil, false, false, err
			}
			children = append(children, child)
			needsPeerTransportCredentials = needsPeerTransportCredentials || childNeedsPeerTransportCredentials
			requestTLSClientCertificate = requestTLSClientCertificate || childRequestTLSClientCertificate
		}
		return NewAllAuthenticator(children), needsPeerTransportCredentials, requestTLSClientCertificate, nil
	case *configuration.AuthenticationPolicy_Deny:
		return NewDenyAuthenticator(policyKind.Deny), false, false, nil
	case *configuration.AuthenticationPolicy_TlsClientCertificate:
                // If we're using mTLS, use the allow authenticator instead, because the TLS handshake will take care of
                // validating the client's identity.
                if policyKind.TlsClientCertificate.Spiffe != nil {
			var m auth.AuthenticationMetadata
			return NewAllowAuthenticator(&m), false, nil
                }
		clientCAs := x509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM([]byte(policyKind.TlsClientCertificate.ClientCertificateAuthorities)) {
			return nil, false, false, status.Error(codes.InvalidArgument, "Failed to parse client certificate authorities")
		}
		validator, err := jmespath.Compile(policyKind.TlsClientCertificate.ValidationJmespathExpression)
		if err != nil {
			return nil, false, false, util.StatusWrap(err, "Failed to compile validation JMESPath expression")
		}
		metadataExtractor, err := jmespath.Compile(policyKind.TlsClientCertificate.MetadataExtractionJmespathExpression)
		if err != nil {
			return nil, false, false, util.StatusWrap(err, "Failed to compile metadata extraction JMESPath expression")
		}
		return NewTLSClientCertificateAuthenticator(
			clientCAs,
			clock.SystemClock,
			validator,
			metadataExtractor,
		), false, true, nil
	case *configuration.AuthenticationPolicy_Jwt:
		authorizationHeaderParser, err := jwt.NewAuthorizationHeaderParserFromConfiguration(policyKind.Jwt, group)
		if err != nil {
			return nil, false, false, util.StatusWrap(err, "Failed to create authorization header parser for JWT authentication policy")
		}
		return NewJWTAuthenticator(authorizationHeaderParser), false, false, nil
	case *configuration.AuthenticationPolicy_PeerCredentialsJmespathExpression:
		metadataExtractor, err := jmespath.Compile(policyKind.PeerCredentialsJmespathExpression)
		if err != nil {
			return nil, false, false, util.StatusWrap(err, "Failed to compile peer credentials metadata extraction JMESPath expression")
		}
		return NewPeerCredentialsAuthenticator(metadataExtractor), true, false, nil
	default:
		return nil, false, false, status.Error(codes.InvalidArgument, "Configuration did not contain an authentication policy type")
	}
}
