package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

const (
	testPatIss = "https://auth.orbitport.test"
	testPatAud = "https://api.orbitport.test"
)

// mockIssuer is an in-process gRPC issuer plugin serving a swappable JWKS.
type mockIssuer struct {
	proto.UnimplementedIssuerPluginServer

	mu    sync.Mutex
	jwks  string
	calls int
}

func (m *mockIssuer) GetJwks(context.Context, *proto.GetJwksRequest) (*proto.GetJwksResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return &proto.GetJwksResponse{JwksJson: m.jwks}, nil
}

func (m *mockIssuer) setJWKS(jwks string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jwks = jwks
}

func (m *mockIssuer) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func startMockIssuer(t *testing.T, m *mockIssuer) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	proto.RegisterIssuerPluginServer(srv, m)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func jwksJSON(kid string, pub *ecdsa.PublicKey) string {
	x := pub.X.FillBytes(make([]byte, 32))
	y := pub.Y.FillBytes(make([]byte, 32))
	return fmt.Sprintf(
		`{"keys":[{"kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":%q,"x":%q,"y":%q}]}`,
		kid,
		base64.RawURLEncoding.EncodeToString(x),
		base64.RawURLEncoding.EncodeToString(y),
	)
}

func newP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func patClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":        testPatIss,
		"aud":        testPatAud,
		"sub":        "acct-1",
		"jti":        "pat-jti-1",
		"kms_tenant": "tenant-1",
		"iat":        now.Unix(),
		"exp":        now.Add(time.Hour).Unix(),
	}
}

func mintES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// newTestPlugin builds the plugin via NewPlugin with the PAT path pointed at
// the in-process issuer mock. The Auth0 domain is a dead hostname: the legacy
// path only dials it when a non-PAT token comes in, and then errors — which
// is exactly what the fall-through test asserts.
func newTestPlugin(t *testing.T, issuerAddr string) *Plugin {
	t.Helper()
	viper.Reset()
	t.Setenv("ORBITPORT_AUTH0_DOMAIN", "auth0.invalid")
	t.Setenv("ORBITPORT_AUTH0_AUDIENCE", testPatAud)
	t.Setenv("ORBITPORT_AUTH_PAT_ISS", testPatIss)
	t.Setenv("ORBITPORT_AUTH_PAT_AUDIENCE", testPatAud)
	t.Setenv("ORBITPORT_AUTH_ISSUER_PLUGIN", issuerAddr)
	viper.SetEnvPrefix("ORBITPORT")
	viper.AutomaticEnv()

	p, err := NewPlugin()
	require.NoError(t, err)
	return p
}

func TestValidateToken_PATHappyPath(t *testing.T) {
	key := newP256Key(t)
	mock := &mockIssuer{jwks: jwksJSON("kid-1", &key.PublicKey)}
	p := newTestPlugin(t, startMockIssuer(t, mock))

	token := mintES256(t, key, "kid-1", patClaims())

	resp, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: token})
	require.NoError(t, err)
	require.True(t, resp.Ok)
	require.Equal(t, "acct-1", resp.ClientId)
	require.Equal(t, "pat-jti-1", resp.Jti)
	require.Equal(t, "tenant-1", resp.KmsTenant)

	// Absent kms_tenant claim (pre-D9-backfill PATs) → empty string.
	claims := patClaims()
	delete(claims, "kms_tenant")
	resp, err = p.ValidateToken(context.Background(), &proto.TokenValidationRequest{
		Token: mintES256(t, key, "kid-1", claims),
	})
	require.NoError(t, err)
	require.Empty(t, resp.KmsTenant)
}

func TestValidateToken_WrongIssFallsThroughToAuth0(t *testing.T) {
	key := newP256Key(t)
	mock := &mockIssuer{jwks: jwksJSON("kid-1", &key.PublicKey)}
	p := newTestPlugin(t, startMockIssuer(t, mock))

	claims := patClaims()
	claims["iss"] = "https://somewhere-else.test"
	token := mintES256(t, key, "kid-1", claims)

	// Routed to the Auth0 path (dead domain) — must error, and must never
	// have touched the issuer mock.
	_, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: token})
	require.Error(t, err)
	require.Equal(t, 0, mock.callCount())
}

func TestValidateToken_UnknownKidRefetches(t *testing.T) {
	oldKey := newP256Key(t)
	newKey := newP256Key(t)
	mock := &mockIssuer{jwks: jwksJSON("kid-old", &oldKey.PublicKey)}
	p := newTestPlugin(t, startMockIssuer(t, mock))

	// Prime the cache with the old key.
	_, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{
		Token: mintES256(t, oldKey, "kid-old", patClaims()),
	})
	require.NoError(t, err)
	require.Equal(t, 1, mock.callCount())

	// Rotate: mock now serves only the new key; a token signed with it has
	// an unknown kid, which must trigger exactly one refetch and then verify.
	mock.setJWKS(jwksJSON("kid-new", &newKey.PublicKey))
	resp, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{
		Token: mintES256(t, newKey, "kid-new", patClaims()),
	})
	require.NoError(t, err)
	require.True(t, resp.Ok)
	require.Equal(t, 2, mock.callCount())
}

func TestValidateToken_ExpiredPATRejected(t *testing.T) {
	key := newP256Key(t)
	mock := &mockIssuer{jwks: jwksJSON("kid-1", &key.PublicKey)}
	p := newTestPlugin(t, startMockIssuer(t, mock))

	claims := patClaims()
	claims["iat"] = time.Now().Add(-time.Hour).Unix()
	claims["exp"] = time.Now().Add(-5 * time.Minute).Unix() // beyond the 1min leeway
	token := mintES256(t, key, "kid-1", claims)

	_, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: token})
	require.Error(t, err)
	require.ErrorIs(t, err, jwt.ErrTokenExpired)
	// Gateway contract: expired PATs are distinguishable by this prefix.
	require.True(t, strings.HasPrefix(err.Error(), "pat_expired:"), "got: %v", err)
}

func TestValidateToken_AlgConfusionRejected(t *testing.T) {
	esKey := newP256Key(t)
	mock := &mockIssuer{jwks: jwksJSON("kid-1", &esKey.PublicKey)}
	p := newTestPlugin(t, startMockIssuer(t, mock))

	// RS256-signed token carrying the PAT iss routes to the PAT path and
	// must be rejected by WithValidMethods(["ES256"]).
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, patClaims())
	token.Header["kid"] = "kid-1"
	signed, err := token.SignedString(rsaKey)
	require.NoError(t, err)

	_, err = p.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: signed})
	require.Error(t, err)
	require.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
}

func TestValidateToken_MissingJtiRejected(t *testing.T) {
	key := newP256Key(t)
	mock := &mockIssuer{jwks: jwksJSON("kid-1", &key.PublicKey)}
	p := newTestPlugin(t, startMockIssuer(t, mock))

	claims := patClaims()
	delete(claims, "jti")
	token := mintES256(t, key, "kid-1", claims)

	_, err := p.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: token})
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing jti")
}

func TestNewPlugin_PartialPatConfigFailsStartup(t *testing.T) {
	viper.Reset()
	t.Setenv("ORBITPORT_AUTH0_DOMAIN", "auth0.invalid")
	t.Setenv("ORBITPORT_AUTH0_AUDIENCE", testPatAud)
	t.Setenv("ORBITPORT_AUTH_PAT_ISS", testPatIss)
	// ORBITPORT_AUTH_ISSUER_PLUGIN deliberately unset — fail-closed.
	viper.SetEnvPrefix("ORBITPORT")
	viper.AutomaticEnv()

	_, err := NewPlugin()
	require.Error(t, err)
	require.Contains(t, err.Error(), "ORBITPORT_AUTH_ISSUER_PLUGIN")
}
