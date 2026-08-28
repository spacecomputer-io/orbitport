package patissuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

func newTestPlugin(t *testing.T, extraEnv map[string]string) *Plugin {
	t.Helper()
	viper.Reset()
	t.Setenv("ORBITPORT_PATISSUER_ISS", "https://auth.orbitport.test")
	t.Setenv("ORBITPORT_PATISSUER_AUD", "https://api.orbitport.test")
	for k, v := range extraEnv {
		t.Setenv(k, v)
	}
	viper.SetEnvPrefix("ORBITPORT")
	viper.AutomaticEnv()

	p, err := NewPlugin()
	require.NoError(t, err)
	return p
}

func issueValid(t *testing.T, p *Plugin) string {
	t.Helper()
	resp, err := p.IssueToken(context.Background(), &proto.IssueTokenRequest{
		Jti:       "jti-1",
		Subject:   "acct-1",
		KmsTenant: "tenant-1",
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour).Unix(),
	})
	require.NoError(t, err)
	require.True(t, resp.Ok)
	require.NotEmpty(t, resp.Token)
	return resp.Token
}

func jwksKey(t *testing.T, p *Plugin) (kid string, pub *ecdsa.PublicKey) {
	t.Helper()
	resp, err := p.GetJwks(context.Background(), &proto.GetJwksRequest{})
	require.NoError(t, err)

	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal([]byte(resp.JwksJson), &set))
	require.Len(t, set.Keys, 1)
	k := set.Keys[0]
	require.Equal(t, "EC", k.Kty)
	require.Equal(t, "P-256", k.Crv)
	require.Equal(t, "ES256", k.Alg)
	require.Equal(t, "sig", k.Use)
	require.NotEmpty(t, k.Kid)

	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	require.NoError(t, err)
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	require.NoError(t, err)
	require.Len(t, xb, 32)
	require.Len(t, yb, 32)

	pub = &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}
	return k.Kid, pub
}

func TestIssueAndVerifyAgainstJWKS(t *testing.T) {
	p := newTestPlugin(t, nil)
	tokenString := issueValid(t, p)
	kid, pub := jwksKey(t, p)

	parsed, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer("https://auth.orbitport.test"),
		jwt.WithAudience("https://api.orbitport.test"),
		jwt.WithExpirationRequired(),
	)
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	require.Equal(t, kid, parsed.Header["kid"])

	claims := parsed.Claims.(jwt.MapClaims)
	require.Equal(t, "acct-1", claims["sub"])
	require.Equal(t, "jti-1", claims["jti"])
	require.Equal(t, "tenant-1", claims["kms_tenant"])
}

func TestKmsTenantOmittedWhenEmpty(t *testing.T) {
	p := newTestPlugin(t, nil)
	resp, err := p.IssueToken(context.Background(), &proto.IssueTokenRequest{
		Jti:       "jti-2",
		Subject:   "acct-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)

	parsed, _, err := jwt.NewParser().ParseUnverified(resp.Token, jwt.MapClaims{})
	require.NoError(t, err)
	_, present := parsed.Claims.(jwt.MapClaims)["kms_tenant"]
	require.False(t, present)
}

func TestIssueValidation(t *testing.T) {
	p := newTestPlugin(t, nil)
	future := time.Now().Add(time.Hour).Unix()

	cases := []struct {
		name string
		req  *proto.IssueTokenRequest
	}{
		{"missing jti", &proto.IssueTokenRequest{Subject: "a", ExpiresAt: future}},
		{"missing subject", &proto.IssueTokenRequest{Jti: "j", ExpiresAt: future}},
		{"expiry in past", &proto.IssueTokenRequest{Jti: "j", Subject: "a", ExpiresAt: time.Now().Add(-time.Minute).Unix()}},
		{"expiry beyond ceiling", &proto.IssueTokenRequest{Jti: "j", Subject: "a", ExpiresAt: time.Now().AddDate(2, 0, 0).Unix()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.IssueToken(context.Background(), tc.req)
			require.Error(t, err)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestStablePemKeyKeepsKid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))

	p1 := newTestPlugin(t, map[string]string{"ORBITPORT_PATISSUER_LOCAL_KEY_PEM": pemStr})
	kid1, _ := jwksKey(t, p1)
	p2 := newTestPlugin(t, map[string]string{"ORBITPORT_PATISSUER_LOCAL_KEY_PEM": pemStr})
	kid2, _ := jwksKey(t, p2)
	require.Equal(t, kid1, kid2)
}

func TestConfigFailClosed(t *testing.T) {
	viper.Reset()
	t.Setenv("ORBITPORT_PATISSUER_ISS", "")
	t.Setenv("ORBITPORT_PATISSUER_AUD", "")
	viper.SetEnvPrefix("ORBITPORT")
	viper.AutomaticEnv()

	_, err := NewPlugin()
	require.Error(t, err)
	require.Contains(t, err.Error(), "ORBITPORT_PATISSUER_ISS")
}

func TestTransitRequiresProxyURL(t *testing.T) {
	viper.Reset()
	t.Setenv("ORBITPORT_PATISSUER_ISS", "https://auth.orbitport.test")
	t.Setenv("ORBITPORT_PATISSUER_AUD", "https://api.orbitport.test")
	t.Setenv("ORBITPORT_PATISSUER_SIGNER", "transit")
	viper.SetEnvPrefix("ORBITPORT")
	viper.AutomaticEnv()

	_, err := NewPlugin()
	require.Error(t, err)
	require.Contains(t, err.Error(), "OPENBAO_PROXY_URL")
}
