package patissuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

// fakeTransit serves the two Transit endpoints backed by a real P-256 key,
// signing exactly like OpenBao does (hash-then-sign, JWS marshaling,
// vault:vN: envelope) so Mint output must verify for the test to pass.
func fakeTransit(t *testing.T, key *ecdsa.PrivateKey, version int) *httptest.Server {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/transit/keys/pat-signing", func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{"data": map[string]any{
			"type":           "ecdsa-p256",
			"latest_version": version,
			"keys": map[string]any{
				"1": map[string]string{"public_key": pubPEM},
			},
		}}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	})
	mux.HandleFunc("POST /v1/transit/sign/pat-signing/sha2-256", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Input               string `json:"input"`
			Prehashed           bool   `json:"prehashed"`
			MarshalingAlgorithm string `json:"marshaling_algorithm"`
			KeyVersion          int    `json:"key_version"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.False(t, body.Prehashed)
		require.Equal(t, "jws", body.MarshalingAlgorithm)
		require.Equal(t, version, body.KeyVersion)

		input, err := base64.StdEncoding.DecodeString(body.Input)
		require.NoError(t, err)
		digest := sha256.Sum256(input)
		r32, s32, err := ecdsa.Sign(rand.Reader, key, digest[:])
		require.NoError(t, err)
		sig := append(r32.FillBytes(make([]byte, 32)), s32.FillBytes(make([]byte, 32))...)

		resp := map[string]any{"data": map[string]string{
			"signature": "vault:v1:" + base64.RawURLEncoding.EncodeToString(sig),
		}}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	})
	return httptest.NewServer(mux)
}

func transitTestPlugin(t *testing.T, proxyURL string) *Plugin {
	t.Helper()
	return newTestPlugin(t, map[string]string{
		"ORBITPORT_PATISSUER_SIGNER":            "transit",
		"ORBITPORT_PATISSUER_OPENBAO_PROXY_URL": proxyURL,
	})
}

func TestTransitMintVerifiesAgainstJWKS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	srv := fakeTransit(t, key, 1)
	defer srv.Close()

	p := transitTestPlugin(t, srv.URL)
	tokenString := issueValid(t, p)
	kid, pub := jwksKey(t, p)
	require.Equal(t, "1", kid)

	parsed, err := jwt.Parse(
		tokenString,
		func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer("https://auth.orbitport.test"),
		jwt.WithAudience("https://api.orbitport.test"),
		jwt.WithExpirationRequired(),
	)
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	require.Equal(t, "1", parsed.Header["kid"])
}

func TestTransitRejectsUnvettedKeyType(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/transit/keys/pat-signing", func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{"data": map[string]any{
			"type":           "rsa-2048",
			"latest_version": 1,
			"keys":           map[string]any{"1": map[string]string{"public_key": "irrelevant"}},
		}}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := transitTestPlugin(t, srv.URL)
	_, err := p.IssueToken(context.Background(), &proto.IssueTokenRequest{
		Jti:       "jti-1",
		Subject:   "acct-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	require.Error(t, err)
}

// A signature that isn't exactly 64 bytes must be rejected at mint time —
// the scenario if OpenBao ignored marshaling_algorithm=jws and returned DER.
func TestTransitRejectsWrongLengthSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/transit/keys/pat-signing", func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{"data": map[string]any{
			"type":           "ecdsa-p256",
			"latest_version": 1,
			"keys": map[string]any{
				"1": map[string]string{"public_key": pubPEM},
			},
		}}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	})
	mux.HandleFunc("POST /v1/transit/sign/pat-signing/sha2-256", func(w http.ResponseWriter, _ *http.Request) {
		// 70 bytes: never a valid ES256 R||S length, standing in for a
		// DER-marshaled signature.
		bogus := make([]byte, 70)
		resp := map[string]any{"data": map[string]string{
			"signature": "vault:v1:" + base64.RawURLEncoding.EncodeToString(bogus),
		}}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ts := newTransitSigner(&patissuerConfig{
		OpenBaoProxyURL: srv.URL,
		TransitMount:    "transit",
		TransitKey:      "pat-signing",
		TimeoutSecs:     5,
	})
	_, err = ts.Mint(context.Background(), jwt.MapClaims{"sub": "acct-1"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "wrong length")
}

// Two round trips that individually fit within the configured timeout but
// together exceed it must still succeed.
func TestTransitTimeoutIsPerCall(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	const perCallDelay = 200 * time.Millisecond
	const budget = 300 * time.Millisecond // < 2*perCallDelay: a shared budget would starve the sign call

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/transit/keys/pat-signing", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(perCallDelay)
		resp := map[string]any{"data": map[string]any{
			"type":           "ecdsa-p256",
			"latest_version": 1,
			"keys": map[string]any{
				"1": map[string]string{"public_key": pubPEM},
			},
		}}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	})
	mux.HandleFunc("POST /v1/transit/sign/pat-signing/sha2-256", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(perCallDelay)
		var body struct {
			Input string `json:"input"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		input, err := base64.StdEncoding.DecodeString(body.Input)
		require.NoError(t, err)
		digest := sha256.Sum256(input)
		r32, s32, err := ecdsa.Sign(rand.Reader, key, digest[:])
		require.NoError(t, err)
		sig := append(r32.FillBytes(make([]byte, 32)), s32.FillBytes(make([]byte, 32))...)
		resp := map[string]any{"data": map[string]string{
			"signature": "vault:v1:" + base64.RawURLEncoding.EncodeToString(sig),
		}}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Constructed directly so the timeout can be sub-second; TimeoutSecs is
	// whole seconds only.
	ts := &transitSigner{
		client:  &http.Client{Timeout: budget},
		baseURL: srv.URL,
		mount:   "transit",
		keyName: "pat-signing",
	}

	_, err = ts.Mint(context.Background(), jwt.MapClaims{"sub": "acct-1"})
	require.NoError(t, err)
}

func TestStripVaultEnvelope(t *testing.T) {
	raw := []byte{0xfb, 0x01, 0x02, 0x03}
	want := base64.RawURLEncoding.EncodeToString(raw)

	for _, encoded := range []string{
		base64.RawURLEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.StdEncoding.EncodeToString(raw),
	} {
		got, err := stripVaultEnvelope("vault:v1:" + encoded)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}

	_, err := stripVaultEnvelope("no-envelope")
	require.Error(t, err)
}

// TestTransitLive exercises the real OpenBao from the dev compose stack
// (proxy on localhost:8200, token injected by the proxy). Skipped unless
// ORBITPORT_PATISSUER_LIVE_TEST=1. It creates the pat-signing key if absent.
func TestTransitLive(t *testing.T) {
	if os.Getenv("ORBITPORT_PATISSUER_LIVE_TEST") != "1" {
		t.Skip("set ORBITPORT_PATISSUER_LIVE_TEST=1 with the dev compose stack up")
	}
	proxy := "http://localhost:8200"

	req, err := http.NewRequest(
		http.MethodPost,
		proxy+"/v1/transit/keys/pat-signing",
		strings.NewReader(`{"type":"ecdsa-p256"}`),
	)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	p := transitTestPlugin(t, proxy)
	tokenString := issueValid(t, p)
	_, pub := jwksKey(t, p)

	parsed, err := jwt.Parse(
		tokenString,
		func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"ES256"}),
	)
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	t.Logf("live transit-signed PAT verified, kid=%v", parsed.Header["kid"])
}
