package patissuer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// transitSigner signs via OpenBao Transit through the OpenBao proxy, which
// injects the vault token — this code holds no OpenBao credentials.
type transitSigner struct {
	client  *http.Client
	baseURL string
	mount   string
	keyName string
}

func newTransitSigner(cfg *patissuerConfig) *transitSigner {
	return &transitSigner{
		client:  &http.Client{Timeout: time.Duration(cfg.TimeoutSecs) * time.Second},
		baseURL: strings.TrimRight(cfg.OpenBaoProxyURL, "/"),
		mount:   cfg.TransitMount,
		keyName: cfg.TransitKey,
	}
}

type keyInfo struct {
	Type          string
	LatestVersion int
	// version -> PEM public key
	PublicKeys map[int]string
}

type jwsHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type transitSignRequest struct {
	Input               string `json:"input"`
	Prehashed           bool   `json:"prehashed"`
	MarshalingAlgorithm string `json:"marshaling_algorithm"`
	KeyVersion          int    `json:"key_version"`
}

func (s *transitSigner) Mint(ctx context.Context, claims jwt.MapClaims) (string, error) {
	// Each round trip gets its own budget so a slow key read can't starve
	// the sign call.
	readCtx, readCancel := context.WithTimeout(ctx, s.client.Timeout)
	defer readCancel()

	info, err := s.readKey(readCtx)
	if err != nil {
		return "", err
	}
	alg, err := jwsAlg(info.Type)
	if err != nil {
		return "", err
	}

	// typ matches what the local signer emits via jwt.NewWithClaims, so both
	// signers produce identically shaped tokens.
	headerJSON, err := json.Marshal(jwsHeader{
		Alg: alg,
		Typ: "JWT",
		Kid: strconv.Itoa(info.LatestVersion),
	})
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingString := base64.RawURLEncoding.EncodeToString(headerJSON) +
		"." + base64.RawURLEncoding.EncodeToString(payloadJSON)

	// key_version is pinned to the version the kid header names so a
	// concurrent rotation can't cause a mismatch.
	body, err := json.Marshal(transitSignRequest{
		Input:               base64.StdEncoding.EncodeToString([]byte(signingString)),
		Prehashed:           false,
		MarshalingAlgorithm: "jws",
		KeyVersion:          info.LatestVersion,
	})
	if err != nil {
		return "", err
	}

	signCtx, signCancel := context.WithTimeout(ctx, s.client.Timeout)
	defer signCancel()

	url := fmt.Sprintf("%s/v1/%s/sign/%s/sha2-256", s.baseURL, s.mount, s.keyName)
	req, err := http.NewRequestWithContext(signCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	var signResp struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := s.do(req, &signResp); err != nil {
		return "", fmt.Errorf("transit sign: %w", err)
	}

	sig, err := stripVaultEnvelope(signResp.Data.Signature)
	if err != nil {
		return "", err
	}
	// Catches OpenBao returning ASN.1 DER instead of honoring
	// marshaling_algorithm=jws, rather than minting an invalid PAT.
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return "", fmt.Errorf("transit signature is not valid base64url: %w", err)
	}
	if len(sigBytes) != 64 {
		return "", fmt.Errorf("transit signature has wrong length: want 64 bytes (ES256 R||S), got %d", len(sigBytes))
	}
	return signingString + "." + sig, nil
}

func (s *transitSigner) JWKS(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.client.Timeout)
	defer cancel()

	info, err := s.readKey(ctx)
	if err != nil {
		return "", err
	}
	alg, err := jwsAlg(info.Type)
	if err != nil {
		return "", err
	}

	versions := make([]int, 0, len(info.PublicKeys))
	for v := range info.PublicKeys {
		versions = append(versions, v)
	}
	sort.Ints(versions)

	keys := make([]map[string]string, 0, len(versions))
	for _, v := range versions {
		pub, err := parseECPublicKeyPEM(info.PublicKeys[v])
		if err != nil {
			return "", fmt.Errorf("key version %d: %w", v, err)
		}
		x := pub.X.FillBytes(make([]byte, 32))
		y := pub.Y.FillBytes(make([]byte, 32))
		keys = append(keys, map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"use": "sig",
			"alg": alg,
			"kid": strconv.Itoa(v),
			"x":   base64.RawURLEncoding.EncodeToString(x),
			"y":   base64.RawURLEncoding.EncodeToString(y),
		})
	}

	out, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (s *transitSigner) readKey(ctx context.Context) (*keyInfo, error) {
	url := fmt.Sprintf("%s/v1/%s/keys/%s", s.baseURL, s.mount, s.keyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data struct {
			Type          string          `json:"type"`
			LatestVersion int             `json:"latest_version"`
			Keys          json.RawMessage `json:"keys"`
		} `json:"data"`
	}
	if err := s.do(req, &resp); err != nil {
		return nil, fmt.Errorf("transit key read: %w", err)
	}

	var rawKeys map[string]struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(resp.Data.Keys, &rawKeys); err != nil {
		return nil, fmt.Errorf("parsing transit key versions: %w", err)
	}
	pubKeys := make(map[int]string, len(rawKeys))
	for vs, k := range rawKeys {
		v, err := strconv.Atoi(vs)
		if err != nil || k.PublicKey == "" {
			continue
		}
		pubKeys[v] = k.PublicKey
	}
	if len(pubKeys) == 0 {
		return nil, fmt.Errorf("transit key %q has no public keys", s.keyName)
	}

	return &keyInfo{
		Type:          resp.Data.Type,
		LatestVersion: resp.Data.LatestVersion,
		PublicKeys:    pubKeys,
	}, nil
}

func (s *transitSigner) do(req *http.Request, out any) error {
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("openbao returned %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return json.Unmarshal(body, out)
}

// jwsAlg derives the JWS alg from the Transit key type, never a constant.
func jwsAlg(keyType string) (string, error) {
	switch keyType {
	case "ecdsa-p256":
		return "ES256", nil
	default:
		return "", fmt.Errorf("unsupported transit key type %q (vetted: ecdsa-p256)", keyType)
	}
}

// stripVaultEnvelope turns "vault:vN:<sig>" into base64url-unpadded JWS
// signature bytes.
func stripVaultEnvelope(signature string) (string, error) {
	parts := strings.SplitN(signature, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" {
		return "", fmt.Errorf("unexpected transit signature envelope")
	}
	raw := parts[2]
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if decoded, err := enc.DecodeString(raw); err == nil {
			return base64.RawURLEncoding.EncodeToString(decoded), nil
		}
	}
	return "", fmt.Errorf("transit signature is not valid base64")
}

func parseECPublicKeyPEM(data string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, fmt.Errorf("no PEM block in transit public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing transit public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("transit public key is not EC")
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("transit public key must be P-256")
	}
	return pub, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
