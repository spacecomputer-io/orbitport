package patissuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// signer is the key-custody seam, selected by ORBITPORT_PATISSUER_SIGNER:
// localSigner for dev, transitSigner for deployed environments.
type signer interface {
	// Mint signs the claims and returns a compact JWS with a kid header.
	Mint(ctx context.Context, claims jwt.MapClaims) (string, error)
	// JWKS returns the RFC 7517 public key set verifiers select from by kid.
	JWKS(ctx context.Context) (string, error)
}

// localSigner holds an EC P-256 key in process memory. Key custody is the
// only difference from transitSigner — tokens and JWKS are real ES256.
type localSigner struct {
	key *ecdsa.PrivateKey
	kid string
}

func newLocalSigner(keyPEM string) (*localSigner, bool, error) {
	generated := false
	var key *ecdsa.PrivateKey

	if keyPEM == "" {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, false, fmt.Errorf("generating ephemeral signing key: %w", err)
		}
		key = k
		generated = true
	} else {
		k, err := parseECPrivateKeyPEM([]byte(keyPEM))
		if err != nil {
			return nil, false, fmt.Errorf("parsing ORBITPORT_PATISSUER_LOCAL_KEY_PEM: %w", err)
		}
		key = k
	}

	kid, err := keyID(&key.PublicKey)
	if err != nil {
		return nil, false, err
	}

	return &localSigner{key: key, kid: kid}, generated, nil
}

func (s *localSigner) Mint(_ context.Context, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.key)
}

func (s *localSigner) JWKS(_ context.Context) (string, error) {
	pub := s.key.PublicKey
	if pub.Curve != elliptic.P256() {
		return "", fmt.Errorf("unsupported curve %s", pub.Curve.Params().Name)
	}

	// Fixed-width big-endian coordinates per RFC 7518 §6.2.1.
	x := pub.X.FillBytes(make([]byte, 32))
	y := pub.Y.FillBytes(make([]byte, 32))

	set := map[string]any{
		"keys": []map[string]string{{
			"kty": "EC",
			"crv": "P-256",
			"use": "sig",
			"alg": "ES256",
			"kid": s.kid,
			"x":   base64.RawURLEncoding.EncodeToString(x),
			"y":   base64.RawURLEncoding.EncodeToString(y),
		}},
	}

	out, err := json.Marshal(set)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// keyID derives a stable kid from the public key so restarts with the same
// key keep the same kid.
func keyID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshaling public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8]), nil
}

func parseECPrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("key is neither SEC1 nor PKCS#8 EC: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PKCS#8 key is not an EC key")
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("EC key must be P-256, got %s", key.Curve.Params().Name)
	}
	return key, nil
}
