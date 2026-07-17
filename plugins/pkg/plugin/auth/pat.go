package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

const jwksCacheTTL = 5 * time.Minute

// unverifiedIssuer decodes the JWT payload WITHOUT verification, solely to
// read the iss claim for routing between the PAT and Auth0 paths. The token
// is fully verified afterwards by whichever path it routes to.
func unverifiedIssuer(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Iss
}

// jwksCache caches the issuer plugin's JWKS as a kid -> public key map for
// jwksCacheTTL, refetching once on an unknown kid to pick up key rotation.
type jwksCache struct {
	client proto.IssuerPluginClient

	mu        sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time
}

func newJWKSCache(issuerPluginURL string) (*jwksCache, error) {
	conn, err := grpc.NewClient(
		issuerPluginURL,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to issuer plugin: %w", err)
	}
	return &jwksCache{client: proto.NewIssuerPluginClient(conn)}, nil
}

// key returns the ES256 public key for kid, refreshing the cache when stale
// or when the kid is unknown (key rotation).
// ponytail: unknown-kid refetch is unthrottled; add a min-refresh interval if
// a flood of bad-kid tokens ever hammers the issuer plugin.
func (c *jwksCache) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.keys == nil || time.Since(c.fetchedAt) > jwksCacheTTL {
		if err := c.refreshLocked(ctx); err != nil {
			return nil, err
		}
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	if err := c.refreshLocked(ctx); err != nil {
		return nil, err
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no JWKS key for kid %q", kid)
}

func (c *jwksCache) refreshLocked(ctx context.Context) error {
	resp, err := c.client.GetJwks(ctx, &proto.GetJwksRequest{})
	if err != nil {
		return fmt.Errorf("fetching JWKS from issuer plugin: %w", err)
	}
	keys, err := parseJWKS(resp.GetJwksJson())
	if err != nil {
		return err
	}
	c.keys = keys
	c.fetchedAt = time.Now()
	return nil
}

// parseJWKS extracts the EC P-256 signing keys from an RFC 7517 JWK Set.
// Non-EC / non-P-256 entries are skipped.
func parseJWKS(jwksJSON string) (map[string]*ecdsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwksJSON), &set); err != nil {
		return nil, fmt.Errorf("parsing JWKS JSON: %w", err)
	}

	keys := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Kid == "" {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("JWK kid %q: decoding x: %w", k.Kid, err)
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("JWK kid %q: decoding y: %w", k.Kid, err)
		}
		keys[k.Kid] = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS contains no usable EC P-256 keys")
	}
	return keys, nil
}

// validatePAT verifies a PAT (ES256, issuer-plugin JWKS) and returns the
// validation response with the jti discriminator set.
func (p *Plugin) validatePAT(ctx context.Context, tokenString string) (*proto.TokenValidationResponse, error) {
	keyfunc := func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("PAT is missing kid header")
		}
		return p.patKeys.key(ctx, kid)
	}

	parsed, err := jwt.Parse(
		tokenString,
		keyfunc,
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(p.patIss),
		jwt.WithAudience(p.patAudience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(time.Minute),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			// "pat_expired:" prefix is the gateway's contract for mapping
			// this to a distinguishable 401.
			return nil, fmt.Errorf("pat_expired: %w", err)
		}
		return nil, fmt.Errorf("failed to validate PAT: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected PAT claims type %T", parsed.Claims)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("validated PAT is missing sub claim")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, fmt.Errorf("validated PAT is missing jti claim")
	}
	// Optional until the D9 backfill lands — empty means "no frozen tenant".
	kmsTenant, _ := claims["kms_tenant"].(string)

	return &proto.TokenValidationResponse{
		Ok:        true,
		ClientId:  sub,
		Jti:       jti,
		KmsTenant: kmsTenant,
	}, nil
}
