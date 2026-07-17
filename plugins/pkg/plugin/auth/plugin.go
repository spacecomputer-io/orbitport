package auth

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

// Plugin implements the AuthPluginServer interface for the Auth0 API.
type Plugin struct {
	proto.AuthPluginServer

	jwtValidator    *validator.Validator
	cachingProvider *jwks.CachingProvider

	// PAT dual-validation path. patKeys is nil when PAT validation is not
	// configured, in which case the plugin behaves exactly as before.
	patIss      string
	patAudience string
	patKeys     *jwksCache
}

// NewPlugin creates a new Auth plugin.
func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()
	logger := utils.GetLogger("orbitport:auth")
	logger.Infof("creating plugin with config: %+v", cfg)

	// strict fail-closed validation
	if len(cfg.Auth0Domain) == 0 || len(cfg.Auth0Audience) == 0 {
		return nil, fmt.Errorf("FATAL: Auth0Domain or Auth0Audience is missing. Refusing to start without auth configuration")
	}

	// fail-closed on partial PAT configuration
	if err := cfg.validatePat(); err != nil {
		return nil, err
	}

	logger.Debug("Auth0 domain is set, creating Auth plugin")
	plugin, err := newAuthPlugin(cfg.Auth0Domain, cfg.Auth0Audience)
	if err != nil {
		return nil, fmt.Errorf("failed to create Auth plugin: %w", err)
	}
	logger.Info("authentication is ON")

	if cfg.patEnabled() {
		cache, err := newJWKSCache(cfg.PatIssuerPlugin)
		if err != nil {
			return nil, fmt.Errorf("failed to create PAT JWKS cache: %w", err)
		}
		plugin.patIss = cfg.PatIss
		plugin.patAudience = cfg.PatAudience
		if plugin.patAudience == "" {
			plugin.patAudience = cfg.Auth0Audience
		}
		plugin.patKeys = cache
		logger.Infof("PAT dual validation is ON (iss=%s)", cfg.PatIss)
	}

	return plugin, nil
}

func newAuthPlugin(auth0Domain, auth0Audience string) (*Plugin, error) {
	issuerURL, err := url.Parse("https://" + auth0Domain + "/")
	if err != nil {
		log.Fatalf("Failed to parse the issuer url: %v", err)
	}

	cProvider := jwks.NewCachingProvider(issuerURL, 5*time.Minute)

	jwtValidator, err := validator.New(
		cProvider.KeyFunc,
		validator.RS256,
		issuerURL.String(),
		[]string{auth0Audience},
		validator.WithAllowedClockSkew(time.Minute),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to set up the jwt validator: %w", err)
	}

	plugin := new(Plugin)
	plugin.jwtValidator = jwtValidator
	plugin.cachingProvider = cProvider

	return plugin, nil
}

// ValidateToken handles the ValidateToken RPC call.
// PATs (unverified iss == the configured PAT iss) are verified against the
// issuer plugin's JWKS and return a non-empty Jti; everything else takes the
// legacy Auth0 path unchanged and returns Jti="".
func (p *Plugin) ValidateToken(ctx context.Context, req *proto.TokenValidationRequest) (*proto.TokenValidationResponse, error) {
	logger := utils.GetLogger("orbitport:auth")
	logger.Debug("Validating token")
	if p.patKeys != nil && unverifiedIssuer(req.Token) == p.patIss {
		resp, err := p.validatePAT(ctx, req.Token)
		if err != nil {
			logger.Warnf("Encountered error while validating PAT: %v", err)
			return nil, err
		}
		return resp, nil
	}
	claims, err := p.jwtValidator.ValidateToken(ctx, req.Token)
	if err != nil {
		logger.Warnf("Encountered error while validating JWT: %v", err)
		return nil, fmt.Errorf("failed to validate JWT token: %w", err)
	}
	validatedClaims, ok := claims.(*validator.ValidatedClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected validated claims type %T", claims)
	}
	clientID := validatedClaims.RegisteredClaims.Subject
	if clientID == "" {
		return nil, fmt.Errorf("validated JWT is missing sub claim")
	}

	return &proto.TokenValidationResponse{
		Ok:       true,
		ClientId: clientID,
		// D9: legacy KMS tenancy is the RAW sub (including any @clients
		// suffix) — byte-identical to what the gateway used before.
		KmsTenant: clientID,
	}, nil
}
