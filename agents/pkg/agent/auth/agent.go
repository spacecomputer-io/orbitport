package auth

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"

	"github.com/spacecomputerio/orbitport/agents/pkg/utils"
	"github.com/spacecomputerio/orbitport/agents/proto"
)

// Agent implements the AuthAgentServer interface for the Auth0 API.
type Agent struct {
	proto.AuthAgentServer

	jwtValidator    *validator.Validator
	cachingProvider *jwks.CachingProvider
}

// NewAgent creates a new Auth agent.
func NewAgent() (*Agent, error) {
	cfg := readFromEnv()
	logger := utils.GetLogger("orbitport:auth")
	logger.Infof("creating agent with config: %+v", cfg)

	if len(cfg.Auth0Domain) == 0 || len(cfg.Auth0Audience) == 0 {
		logger.Warn("Auth0 domain is not set, authentication is OFF")
		return new(Agent), nil
	}
	logger.Debug("Auth0 domain is set, creating Auth agent")
	agent, err := newAuthAgent(cfg.Auth0Domain, cfg.Auth0Audience)
	if err != nil {
		return nil, fmt.Errorf("failed to create Auth agent: %w", err)
	}
	logger.Info("authentication is ON")

	return agent, nil
}

func newAuthAgent(auth0Domain, auth0Audience string) (*Agent, error) {
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

	agent := new(Agent)
	agent.jwtValidator = jwtValidator
	agent.cachingProvider = cProvider

	return agent, nil
}

// ValidateToken handles the ValidateToken RPC call.
// It validates the JWT token using the Auth0 sdk.
func (a *Agent) ValidateToken(ctx context.Context, req *proto.TokenValidationRequest) (*proto.TokenValidationResponse, error) {
	logger := utils.GetLogger("orbitport:auth")
	if a.jwtValidator == nil {
		logger.Debug("Auth0 domain is not set, authentication is OFF")
		return &proto.TokenValidationResponse{
			Ok: true,
		}, nil
	}
	logger.Debug("Validating token")
	_, err := a.jwtValidator.ValidateToken(ctx, req.Token)
	if err != nil {
		logger.Warnf("Encountered error while validating JWT: %v", err)
		return nil, fmt.Errorf("failed to validate JWT token: %w", err)
	}

	return &proto.TokenValidationResponse{
		Ok: true,
	}, nil
}
