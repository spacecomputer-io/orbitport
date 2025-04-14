package auth

import (
	"context"
	"errors"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/gin-gonic/gin"
	adapter "github.com/gwatts/gin-adapter"
	"github.com/spacecomputerio/orbitport/internal/utils"
)

func StaticTokenMiddleware(expectedToken string) gin.HandlerFunc {
	logger := utils.GetLogger("orbitport:auth:static-token")
	middleware := jwtmiddleware.New(
		func(ctx context.Context, token string) (interface{}, error) {
			logger.Infof("validating token '%s'\nexpected '%s'", token, expectedToken)
			if expectedToken == token {
				return nil, nil
			}
			return nil, errors.New("invalid token")
		},
	)
	return adapter.Wrap(middleware.CheckJWT)
}
