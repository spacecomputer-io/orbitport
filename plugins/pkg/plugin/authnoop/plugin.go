package authnoop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

// Plugin implements a development-only auth plugin that accepts all tokens.
type Plugin struct {
	proto.AuthPluginServer
}

// NewPlugin creates a noop auth plugin for local development environments.
func NewPlugin() (*Plugin, error) {
	utils.GetLogger("orbitport:authnoop").Warn(
		"Using noop auth plugin: all tokens will be accepted. Do not use in production!",
	)
	return new(Plugin), nil
}

// ValidateToken handles the ValidateToken RPC call.
func (p *Plugin) ValidateToken(_ context.Context, req *proto.TokenValidationRequest) (*proto.TokenValidationResponse, error) {
	utils.GetLogger("orbitport:authnoop").Warn("Processing request with noop authentication")
	sum := sha256.Sum256([]byte(req.Token))
	return &proto.TokenValidationResponse{
		Ok:       true,
		ClientId: "dev_" + hex.EncodeToString(sum[:8]),
	}, nil
}
