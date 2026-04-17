package authnoop

import (
	"context"
	"testing"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

func TestValidateTokenReturnsDeterministicClientID(t *testing.T) {
	plugin, err := NewPlugin()
	if err != nil {
		t.Fatalf("NewPlugin() error = %v", err)
	}

	first, err := plugin.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: "alpha"})
	if err != nil {
		t.Fatalf("ValidateToken(alpha) error = %v", err)
	}
	second, err := plugin.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: "alpha"})
	if err != nil {
		t.Fatalf("ValidateToken(alpha) second error = %v", err)
	}
	third, err := plugin.ValidateToken(context.Background(), &proto.TokenValidationRequest{Token: "beta"})
	if err != nil {
		t.Fatalf("ValidateToken(beta) error = %v", err)
	}

	if !first.Ok {
		t.Fatal("expected noop auth to accept token")
	}
	if first.ClientId == "" {
		t.Fatal("expected noop auth to return a non-empty client_id")
	}
	if first.ClientId != second.ClientId {
		t.Fatalf("expected deterministic client_id, got %q and %q", first.ClientId, second.ClientId)
	}
	if first.ClientId == third.ClientId {
		t.Fatalf("expected different tokens to map to different client IDs, got %q", first.ClientId)
	}
}
