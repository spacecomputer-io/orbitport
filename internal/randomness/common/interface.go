package randomness_common

import (
	"context"
)

// RandomSeed represents a seed for randomness.
// TODO: work with bytes arrays instead of strings.
type RandomSeed struct {
	Value string     `json:"value"`
	Sig   string     `json:"sig"`
	Src   RandSource `json:"src"`
}

// Service represents the randomness service.
type Service interface {
	// GetRandomSeed retrieves a true randomness seed from the Aptos Orbital API.
	GetRandomSeed(ctx context.Context, sources ...RandSource) (*RandomSeed, error)

	Start(context.Context) error
	Close()
}
