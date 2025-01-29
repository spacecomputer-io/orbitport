package randomness_common

// RandomSeed represents a seed for randomness.
// TODO: work with bytes arrays instead of strings.
type RandomSeed struct {
	Value string `json:"value"`
	Sig   string `json:"sig"`
}

// Service represents the randomness service.
type Service interface {
	// GetRandomSeed retrieves a true randomness seed from the Aptos Orbital API.
	GetRandomSeed() (*RandomSeed, error)
}
