package randomness_common

// RandomSeed represents a seed for randomness.
// TODO: Define the structure.
type RandomSeed interface{}

// Service represents the randomness service.
type Service interface {
	// GetRandomSeed retrieves a true randomness seed from the Aptos Orbital API.
	GetRandomSeed() (RandomSeed, error)
}
