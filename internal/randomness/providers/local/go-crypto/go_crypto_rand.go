package go_crypto

import (
	gocryptorand "crypto/rand"

	randomness_common "github.com/spacecoinxyz/orbitport/internal/randomness/common"
)

func GenerateRandomSeed(n int) (*randomness_common.RandomSeed, error) {
	rseed, err := generateRandomBytes(n)
	if err != nil {
		return nil, err
	}
	return &randomness_common.RandomSeed{
		Value: string(rseed),
		Sig:   "",
		Src:   randomness_common.RandSourceLocalGoCrypto,
	}, nil
}

// generateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := gocryptorand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
