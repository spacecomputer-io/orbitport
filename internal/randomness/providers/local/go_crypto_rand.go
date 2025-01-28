package provider_local

import (
	gocryptorand "crypto/rand"
)

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := gocryptorand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
