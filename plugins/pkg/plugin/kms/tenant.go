package kms

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

func tenantNamespace(clientID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(clientID)))
	return "tenant_" + hex.EncodeToString(sum[:8])
}

func scopedBackendKey(clientID, keyID string) (string, error) {
	keyUUID, err := orbitportKeyUUID(keyID)
	if err != nil {
		return "", err
	}
	return tenantNamespace(clientID) + "_" + keyUUID, nil
}

func orbitportKeyUUID(keyID string) (string, error) {
	const prefix = "kms:"

	if !strings.HasPrefix(keyID, prefix) {
		return "", fmt.Errorf("key_id must start with %q", prefix)
	}

	value := strings.TrimPrefix(keyID, prefix)
	if _, err := uuid.Parse(value); err != nil {
		return "", fmt.Errorf("key_id must contain a valid UUID: %w", err)
	}
	return value, nil
}
