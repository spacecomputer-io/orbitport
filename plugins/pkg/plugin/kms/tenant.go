package kms

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const keyIDPrefix = "kms:"

func tenantNamespace(clientID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(clientID)))
	return "tenant_" + hex.EncodeToString(sum[:8])
}

func scopedBackendKey(clientID, alias string) (string, error) {
	normalizedAlias, err := canonicalAlias(alias)
	if err != nil {
		return "", err
	}
	return tenantNamespace(clientID) + "_" + normalizedAlias, nil
}

func canonicalKeyID(alias string) (string, error) {
	normalizedAlias, err := canonicalAlias(alias)
	if err != nil {
		return "", err
	}
	return keyIDPrefix + normalizedAlias, nil
}

func resolveKeyRef(keyRef string) (string, string, error) {
	trimmed := strings.TrimSpace(keyRef)
	if trimmed == "" {
		return "", "", fmt.Errorf("key_id is required")
	}

	if strings.HasPrefix(trimmed, keyIDPrefix) {
		alias, err := canonicalAlias(strings.TrimPrefix(trimmed, keyIDPrefix))
		if err != nil {
			return "", "", err
		}
		return keyIDPrefix + alias, alias, nil
	}

	alias, err := canonicalAlias(trimmed)
	if err != nil {
		return "", "", err
	}
	return keyIDPrefix + alias, alias, nil
}

func canonicalAlias(alias string) (string, error) {
	trimmed := strings.TrimSpace(alias)
	if err := validateAlias(trimmed); err != nil {
		return "", err
	}
	return trimmed, nil
}
