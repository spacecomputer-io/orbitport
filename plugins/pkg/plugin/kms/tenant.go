package kms

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const keyIDPrefix = "kms:"
const tenantNamespacePrefix = "tenant_"
const tenantNamespaceBytes = 16

func tenantNamespace(clientID string) string {
	return tenantNamespaceForBytes(clientID, tenantNamespaceBytes)
}

func tenantNamespaceForBytes(clientID string, size int) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(clientID)))
	if size > len(sum) {
		size = len(sum)
	}
	return tenantNamespacePrefix + hex.EncodeToString(sum[:size])
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
