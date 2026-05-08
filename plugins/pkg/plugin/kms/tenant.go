package kms

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const keyIDPrefix = "kms:"

func tenantNamespace(clientID string) string {
	// Use the full 32-byte (256-bit) SHA-256 digest as the namespace prefix.
	// The previous implementation truncated to 8 bytes (64 bits), which is
	// vulnerable to a birthday attack: two different clientIDs sharing the
	// same 8-byte prefix would map to the same key namespace, silently
	// breaking per-tenant key isolation.  At 64 bits, a collision becomes
	// 50%-probable around 2^32 (~4 billion) tenants — unacceptably low for a
	// security-critical KMS operation.
	sum := sha256.Sum256([]byte(strings.TrimSpace(clientID)))
	return "tenant_" + hex.EncodeToString(sum[:])
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
