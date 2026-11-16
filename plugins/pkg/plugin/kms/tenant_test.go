package kms

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTenantNamespaceIsDeterministic(t *testing.T) {
	first := tenantNamespace("auth0|tenant-a")
	second := tenantNamespace("auth0|tenant-a")
	third := tenantNamespace("auth0|tenant-b")

	assert.NotEmpty(t, first)
	assert.Equal(t, first, second)
	assert.NotEqual(t, first, third)
}

func TestTenantNamespaceUsesSixteenBytesOfHash(t *testing.T) {
	namespace := tenantNamespace("auth0|tenant-a")
	got := len(strings.TrimPrefix(namespace, tenantNamespacePrefix))
	assert.Equal(t, tenantNamespaceBytes*2, got)
}

func TestScopedBackendKeyUsesTenantNamespace(t *testing.T) {
	keyA, err := scopedBackendKey("tenant-a", "payments-main")
	if !assert.NoError(t, err) {
		return
	}

	keyB, err := scopedBackendKey("tenant-b", "payments-main")
	if !assert.NoError(t, err) {
		return
	}

	assert.NotEqual(t, keyA, keyB)
	assert.Equal(t, tenantNamespace("tenant-a")+"_payments-main", keyA)
}

func TestCanonicalKeyIDUsesAlias(t *testing.T) {
	keyID, err := canonicalKeyID("payments-main")
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "kms:payments-main", keyID)
}

func TestResolveKeyRef(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedKeyID string
		expectedAlias string
		expectError   bool
	}{
		{
			name:          "Alias_ReturnsCanonicalKeyIDAndAlias",
			input:         "payments-main",
			expectedKeyID: "kms:payments-main",
			expectedAlias: "payments-main",
		},
		{
			name:          "CanonicalKeyID_ReturnsCanonicalKeyIDAndAlias",
			input:         "kms:payments-main",
			expectedKeyID: "kms:payments-main",
			expectedAlias: "payments-main",
		},
		{
			name:        "AliasWithUnderscore_ReturnsError",
			input:       "payments_main",
			expectError: true,
		},
		{
			name:        "CanonicalKeyIDWithSlash_ReturnsError",
			input:       "kms:payments/main",
			expectError: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			keyID, alias, err := resolveKeyRef(testCase.input)

			if testCase.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, testCase.expectedKeyID, keyID)
			assert.Equal(t, testCase.expectedAlias, alias)
		})
	}
}
