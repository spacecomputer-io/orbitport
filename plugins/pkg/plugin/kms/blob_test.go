package kms

import (
	"encoding/base64"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCiphertextBlobRoundTrip(t *testing.T) {
	encoded, err := encodeCiphertextBlob(schemeTransit, "kms:abc", "kms-abc", "vault:v1:xyz", encryptionAlgorithmAES256GCM96)

	require.NoError(t, err)

	decoded, err := decodeCiphertextBlob(encoded)

	require.NoError(t, err)

	require.Equal(t, "kms:abc", decoded.KeyID)
	require.Equal(t, "kms-abc", decoded.backendKey())
	require.Equal(t, schemeTransit, decoded.Scheme)
	require.Equal(t, encryptionAlgorithmAES256GCM96, decoded.Algorithm)

}

func TestDecodeCiphertextBlobErrors(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		errorContains string
	}{
		{
			name:          "invalid string",
			input:         "Invalid String",
			errorContains: "decode ciphertext blob",
		},
		{
			name:          "valid base 64 with invalid json ",
			input:         base64.StdEncoding.EncodeToString([]byte("test")),
			errorContains: "unmarshal ciphertext blob",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decodedBlob, err := decodeCiphertextBlob(tt.input)

			require.Error(t, err)
			require.ErrorContains(t, err, tt.errorContains)
			require.Nil(t, decodedBlob)

		})
	}
}
