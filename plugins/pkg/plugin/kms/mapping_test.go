package kms

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTransitKeyType(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:     "AES256GCM96_ReturnsAES256GCM96",
			input:    keySpecAES256GCM96,
			expected: "aes256-gcm96",
		},
		{
			name:     "ECDSAP256_ReturnsECDSAP256",
			input:    keySpecECDSAP256,
			expected: "ecdsa-p256",
		},
		{
			name:     "ECDSAP384_ReturnsECDSAP384",
			input:    keySpecECDSAP384,
			expected: "ecdsa-p384",
		},
		{
			name:     "ED25519_ReturnsED25519",
			input:    keySpecED25519,
			expected: "ed25519",
		},
		{
			name:     "RSA4096_ReturnsRSA4096",
			input:    keySpecRSA4096,
			expected: "rsa-4096",
		},
		{
			name:        "UnsupportedKeySpec_ReturnsError",
			input:       "INVALID_KEY_SPEC",
			expectError: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := transitKeyType(testCase.input)
			if testCase.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, actual)

		})
	}
}

func TestDataKeyBits(t *testing.T) {
	tests := []struct {
		name          string
		dataKeySpec   string
		numberOfBytes uint32
		expectedBits  int
		expectError   bool
	}{
		{
			name:         "AES128Spec_Returns128Bits",
			dataKeySpec:  dataKeySpecAES128,
			expectedBits: 128,
		},
		{
			name:         "AES256Spec_Returns256Bits",
			dataKeySpec:  dataKeySpecAES256,
			expectedBits: 256,
		},
		{
			name:          "NumberOfBytes32_Returns256Bits",
			numberOfBytes: 32,
			expectedBits:  256,
		},
		{
			name:          "SpecAndNumberOfBytesProvided_ReturnsError",
			dataKeySpec:   dataKeySpecAES256,
			numberOfBytes: 32,
			expectError:   true,
		},
		{
			name:        "NoSpecOrNumberOfBytes_ReturnsError",
			expectError: true,
		},
		{
			name:        "UnsupportedDataKeySpec_ReturnsError",
			dataKeySpec: "INVALID_DATA_KEY_SPEC",
			expectError: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {

			bits, err := dataKeyBits(testCase.dataKeySpec, testCase.numberOfBytes)
			if testCase.expectError {
				assert.Error(t, err)
				assert.Zero(t, bits)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, testCase.expectedBits, bits)

		})
	}
}

func TestNormalizeScheme(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:     "Empty_ReturnsSchemeTransit",
			input:    "",
			expected: schemeTransit,
		},
		{
			name:     "SchemeTransit_ReturnsSchemeTransit",
			input:    schemeTransit,
			expected: schemeTransit,
		},
		{
			name:     "PQC_ReturnsPQC",
			input:    schemePQC,
			expected: schemePQC,
		},
		{
			name:     "SchemeEthereum_ReturnsEthereum",
			input:    schemeEthereum,
			expected: schemeEthereum,
		},
		{
			name:        "UnsupportedScheme_ReturnsError",
			input:       "garbage",
			expectError: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {

			actual, err := normalizeScheme(testCase.input)
			if testCase.expectError {
				assert.Error(t, err)
				assert.Empty(t, actual)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, actual)
		})
	}
}

func TestPQCMLDSAVariant(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:     "MLDSA44_ReturnsMLDSA44",
			input:    keySpecMLDSA44,
			expected: "ml-dsa-44",
		},
		{
			name:     "MLDSA65_ReturnsMLDSA65",
			input:    keySpecMLDSA65,
			expected: "ml-dsa-65",
		},
		{
			name:     "MLDSA87_ReturnsMLDSA87",
			input:    keySpecMLDSA87,
			expected: "ml-dsa-87",
		},
		{
			name:        "UnsupportedKeySpec_ReturnsError",
			input:       keySpecECDSAP256,
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := pqcMLDSAVariant(test.input)

			if test.expectError {
				assert.Error(t, err)
				assert.Empty(t, actual)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestPQCMLKEMVariant(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:     "MLKEM768_ReturnsMLKEM768",
			input:    keySpecMLKEM768,
			expected: "ml-kem-768",
		},
		{
			name:     "MLKEM1024_ReturnsMLKEM1024",
			input:    keySpecMLKEM1024,
			expected: "ml-kem-1024",
		},
		{
			name:        "UnsupportedKeySpec_ReturnsError",
			input:       keySpecECDSAP256,
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := pqcMLKEMVariant(test.input)

			if test.expectError {
				assert.Error(t, err)
				assert.Empty(t, actual)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}
