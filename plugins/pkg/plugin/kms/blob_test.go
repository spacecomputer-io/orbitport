package kms

import "testing"

func TestCiphertextBlobRoundTrip(t *testing.T) {
	encoded, err := encodeCiphertextBlob(schemeTransit, "kms:abc", "kms-abc", "vault:v1:xyz", encryptionAlgorithmAES256GCM96)
	if err != nil {
		t.Fatalf("encode blob: %v", err)
	}

	decoded, err := decodeCiphertextBlob(encoded)
	if err != nil {
		t.Fatalf("decode blob: %v", err)
	}

	if decoded.KeyID != "kms:abc" || decoded.backendKey() != "kms-abc" || decoded.Scheme != schemeTransit || decoded.Algorithm != encryptionAlgorithmAES256GCM96 {
		t.Fatalf("decoded blob mismatch: %+v", decoded)
	}
}
