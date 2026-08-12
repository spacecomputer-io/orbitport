package kms

import "testing"

func TestTransitKeyType(t *testing.T) {
	tests := map[string]string{
		keySpecAES256GCM96: "aes256-gcm96",
		keySpecECDSAP256:   "ecdsa-p256",
		keySpecECDSAP384:   "ecdsa-p384",
		keySpecED25519:     "ed25519",
		keySpecRSA4096:     "rsa-4096",
	}

	for input, expected := range tests {
		actual, err := transitKeyType(input)
		if err != nil {
			t.Fatalf("transitKeyType(%q): %v", input, err)
		}
		if actual != expected {
			t.Fatalf("transitKeyType(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestDataKeyBits(t *testing.T) {
	bits, err := dataKeyBits(dataKeySpecAES256, 0)
	if err != nil {
		t.Fatalf("dataKeyBits: %v", err)
	}
	if bits != 256 {
		t.Fatalf("expected 256 bits, got %d", bits)
	}

	if _, err := dataKeyBits(dataKeySpecAES256, 32); err == nil {
		t.Fatal("expected xor validation error")
	}
}

func TestNormalizeScheme(t *testing.T) {
	tests := map[string]string{
		"":             schemeTransit,
		schemeTransit:  schemeTransit,
		schemeEthereum: schemeEthereum,
		schemePQC:      schemePQC,
	}

	for input, expected := range tests {
		actual, err := normalizeScheme(input)
		if err != nil {
			t.Fatalf("normalizeScheme(%q): %v", input, err)
		}
		if actual != expected {
			t.Fatalf("normalizeScheme(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestPQCVariant(t *testing.T) {
	dsaTests := map[string]string{
		keySpecMLDSA44: "ml-dsa-44",
		keySpecMLDSA65: "ml-dsa-65",
		keySpecMLDSA87: "ml-dsa-87",
	}

	for input, expected := range dsaTests {
		actual, err := pqcMLDSAVariant(input)
		if err != nil {
			t.Fatalf("pqcMLDSAVariant(%q): %v", input, err)
		}
		if actual != expected {
			t.Fatalf("pqcMLDSAVariant(%q) = %q, want %q", input, actual, expected)
		}
	}

	kemTests := map[string]string{
		keySpecMLKEM768:  "ml-kem-768",
		keySpecMLKEM1024: "ml-kem-1024",
	}

	for input, expected := range kemTests {
		actual, err := pqcMLKEMVariant(input)
		if err != nil {
			t.Fatalf("pqcMLKEMVariant(%q): %v", input, err)
		}
		if actual != expected {
			t.Fatalf("pqcMLKEMVariant(%q) = %q, want %q", input, actual, expected)
		}
	}

	if _, err := pqcMLDSAVariant(keySpecECDSAP256); err == nil {
		t.Fatal("expected unsupported PQC ML-DSA KeySpec error")
	}
	if _, err := pqcMLKEMVariant(keySpecECDSAP256); err == nil {
		t.Fatal("expected unsupported PQC ML-KEM KeySpec error")
	}
}
