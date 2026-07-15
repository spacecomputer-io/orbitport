package kms

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type ciphertextBlob struct {
	Version     int    `json:"v"`
	Scheme      string `json:"scheme,omitempty"`
	KeyID       string `json:"key_id"`
	ProviderKey string `json:"provider_key,omitempty"`
	TransitKey  string `json:"transit_key,omitempty"`
	Ciphertext  string `json:"ciphertext"`
	Algorithm   string `json:"algorithm"`
}

func (b *ciphertextBlob) backendKey() string {
	if b.ProviderKey != "" {
		return b.ProviderKey
	}
	return b.TransitKey
}

func (b *ciphertextBlob) normalize() {
	if b.Scheme == "" {
		b.Scheme = schemeTransit
	}
	if b.ProviderKey == "" {
		b.ProviderKey = b.TransitKey
	}
}

func encodeCiphertextBlob(scheme, keyID, providerKey, ciphertext, algorithm string) (string, error) {
	blob, err := json.Marshal(ciphertextBlob{
		Version:     1,
		Scheme:      scheme,
		KeyID:       keyID,
		ProviderKey: providerKey,
		Ciphertext:  ciphertext,
		Algorithm:   algorithm,
	})
	if err != nil {
		return "", fmt.Errorf("marshal ciphertext blob: %w", err)
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

func decodeCiphertextBlob(encoded string) (*ciphertextBlob, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext blob: %w", err)
	}

	var blob ciphertextBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return nil, fmt.Errorf("unmarshal ciphertext blob: %w", err)
	}
	if blob.Version != 1 {
		return nil, fmt.Errorf("unsupported ciphertext blob version: %d", blob.Version)
	}
	blob.normalize()
	if blob.KeyID == "" || blob.backendKey() == "" || blob.Ciphertext == "" || blob.Algorithm == "" {
		return nil, fmt.Errorf("ciphertext blob is missing required fields")
	}

	return &blob, nil
}
