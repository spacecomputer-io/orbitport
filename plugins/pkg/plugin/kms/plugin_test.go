package kms

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

func TestCreateKeyStoresMetadata(t *testing.T) {
	var createdType string
	var kvBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/kms-test-transit"):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			createdType = body["type"]
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/kms-test-transit"):
			_, _ = w.Write([]byte(`{"data":{"latest_version":3,"type":"aes256-gcm96"}}`))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/v1/secret/data/kms/metadata/"):
			_ = json.NewDecoder(r.Body).Decode(&kvBody)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{
		OpenBaoProxyURL: server.URL,
		EthereumMount:   "ethereum",
		TransitMount:    "transit",
		KVMount:         "secret",
		TimeoutSecs:     10,
	}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))
	plugin.now = func() time.Time { return time.Unix(1, 0).UTC() }

	uuidCounter := 0
	origUUIDNewString := uuidNewString
	uuidNewString = func() string {
		uuidCounter++
		if uuidCounter == 1 {
			return "test"
		}
		return "test-transit"
	}
	defer func() { uuidNewString = origUUIDNewString }()

	resp, err := plugin.CreateKey(context.Background(), &proto.CreateKeyRequest{
		Description: "desc",
		KeySpec:     keySpecSymmetric,
		KeyUsage:    encryptDecryptUsage,
	})
	if err != nil {
		t.Fatalf("CreateKey returned error: %v", err)
	}
	if createdType != "aes256-gcm96" {
		t.Fatalf("expected aes256-gcm96 type, got %q", createdType)
	}
	if resp.KeyMetadata.KeyId != "kms:test" || resp.KeyMetadata.PrimaryVersion != 3 {
		t.Fatalf("unexpected metadata: %+v", resp.KeyMetadata)
	}
	if kvBody == nil {
		t.Fatal("expected metadata write")
	}
	data, ok := kvBody["data"].(map[string]any)
	if !ok || data["scheme"] != schemeTransit {
		t.Fatalf("expected transit metadata scheme, got %+v", kvBody)
	}
}

func TestEncryptWrapsTransitCiphertext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/kms:test"):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"kms:test","scheme":"TRANSIT","provider_key":"kms-test","key_spec":"SYMMETRIC_DEFAULT","key_usage":"ENCRYPT_DECRYPT","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/encrypt/kms-test"):
			_, _ = w.Write([]byte(`{"data":{"ciphertext":"vault:v3:abc"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.Encrypt(context.Background(), &proto.EncryptRequest{
		KeyId:               "kms:test",
		Plaintext:           "Zm9v",
		EncryptionAlgorithm: stringPtr(keySpecSymmetric),
	})
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	blob, err := decodeCiphertextBlob(resp.CiphertextBlob)
	if err != nil {
		t.Fatalf("decode ciphertext blob: %v", err)
	}
	if blob.Ciphertext != "vault:v3:abc" || blob.KeyID != "kms:test" {
		t.Fatalf("unexpected blob: %+v", blob)
	}
}

func TestCreateEthereumKeyStoresSchemeMetadata(t *testing.T) {
	var kvBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/keys/kms-eth-key"):
			_, _ = w.Write([]byte(`{"data":{"name":"kms-eth-key","address":"0xabc","public_key":"0xdef","created_at":"2024-01-01T00:00:00Z"}}`))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/v1/secret/data/kms/metadata/"):
			_ = json.NewDecoder(r.Body).Decode(&kvBody)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))
	plugin.now = func() time.Time { return time.Unix(1, 0).UTC() }

	origUUIDNewString := uuidNewString
	uuidCounter := 0
	uuidNewString = func() string {
		uuidCounter++
		if uuidCounter == 1 {
			return "eth"
		}
		return "eth-key"
	}
	defer func() { uuidNewString = origUUIDNewString }()

	resp, err := plugin.CreateKey(context.Background(), &proto.CreateKeyRequest{
		Description: "eth",
		KeySpec:     keySpecECCSecgP256K1,
		KeyUsage:    signVerifyUsage,
		Scheme:      stringPtr(schemeEthereum),
	})
	if err != nil {
		t.Fatalf("CreateKey returned error: %v", err)
	}
	if resp.KeyMetadata.Scheme != schemeEthereum {
		t.Fatalf("unexpected metadata scheme: %+v", resp.KeyMetadata)
	}
	if resp.KeyMetadata.Address == nil || *resp.KeyMetadata.Address != "0xabc" {
		t.Fatalf("unexpected address: %+v", resp.KeyMetadata)
	}
	data, ok := kvBody["data"].(map[string]any)
	if !ok || data["scheme"] != schemeEthereum {
		t.Fatalf("expected ethereum metadata scheme, got %+v", kvBody)
	}
}

func TestEthereumSignUsesEthereumEngine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/kms:eth"):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"kms:eth","scheme":"ETHEREUM","provider_key":"kms-eth","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/sign/kms-eth"):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["message"] != "hello" {
				t.Fatalf("unexpected sign body: %+v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"signature":"0xsigned","hash":"0xhash","method":"eip191","address":"0xabc"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.Sign(context.Background(), &proto.SignRequest{
		KeyId:            "kms:eth",
		Message:          "hello",
		SigningAlgorithm: signingAlgorithmEthereumSecp256k1,
		MessageType:      stringPtr(messageTypeEIP191),
	})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if resp.Signature != "0xsigned" {
		t.Fatalf("unexpected signature: %+v", resp)
	}
}

func stringPtr(value string) *string {
	return &value
}
