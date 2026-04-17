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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testTransitKeyID  = "kms:11111111-1111-1111-1111-111111111111"
	testEthereumKeyID = "kms:22222222-2222-2222-2222-222222222222"
)

func TestCreateKeyStoresMetadata(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testTransitKeyID)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	var createdType string
	var kvBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			createdType = body["type"]
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"latest_version":3,"type":"aes256-gcm96"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitKeyID):
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
			return "11111111-1111-1111-1111-111111111111"
		}
		return "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	}
	defer func() { uuidNewString = origUUIDNewString }()

	resp, err := plugin.CreateKey(context.Background(), &proto.CreateKeyRequest{
		Description: "desc",
		KeySpec:     keySpecSymmetric,
		KeyUsage:    encryptDecryptUsage,
		ClientId:    clientID,
	})
	if err != nil {
		t.Fatalf("CreateKey returned error: %v", err)
	}
	if createdType != "aes256-gcm96" {
		t.Fatalf("expected aes256-gcm96 type, got %q", createdType)
	}
	if resp.KeyMetadata.KeyId != testTransitKeyID || resp.KeyMetadata.PrimaryVersion != 3 {
		t.Fatalf("unexpected metadata: %+v", resp.KeyMetadata)
	}
	if kvBody == nil {
		t.Fatal("expected metadata write")
	}
	data, ok := kvBody["data"].(map[string]any)
	if !ok || data["scheme"] != schemeTransit {
		t.Fatalf("expected transit metadata scheme, got %+v", kvBody)
	}
	if data["client_id"] != clientID {
		t.Fatalf("expected client_id in metadata, got %+v", data)
	}
}

func TestEncryptWrapsTransitCiphertext(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testTransitKeyID)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testTransitKeyID + `","client_id":"client-a","scheme":"TRANSIT","provider_key":"` + providerKey + `","key_spec":"SYMMETRIC_DEFAULT","key_usage":"ENCRYPT_DECRYPT","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/encrypt/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"ciphertext":"vault:v3:abc"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.Encrypt(context.Background(), &proto.EncryptRequest{
		KeyId:               testTransitKeyID,
		Plaintext:           "Zm9v",
		EncryptionAlgorithm: stringPtr(keySpecSymmetric),
		ClientId:            clientID,
	})
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	blob, err := decodeCiphertextBlob(resp.CiphertextBlob)
	if err != nil {
		t.Fatalf("decode ciphertext blob: %v", err)
	}
	if blob.Ciphertext != "vault:v3:abc" || blob.KeyID != testTransitKeyID {
		t.Fatalf("unexpected blob: %+v", blob)
	}
}

func TestEncryptRejectsWrongTenant(t *testing.T) {
	requestClientID := "client-b"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(requestClientID)+"/"+testTransitKeyID):
			http.NotFound(w, r)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err := plugin.Encrypt(context.Background(), &proto.EncryptRequest{
		KeyId:               testTransitKeyID,
		Plaintext:           "Zm9v",
		EncryptionAlgorithm: stringPtr(keySpecSymmetric),
		ClientId:            requestClientID,
	})
	if err == nil {
		t.Fatal("expected Encrypt to reject wrong tenant")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", status.Code(err))
	}
}

func TestCreateEthereumKeyStoresSchemeMetadata(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumKeyID)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	var kvBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/keys/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"name":"` + providerKey + `","address":"0xabc","public_key":"0xdef","created_at":"2024-01-01T00:00:00Z"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
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
			return "22222222-2222-2222-2222-222222222222"
		}
		return "33333333-3333-3333-3333-333333333333"
	}
	defer func() { uuidNewString = origUUIDNewString }()

	resp, err := plugin.CreateKey(context.Background(), &proto.CreateKeyRequest{
		Description: "eth",
		KeySpec:     keySpecECCSecgP256K1,
		KeyUsage:    signVerifyUsage,
		Scheme:      stringPtr(schemeEthereum),
		ClientId:    clientID,
	})
	if err != nil {
		t.Fatalf("CreateKey returned error: %v", err)
	}
	if resp.KeyMetadata.Scheme != schemeEthereum {
		t.Fatalf("unexpected metadata scheme: %+v", resp.KeyMetadata)
	}
	if resp.KeyMetadata.KeyId != testEthereumKeyID {
		t.Fatalf("unexpected key id: %+v", resp.KeyMetadata)
	}
	if resp.KeyMetadata.Address == nil || *resp.KeyMetadata.Address != "0xabc" {
		t.Fatalf("unexpected address: %+v", resp.KeyMetadata)
	}
	data, ok := kvBody["data"].(map[string]any)
	if !ok || data["scheme"] != schemeEthereum {
		t.Fatalf("expected ethereum metadata scheme, got %+v", kvBody)
	}
	if data["client_id"] != clientID {
		t.Fatalf("expected client_id in metadata, got %+v", data)
	}
}

func TestEthereumSignUsesEthereumEngine(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumKeyID)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/sign/"+providerKey):
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
		KeyId:            testEthereumKeyID,
		Message:          "hello",
		SigningAlgorithm: signingAlgorithmEthereumSecp256k1,
		MessageType:      stringPtr(messageTypeEIP191),
		ClientId:         clientID,
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
