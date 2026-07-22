package kms

import (
	"context"
	stdmlkem "crypto/mlkem"
	"encoding/base64"
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
	testPQCAlias = "pqc-main"
	testPQCKeyID = "kms:pqc-main"
)

func TestCreateMLDSAKeyStoresPQCMetadata(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testPQCAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	var createdVariant string
	var kvBody map[string]any
	const publicKey = "cHVibGljLWtleQ=="

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testPQCKeyID):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/pqc/mldsa/keys/"+providerKey):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			createdVariant = body["variant"]
			_, _ = w.Write([]byte(`{"data":{"name":"` + providerKey + `","version":1,"variant":"ml-dsa-65","public_key":"` + publicKey + `","created_at":"2026-07-01T00:00:00Z"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testPQCKeyID):
			_ = json.NewDecoder(r.Body).Decode(&kvBody)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := testPQCConfig(server.URL)
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))
	plugin.now = func() time.Time { return time.Unix(1, 0).UTC() }

	resp, err := plugin.CreateKey(context.Background(), &proto.CreateKeyRequest{
		Description: "pqc ml-dsa",
		KeySpec:     keySpecMLDSA65,
		KeyUsage:    signVerifyUsage,
		Scheme:      stringPtr(schemePQC),
		ClientId:    clientID,
		Alias:       testPQCAlias,
	})
	if err != nil {
		t.Fatalf("CreateKey returned error: %v", err)
	}
	if createdVariant != "ml-dsa-65" {
		t.Fatalf("created variant = %q, want ml-dsa-65", createdVariant)
	}
	if resp.KeyMetadata.Scheme != schemePQC || resp.KeyMetadata.KeyId != testPQCKeyID {
		t.Fatalf("unexpected ML-DSA key metadata: %+v", resp.KeyMetadata)
	}
	if resp.KeyMetadata.PublicKey == nil || *resp.KeyMetadata.PublicKey != publicKey {
		t.Fatalf("expected ML-DSA public key in response, got %+v", resp.KeyMetadata)
	}

	data, ok := kvBody["data"].(map[string]any)
	if !ok || data["scheme"] != schemePQC {
		t.Fatalf("expected ML-DSA metadata scheme, got %+v", kvBody)
	}
	if data["provider_key"] != providerKey || data["key_spec"] != keySpecMLDSA65 || data["key_usage"] != signVerifyUsage {
		t.Fatalf("unexpected ML-DSA metadata: %+v", data)
	}
	if data["public_key"] != publicKey {
		t.Fatalf("expected ML-DSA public key in metadata, got %+v", data)
	}
}

func TestMLDSASignUsesPQCPlugin(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testPQCAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	message := base64.StdEncoding.EncodeToString([]byte("hello ml-dsa"))
	signature := base64.StdEncoding.EncodeToString([]byte("signature"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testPQCKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testPQCKeyID + `","client_id":"client-a","alias":"` + testPQCAlias + `","scheme":"PQC","provider_key":"` + providerKey + `","key_spec":"ML_DSA_65","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2026-07-01T00:00:00Z","public_key":"cHVibGljLWtleQ==","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/pqc/mldsa/sign/"+providerKey):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["message"] != message {
				t.Fatalf("unexpected sign body: %+v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"name":"` + providerKey + `","variant":"ml-dsa-65","signature":"` + signature + `"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := testPQCConfig(server.URL)
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.Sign(context.Background(), &proto.SignRequest{
		KeyId:            testPQCAlias,
		Message:          message,
		SigningAlgorithm: signingAlgorithmMLDSA,
		MessageType:      stringPtr(messageTypeRaw),
		ClientId:         clientID,
	})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if resp.Signature != signature || resp.KeyId != testPQCKeyID || resp.SigningAlgorithm != signingAlgorithmMLDSA {
		t.Fatalf("unexpected sign response: %+v", resp)
	}
}

func TestMLDSASignRejectsInvalidBase64Message(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testPQCAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testPQCKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testPQCKeyID + `","client_id":"client-a","alias":"` + testPQCAlias + `","scheme":"PQC","provider_key":"` + providerKey + `","key_spec":"ML_DSA_65","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2026-07-01T00:00:00Z","public_key":"cHVibGljLWtleQ==","tags":[]}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := testPQCConfig(server.URL)
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.Sign(context.Background(), &proto.SignRequest{
		KeyId:            testPQCAlias,
		Message:          "not-base64",
		SigningAlgorithm: signingAlgorithmMLDSA,
		MessageType:      stringPtr(messageTypeRaw),
		ClientId:         clientID,
	})
	if err == nil {
		t.Fatal("expected Sign to reject invalid PQC message")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
	if status.Convert(err).Message() != "PQC RAW messages must be base64-encoded bytes" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPQCRejectsUnsupportedEncryption(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testPQCAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testPQCKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testPQCKeyID + `","client_id":"client-a","alias":"` + testPQCAlias + `","scheme":"PQC","provider_key":"` + providerKey + `","key_spec":"ML_DSA_65","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2026-07-01T00:00:00Z","public_key":"cHVibGljLWtleQ==","tags":[]}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := testPQCConfig(server.URL)
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.Encrypt(context.Background(), &proto.EncryptRequest{
		KeyId:               testPQCAlias,
		Plaintext:           "Zm9v",
		EncryptionAlgorithm: stringPtr(encryptionAlgorithmAES256GCM96),
		ClientId:            clientID,
	})
	if err == nil {
		t.Fatal("expected Encrypt to reject PQC keys")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", status.Code(err))
	}
	if status.Convert(err).Message() != "PQC keys do not support encryption" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateMLKEMKeyStoresPQCMetadata(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testPQCAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	var createdVariant string
	var kvBody map[string]any
	const publicKey = "cHVibGljLWtleQ=="

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testPQCKeyID):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/pqc/mlkem/keys/"+providerKey):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			createdVariant = body["variant"]
			_, _ = w.Write([]byte(`{"data":{"name":"` + providerKey + `","version":1,"variant":"ml-kem-768","public_key":"` + publicKey + `","created_at":"2026-07-01T00:00:00Z"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testPQCKeyID):
			_ = json.NewDecoder(r.Body).Decode(&kvBody)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := testPQCConfig(server.URL)
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))
	plugin.now = func() time.Time { return time.Unix(1, 0).UTC() }

	resp, err := plugin.CreateKey(context.Background(), &proto.CreateKeyRequest{
		Description: "pqc ml-kem",
		KeySpec:     keySpecMLKEM768,
		KeyUsage:    keyAgreementUsage,
		Scheme:      stringPtr(schemePQC),
		ClientId:    clientID,
		Alias:       testPQCAlias,
	})
	if err != nil {
		t.Fatalf("CreateKey returned error: %v", err)
	}
	if createdVariant != "ml-kem-768" {
		t.Fatalf("created variant = %q, want ml-kem-768", createdVariant)
	}
	if resp.KeyMetadata.Scheme != schemePQC || resp.KeyMetadata.KeyId != testPQCKeyID {
		t.Fatalf("unexpected ML-KEM key metadata: %+v", resp.KeyMetadata)
	}
	if resp.KeyMetadata.PublicKey == nil || *resp.KeyMetadata.PublicKey != publicKey {
		t.Fatalf("expected ML-KEM public key in response, got %+v", resp.KeyMetadata)
	}

	data, ok := kvBody["data"].(map[string]any)
	if !ok || data["scheme"] != schemePQC {
		t.Fatalf("expected ML-KEM metadata scheme, got %+v", kvBody)
	}
	if data["provider_key"] != providerKey || data["key_spec"] != keySpecMLKEM768 || data["key_usage"] != keyAgreementUsage {
		t.Fatalf("unexpected ML-KEM metadata: %+v", data)
	}
	if data["public_key"] != publicKey {
		t.Fatalf("expected ML-KEM public key in metadata, got %+v", data)
	}
}

func TestMLKEMEncapsulateDecapsulateRoundTrip(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testPQCAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	decapsulationKey, err := stdmlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768() error = %v", err)
	}
	publicKey := base64.StdEncoding.EncodeToString(decapsulationKey.EncapsulationKey().Bytes())
	var decapsulatedSharedKeyB64 string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testPQCKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testPQCKeyID + `","client_id":"client-a","alias":"` + testPQCAlias + `","scheme":"PQC","provider_key":"` + providerKey + `","key_spec":"ML_KEM_768","key_usage":"KEY_AGREEMENT","enabled":true,"primary_version":1,"created_at":"2026-07-01T00:00:00Z","public_key":"` + publicKey + `","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/pqc/mlkem/decapsulate/"+providerKey):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			ciphertext, decodeErr := base64.StdEncoding.DecodeString(body["ciphertext"])
			if decodeErr != nil {
				t.Fatalf("unexpected decapsulate body: %+v", body)
			}
			sharedKey, decapErr := decapsulationKey.Decapsulate(ciphertext)
			if decapErr != nil {
				t.Fatalf("Decapsulate() error = %v", decapErr)
			}
			sharedKeyB64 := base64.StdEncoding.EncodeToString(sharedKey)
			decapsulatedSharedKeyB64 = sharedKeyB64
			_, _ = w.Write([]byte(`{"data":{"name":"` + providerKey + `","variant":"ml-kem-768","shared_key":"` + sharedKeyB64 + `"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := testPQCConfig(server.URL)
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	encapResp, err := plugin.Encapsulate(context.Background(), &proto.EncapsulateRequest{
		KeyId:    testPQCAlias,
		ClientId: clientID,
	})
	if err != nil {
		t.Fatalf("Encapsulate returned error: %v", err)
	}
	if encapResp.Ciphertext == "" || encapResp.SharedKey == "" || encapResp.KeyAgreementAlgorithm != keyAgreementAlgorithmMLKEM {
		t.Fatalf("unexpected encapsulate response: %+v", encapResp)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encapResp.Ciphertext)
	if err != nil {
		t.Fatalf("encapsulate ciphertext is not base64: %v", err)
	}
	if len(ciphertext) != stdmlkem.CiphertextSize768 {
		t.Fatalf("encapsulate ciphertext has %d bytes, want %d", len(ciphertext), stdmlkem.CiphertextSize768)
	}
	sharedKey, err := base64.StdEncoding.DecodeString(encapResp.SharedKey)
	if err != nil {
		t.Fatalf("encapsulate shared key is not base64: %v", err)
	}
	if len(sharedKey) != stdmlkem.SharedKeySize {
		t.Fatalf("encapsulate shared key has %d bytes, want %d", len(sharedKey), stdmlkem.SharedKeySize)
	}

	decapResp, err := plugin.Decapsulate(context.Background(), &proto.DecapsulateRequest{
		KeyId:      testPQCAlias,
		Ciphertext: encapResp.Ciphertext,
		ClientId:   clientID,
	})
	if err != nil {
		t.Fatalf("Decapsulate returned error: %v", err)
	}
	if decapResp.KeyAgreementAlgorithm != keyAgreementAlgorithmMLKEM {
		t.Fatalf("unexpected decapsulate response: %+v", decapResp)
	}
	if decapsulatedSharedKeyB64 != encapResp.SharedKey {
		t.Fatal("encapsulate and decapsulate shared keys differ")
	}
}

func TestMLKEMDecapsulateRejectsInvalidBase64Ciphertext(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testPQCAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testPQCKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testPQCKeyID + `","client_id":"client-a","alias":"` + testPQCAlias + `","scheme":"PQC","provider_key":"` + providerKey + `","key_spec":"ML_KEM_768","key_usage":"KEY_AGREEMENT","enabled":true,"primary_version":1,"created_at":"2026-07-01T00:00:00Z","public_key":"cHVibGljLWtleQ==","tags":[]}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := testPQCConfig(server.URL)
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.Decapsulate(context.Background(), &proto.DecapsulateRequest{
		KeyId:      testPQCAlias,
		Ciphertext: "not-base64",
		ClientId:   clientID,
	})
	if err == nil {
		t.Fatal("expected Decapsulate to reject invalid PQC ciphertext")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
	if status.Convert(err).Message() != "PQC ciphertext must be base64-encoded bytes" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func testPQCConfig(openBaoURL string) *kmsConfig {
	return &kmsConfig{
		OpenBaoProxyURL: openBaoURL,
		EthereumMount:   "ethereum",
		PQCMount:        "pqc",
		TransitMount:    "transit",
		KVMount:         "secret",
		TimeoutSecs:     10,
	}
}
