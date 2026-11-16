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
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testPQCAlias = "pqc-main"
	testPQCKeyID = "kms:pqc-main"
)

func TestCreateMLDSAKey_StoresPQCMetadata(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testPQCAlias)
	if !assert.NoError(t, err) {
		return
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
	if !assert.NoError(t, err) || !assert.NotNil(t, resp) {
		return
	}

	assert.Equal(t, "ml-dsa-65", createdVariant)

	metadata := resp.GetKeyMetadata()
	if !assert.NotNil(t, metadata) {
		return
	}
	assert.Equal(t, schemePQC, metadata.GetScheme())
	assert.Equal(t, testPQCKeyID, metadata.GetKeyId())

	assert.Equal(t, publicKey, metadata.GetPublicKey())

	data, ok := kvBody["data"].(map[string]any)

	if !assert.True(t, ok) {
		return
	}
	assert.Equal(t, schemePQC, data["scheme"])

	assert.Equal(t, providerKey, data["provider_key"])
	assert.Equal(t, keySpecMLDSA65, data["key_spec"])
	assert.Equal(t, signVerifyUsage, data["key_usage"])

	assert.Equal(t, publicKey, data["public_key"])

}

func TestMLDSASign_ValidRequest_UsesPQCPlugin(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testPQCAlias)

	if !assert.NoError(t, err) {
		return
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
			if !assert.Equal(t, message, body["message"]) {
				return
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
	if !assert.NoError(t, err) || !assert.NotNil(t, resp) {
		return
	}

	assert.Equal(t, signature, resp.GetSignature())
	assert.Equal(t, testPQCKeyID, resp.GetKeyId())
	assert.Equal(t, signingAlgorithmMLDSA, resp.GetSigningAlgorithm())
	assert.Equal(t, uint32(1), resp.GetKeyVersion())

}

func TestMLDSASign_InvalidBase64Message_ReturnsInvalidArgument(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testPQCAlias)
	if !assert.NoError(t, err) {
		return
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
	if !assert.Error(t, err) {
		return
	}

	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Equal(t, "PQC RAW messages must be base64-encoded bytes", status.Convert(err).Message())
}

func TestEncrypt_PQCKey_ReturnsFailedPrecondition(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testPQCAlias)
	if !assert.NoError(t, err) {
		return
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
	if !assert.Error(t, err) {
		return
	}

	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Equal(t, "PQC keys do not support encryption", status.Convert(err).Message())
}

func TestCreateMLKEMKey_StoresPQCMetadata(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testPQCAlias)
	if !assert.NoError(t, err) {
		return
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
	if !assert.NoError(t, err) || !assert.NotNil(t, resp) {
		return
	}

	assert.Equal(t, "ml-kem-768", createdVariant)

	metadata := resp.GetKeyMetadata()
	if !assert.NotNil(t, metadata) {
		return
	}

	assert.Equal(t, schemePQC, metadata.GetScheme())
	assert.Equal(t, testPQCKeyID, metadata.GetKeyId())
	assert.Equal(t, publicKey, metadata.GetPublicKey())

	data, ok := kvBody["data"].(map[string]any)
	if !assert.True(t, ok) {
		return
	}

	assert.Equal(t, schemePQC, data["scheme"])
	assert.Equal(t, providerKey, data["provider_key"])
	assert.Equal(t, keySpecMLKEM768, data["key_spec"])
	assert.Equal(t, keyAgreementUsage, data["key_usage"])
	assert.Equal(t, publicKey, data["public_key"])
}

func TestMLKEMEncapsulateAndDecapsulate_ValidRequests_ReturnMatchingSharedKey(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testPQCAlias)
	if !assert.NoError(t, err) {
		return
	}

	decapsulationKey, err := stdmlkem.GenerateKey768()
	if !assert.NoError(t, err) {
		return
	}
	publicKey := base64.StdEncoding.EncodeToString(decapsulationKey.EncapsulationKey().Bytes())

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
	if !assert.NoError(t, err) || !assert.NotNil(t, encapResp) {
		return
	}

	if !assert.NotEmpty(t, encapResp.GetCiphertext()) || !assert.NotEmpty(t, encapResp.GetSharedKey()) {
		return
	}
	assert.Equal(t, keyAgreementAlgorithmMLKEM, encapResp.GetKeyAgreementAlgorithm())

	ciphertext, err := base64.StdEncoding.DecodeString(encapResp.GetCiphertext())
	if !assert.NoError(t, err) {
		return
	}
	assert.Len(t, ciphertext, stdmlkem.CiphertextSize768)

	sharedKey, err := base64.StdEncoding.DecodeString(encapResp.GetSharedKey())
	if !assert.NoError(t, err) {
		return
	}
	assert.Len(t, sharedKey, stdmlkem.SharedKeySize)

	decapResp, err := plugin.Decapsulate(context.Background(), &proto.DecapsulateRequest{
		KeyId:      testPQCAlias,
		Ciphertext: encapResp.GetCiphertext(),
		ClientId:   clientID,
	})
	if !assert.NoError(t, err) || !assert.NotNil(t, decapResp) {
		return
	}

	assert.Equal(t, keyAgreementAlgorithmMLKEM, decapResp.GetKeyAgreementAlgorithm())
	assert.Equal(t, encapResp.GetSharedKey(), decapResp.GetSharedKey())
}

func TestMLKEMDecapsulate_InvalidBase64Ciphertext_ReturnsInvalidArgument(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testPQCAlias)
	if !assert.NoError(t, err) {
		return
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
	if !assert.Error(t, err) {
		return
	}

	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Equal(t, "PQC ciphertext must be base64-encoded bytes", status.Convert(err).Message())
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
