package kms

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testTransitAlias     = "transit-main"
	testTransitKeyID     = "kms:transit-main"
	testTransitSignAlias = "transit-sign"
	testTransitSignKeyID = "kms:transit-sign"
	testEthereumAlias    = "eth-main"
	testEthereumKeyID    = "kms:eth-main"
)

func TestCreateKey_ValidRequest_StoresMetadata(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testTransitAlias)

	require.NoError(t, err)

	var createdType string
	var kvBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitKeyID):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			createdType = body["type"]
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"latest_version":3,"type":"aes256-gcm96","keys":{"1":1700000000,"2":1700000100,"3":1700000200}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitKeyID):
			_ = json.NewDecoder(r.Body).Decode(&kvBody)
			_, _ = w.Write([]byte(`{}`))
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
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

	resp, err := plugin.CreateKey(context.Background(), &proto.CreateKeyRequest{
		Description: "desc",
		KeySpec:     keySpecAES256GCM96,
		KeyUsage:    encryptDecryptUsage,
		ClientId:    clientID,
		Alias:       testTransitAlias,
	})
	require.NoError(t, err)

	assert.Equal(t, "aes256-gcm96", createdType)

	require.NotNil(t, resp)
	require.NotNil(t, resp.KeyMetadata)
	assert.Equal(t, testTransitKeyID, resp.KeyMetadata.KeyId)
	assert.Equal(t, uint32(3), resp.KeyMetadata.PrimaryVersion)
	assert.Equal(t, testTransitAlias, resp.KeyMetadata.Alias)
	assert.Equal(t, keySpecAES256GCM96, resp.KeyMetadata.KeySpec)
	data, ok := kvBody["data"].(map[string]any)
	require.True(t, ok, "expected metadata data object, got %+v", kvBody)
	assert.Equal(t, schemeTransit, data["scheme"])
	assert.Equal(t, clientID, data["client_id"])
	assert.Equal(t, testTransitAlias, data["alias"])
	assert.Equal(t, keySpecAES256GCM96, data["key_spec"])
}

func TestCreateKey_DuplicateAlias_ReturnsAlreadyExists(t *testing.T) {
	clientID := "client-a"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testTransitKeyID + `","client_id":"` + clientID + `","alias":"` + testTransitAlias + `","scheme":"TRANSIT","provider_key":"tenant_x_` + testTransitAlias + `","key_spec":"AES_256_GCM96","key_usage":"ENCRYPT_DECRYPT","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","tags":[]}}}`))
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err := plugin.CreateKey(context.Background(), &proto.CreateKeyRequest{
		Description: "desc",
		KeySpec:     keySpecAES256GCM96,
		KeyUsage:    encryptDecryptUsage,
		ClientId:    clientID,
		Alias:       testTransitAlias,
	})
	require.Error(t, err, "expected CreateKey to reject duplicate alias")
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestCreateKey_TransitAsymmetricKey_ReturnsPublicKey(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testTransitSignAlias)
	require.NoError(t, err)

	var kvBody map[string]any
	const oldPublicKey = "-----BEGIN PUBLIC KEY-----old-----END PUBLIC KEY-----"
	const publicKey = "-----BEGIN PUBLIC KEY-----demo-----END PUBLIC KEY-----"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitSignKeyID):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"latest_version":2,"type":"ecdsa-p256","keys":{"1":{"name":"P-256","public_key":"` + oldPublicKey + `","creation_time":"2024-01-01T00:00:00Z"},"2":{"name":"P-256","public_key":"` + publicKey + `","creation_time":"2024-01-02T00:00:00Z"}}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitSignKeyID):
			_ = json.NewDecoder(r.Body).Decode(&kvBody)
			_, _ = w.Write([]byte(`{}`))
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
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

	resp, err := plugin.CreateKey(context.Background(), &proto.CreateKeyRequest{
		Description: "signing key",
		KeySpec:     keySpecECDSAP256,
		KeyUsage:    signVerifyUsage,
		ClientId:    clientID,
		Alias:       testTransitSignAlias,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.KeyMetadata)
	assert.Equal(t, uint32(2), resp.KeyMetadata.PrimaryVersion)
	require.NotNil(t, resp.KeyMetadata.PublicKey)
	assert.Equal(t, publicKey, *resp.KeyMetadata.PublicKey)
	data, ok := kvBody["data"].(map[string]any)
	require.True(t, ok, "expected metadata data object, got %+v", kvBody)
	assert.Equal(t, publicKey, data["public_key"])
}

func TestGetKeyMetadata_KeyIDOrAlias_ReturnsMetadata(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testTransitSignAlias)
	require.NoError(t, err)
	const publicKey = "-----BEGIN PUBLIC KEY-----demo-----END PUBLIC KEY-----"

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitSignKeyID):
			requests++
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testTransitSignKeyID + `","client_id":"` + clientID + `","alias":"` + testTransitSignAlias + `","scheme":"TRANSIT","provider_key":"` + providerKey + `","key_spec":"ECDSA_P256","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"` + publicKey + `","tags":[]}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	for _, keyRef := range []string{testTransitSignKeyID, testTransitSignAlias} {
		resp, err := plugin.GetKeyMetadata(context.Background(), &proto.GetKeyMetadataRequest{
			KeyId:    keyRef,
			ClientId: clientID,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.KeyMetadata)
		assert.Equal(t, testTransitSignKeyID, resp.KeyMetadata.KeyId)
		assert.Equal(t, testTransitSignAlias, resp.KeyMetadata.Alias)
		require.NotNil(t, resp.KeyMetadata.PublicKey)
		assert.Equal(t, publicKey, *resp.KeyMetadata.PublicKey)
	}

	assert.Equal(t, 2, requests)
}

func TestGetKeyMetadata_MissingClientID_ReturnsInvalidArgument(t *testing.T) {
	plugin := newPlugin(&kmsConfig{
		OpenBaoProxyURL: "http://127.0.0.1:1",
		EthereumMount:   "ethereum",
		TransitMount:    "transit",
		KVMount:         "secret",
		TimeoutSecs:     10,
	}, nil)

	_, err := plugin.GetKeyMetadata(context.Background(), &proto.GetKeyMetadataRequest{
		KeyId: testTransitSignKeyID,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetKeyMetadata_WrongTenant_ReturnsPermissionDenied(t *testing.T) {
	requestClientID := "client-b"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(requestClientID)+"/"+testTransitSignKeyID):
			http.NotFound(w, r)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err := plugin.GetKeyMetadata(context.Background(), &proto.GetKeyMetadataRequest{
		KeyId:    testTransitSignKeyID,
		ClientId: requestClientID,
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestGetPublicKey_KeyIDOrAlias_ReturnsRequestedVersion(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testTransitSignAlias)
	require.NoError(t, err)
	const oldPublicKey = "-----BEGIN PUBLIC KEY-----old-----END PUBLIC KEY-----"
	const publicKey = "-----BEGIN PUBLIC KEY-----demo-----END PUBLIC KEY-----"
	const latestPublicKey = "-----BEGIN PUBLIC KEY-----latest-----END PUBLIC KEY-----"

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitSignKeyID):
			requests++
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testTransitSignKeyID + `","client_id":"` + clientID + `","alias":"` + testTransitSignAlias + `","scheme":"TRANSIT","provider_key":"` + providerKey + `","key_spec":"ECDSA_P256","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":2,"created_at":"2024-01-01T00:00:00Z","public_key":"` + publicKey + `","tags":[]}}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"latest_version":3,"type":"ecdsa-p256","keys":{"1":{"name":"P-256","public_key":"` + oldPublicKey + `","creation_time":"2024-01-01T00:00:00Z"},"2":{"name":"P-256","public_key":"` + publicKey + `","creation_time":"2024-01-02T00:00:00Z"},"3":{"name":"P-256","public_key":"` + latestPublicKey + `","creation_time":"2024-01-03T00:00:00Z"}}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	for _, keyRef := range []string{testTransitSignKeyID, testTransitSignAlias} {
		resp, err := plugin.GetPublicKey(context.Background(), &proto.GetPublicKeyRequest{
			KeyId:    keyRef,
			ClientId: clientID,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, publicKey, resp.PublicKey)
		assert.Equal(t, uint32(2), resp.Version)
	}

	resp, err := plugin.GetPublicKey(context.Background(), &proto.GetPublicKeyRequest{
		KeyId:    testTransitSignAlias,
		ClientId: clientID,
		Version:  uint32Ptr(1),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, oldPublicKey, resp.PublicKey)
	assert.Equal(t, uint32(1), resp.Version)
	assert.Equal(t, 3, requests)
}

func TestGetPublicKey_MissingClientID_ReturnsInvalidArgument(t *testing.T) {
	plugin := newPlugin(&kmsConfig{
		OpenBaoProxyURL: "http://127.0.0.1:1",
		EthereumMount:   "ethereum",
		TransitMount:    "transit",
		KVMount:         "secret",
		TimeoutSecs:     10,
	}, nil)

	_, err := plugin.GetPublicKey(context.Background(), &proto.GetPublicKeyRequest{
		KeyId: testTransitSignKeyID,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetPublicKey_ZeroVersion_ReturnsInvalidArgument(t *testing.T) {
	plugin := newPlugin(&kmsConfig{
		OpenBaoProxyURL: "http://127.0.0.1:1",
		EthereumMount:   "ethereum",
		TransitMount:    "transit",
		KVMount:         "secret",
		TimeoutSecs:     10,
	}, nil)

	_, err := plugin.GetPublicKey(context.Background(), &proto.GetPublicKeyRequest{
		KeyId:    testTransitSignKeyID,
		ClientId: "client-a",
		Version:  uint32Ptr(0),
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetPublicKey_WrongTenant_ReturnsPermissionDenied(t *testing.T) {
	requestClientID := "client-b"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(requestClientID)+"/"+testTransitSignKeyID):
			http.NotFound(w, r)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err := plugin.GetPublicKey(context.Background(), &proto.GetPublicKeyRequest{
		KeyId:    testTransitSignKeyID,
		ClientId: requestClientID,
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestGetPublicKey_KeyWithoutPublicKey_ReturnsFailedPrecondition(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testTransitAlias)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testTransitKeyID + `","client_id":"` + clientID + `","alias":"` + testTransitAlias + `","scheme":"TRANSIT","provider_key":"` + providerKey + `","key_spec":"AES_256_GCM96","key_usage":"ENCRYPT_DECRYPT","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","tags":[]}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.GetPublicKey(context.Background(), &proto.GetPublicKeyRequest{
		KeyId:    testTransitKeyID,
		ClientId: clientID,
	})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestSign_TransitKey_UsesMetadataPrimaryVersion(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testTransitSignAlias)
	require.NoError(t, err)

	message := base64.StdEncoding.EncodeToString([]byte("hello"))
	signRequests := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitSignKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testTransitSignKeyID + `","client_id":"` + clientID + `","alias":"` + testTransitSignAlias + `","scheme":"TRANSIT","provider_key":"` + providerKey + `","key_spec":"ECDSA_P256","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":2,"created_at":"2024-01-01T00:00:00Z","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/sign/"+providerKey+"/sha2-256"):
			signRequests++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("Decode sign body error = %v", err)
			}
			if body["input"] != message {
				t.Fatalf("expected input %q, got %+v", message, body)
			}
			if body["prehashed"] != false {
				t.Fatalf("expected prehashed=false, got %+v", body)
			}
			if body["key_version"] != float64(2) {
				t.Fatalf("expected key_version=2, got %+v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"signature":"vault:v2:signed"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.Sign(context.Background(), &proto.SignRequest{
		KeyId:            testTransitSignAlias,
		Message:          message,
		SigningAlgorithm: "ECDSA_SHA_256",
		MessageType:      stringPtr(messageTypeRaw),
		ClientId:         clientID,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "vault:v2:signed", resp.Signature)
	assert.Equal(t, testTransitSignKeyID, resp.KeyId)
	assert.Equal(t, uint32(2), resp.KeyVersion)
	assert.Equal(t, 1, signRequests)
}

func TestEncrypt_TransitKey_WrapsCiphertext(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testTransitAlias)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testTransitKeyID + `","client_id":"client-a","alias":"` + testTransitAlias + `","scheme":"TRANSIT","provider_key":"` + providerKey + `","key_spec":"AES_256_GCM96","key_usage":"ENCRYPT_DECRYPT","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/encrypt/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"ciphertext":"vault:v3:abc"}}`))
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.Encrypt(context.Background(), &proto.EncryptRequest{
		KeyId:               testTransitAlias,
		Plaintext:           "Zm9v",
		EncryptionAlgorithm: stringPtr(encryptionAlgorithmAES256GCM96),
		ClientId:            clientID,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	blob, err := decodeCiphertextBlob(resp.CiphertextBlob)
	require.NoError(t, err)
	assert.Equal(t, "vault:v3:abc", blob.Ciphertext)
	assert.Equal(t, testTransitKeyID, blob.KeyID)
	assert.Equal(t, testTransitKeyID, resp.KeyId)
	assert.Equal(t, encryptionAlgorithmAES256GCM96, resp.EncryptionAlgorithm)
}

func TestEncrypt_WrongTenant_ReturnsPermissionDenied(t *testing.T) {
	requestClientID := "client-b"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(requestClientID)+"/"+testTransitKeyID):
			http.NotFound(w, r)
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err := plugin.Encrypt(context.Background(), &proto.EncryptRequest{
		KeyId:               testTransitAlias,
		Plaintext:           "Zm9v",
		EncryptionAlgorithm: stringPtr(encryptionAlgorithmAES256GCM96),
		ClientId:            requestClientID,
	})
	require.Error(t, err, "expected Encrypt to reject wrong tenant")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestCreateKey_EthereumKey_StoresSchemeMetadata(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	require.NoError(t, err)

	var kvBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/keys/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"name":"` + providerKey + `","address":"0xabc","public_key":"0xdef","created_at":"2024-01-01T00:00:00Z"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_ = json.NewDecoder(r.Body).Decode(&kvBody)
			_, _ = w.Write([]byte(`{}`))
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))
	plugin.now = func() time.Time { return time.Unix(1, 0).UTC() }

	resp, err := plugin.CreateKey(context.Background(), &proto.CreateKeyRequest{
		Description: "eth",
		KeySpec:     keySpecECCSecgP256K1,
		KeyUsage:    signVerifyUsage,
		Scheme:      stringPtr(schemeEthereum),
		ClientId:    clientID,
		Alias:       testEthereumAlias,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.KeyMetadata)
	assert.Equal(t, schemeEthereum, resp.KeyMetadata.Scheme)
	assert.Equal(t, testEthereumKeyID, resp.KeyMetadata.KeyId)
	assert.Equal(t, testEthereumAlias, resp.KeyMetadata.Alias)
	data, ok := kvBody["data"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, schemeEthereum, data["scheme"])
	assert.Equal(t, clientID, data["client_id"])
	assert.Equal(t, testEthereumAlias, data["alias"])
}

func TestSign_EthereumKey_UsesEthereumEngine(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/sign/"+providerKey):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if !assert.Equal(t, "hello", body["message"]) {
				http.Error(w, "unexpected sign body", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"signature":"0xsigned","hash":"0xhash","method":"eip191","address":"0xabc"}}`))
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.Sign(context.Background(), &proto.SignRequest{
		KeyId:            testEthereumAlias,
		Message:          "hello",
		SigningAlgorithm: signingAlgorithmEthereumSecp256k1,
		MessageType:      stringPtr(messageTypeEIP191),
		ClientId:         clientID,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "0xsigned", resp.Signature)
	assert.Equal(t, testEthereumKeyID, resp.KeyId)
	assert.Equal(t, uint32(1), resp.KeyVersion)
}

func TestSign_EthereumRawMessageTypes_HashesDecodedBytes(t *testing.T) {
	tests := []struct {
		name        string
		messageType *string
	}{
		{
			name:        "explicit_raw",
			messageType: stringPtr(messageTypeRaw),
		},
		{
			name:        "omitted_defaults_to_raw",
			messageType: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientID := "client-a"
			providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
			require.NoError(t, err)

			rawMessage := []byte("deploy-bytes")
			encodedMessage := base64.StdEncoding.EncodeToString(rawMessage)
			hasher := sha3.NewLegacyKeccak256()
			_, err = hasher.Write(rawMessage)
			require.NoError(t, err)
			expectedHash := "0x" + hex.EncodeToString(hasher.Sum(nil))

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
					_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/sign/"+providerKey):
					var body map[string]string
					_ = json.NewDecoder(r.Body).Decode(&body)
					if !assert.Equal(t, expectedHash, body["hash"]) {
						http.Error(w, "unexpected sign body", http.StatusBadRequest)
						return
					}
					if !assert.NotContains(t, body, "message") {
						http.Error(w, "unexpected sign body", http.StatusBadRequest)
						return
					}
					_, _ = w.Write([]byte(`{"data":{"signature":"0xsigned","hash":"` + expectedHash + `","method":"` + ethereumSignMethodRawHash + `","address":"0xabc"}}`))
				default:
					assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected request", http.StatusInternalServerError)
				}
			}))
			defer server.Close()

			cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
			plugin := newPlugin(cfg, newOpenBaoClient(cfg))

			resp, err := plugin.Sign(context.Background(), &proto.SignRequest{
				KeyId:            testEthereumAlias,
				Message:          encodedMessage,
				SigningAlgorithm: signingAlgorithmEthereumSecp256k1,
				MessageType:      tc.messageType,
				ClientId:         clientID,
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, "0xsigned", resp.Signature)
			assert.Equal(t, testEthereumKeyID, resp.KeyId)
		})
	}
}

func TestSign_EthereumRawInvalidBase64_ReturnsInvalidArgument(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.Sign(context.Background(), &proto.SignRequest{
		KeyId:            testEthereumAlias,
		Message:          "not-base64",
		SigningAlgorithm: signingAlgorithmEthereumSecp256k1,
		MessageType:      stringPtr(messageTypeRaw),
		ClientId:         clientID,
	})
	require.Error(t, err, "expected Sign to reject invalid RAW message")
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Equal(t, "ETHEREUM RAW messages must be base64-encoded bytes", status.Convert(err).Message())
}

func TestSign_EthereumDigestEncodings_NormalizesHash(t *testing.T) {
	digestBytes, err := hex.DecodeString("25f6c888f741660abd3e48fe2316b0c6095ea1aa9240d5324575d9fca9f2de45")
	require.NoError(t, err)
	encodedDigest := base64.StdEncoding.EncodeToString(digestBytes)
	expectedHash := "0x" + hex.EncodeToString(digestBytes)

	tests := []struct {
		name    string
		message string
	}{
		{name: "base64", message: encodedDigest},
		{name: "hex", message: expectedHash},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientID := "client-a"
			providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
			require.NoError(t, err)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
					_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/sign/"+providerKey):
					var body map[string]string
					_ = json.NewDecoder(r.Body).Decode(&body)
					if !assert.Equal(t, expectedHash, body["hash"]) {
						http.Error(w, "unexpected sign body", http.StatusBadRequest)
						return
					}
					if !assert.NotContains(t, body, "message") {
						http.Error(w, "unexpected sign body", http.StatusBadRequest)
						return
					}
					_, _ = w.Write([]byte(`{"data":{"signature":"0xsigned","hash":"` + expectedHash + `","method":"` + ethereumSignMethodRawHash + `","address":"0xabc"}}`))
				default:
					assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected request", http.StatusInternalServerError)
				}
			}))
			defer server.Close()

			cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
			plugin := newPlugin(cfg, newOpenBaoClient(cfg))

			resp, err := plugin.Sign(context.Background(), &proto.SignRequest{
				KeyId:            testEthereumAlias,
				Message:          tc.message,
				SigningAlgorithm: signingAlgorithmEthereumSecp256k1,
				MessageType:      stringPtr(messageTypeDigest),
				ClientId:         clientID,
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, "0xsigned", resp.Signature)
			assert.Equal(t, testEthereumKeyID, resp.KeyId)
		})
	}
}

func TestSign_EthereumDigestWrongLength_ReturnsInvalidArgument(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.Sign(context.Background(), &proto.SignRequest{
		KeyId:            testEthereumAlias,
		Message:          "0x1234",
		SigningAlgorithm: signingAlgorithmEthereumSecp256k1,
		MessageType:      stringPtr(messageTypeDigest),
		ClientId:         clientID,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Equal(t, "ETHEREUM DIGEST messages must be exactly 32 bytes", status.Convert(err).Message())
}

func TestSign_EthereumInvalidDigestResponse_ReturnsInternal(t *testing.T) {
	digestBytes, err := hex.DecodeString("25f6c888f741660abd3e48fe2316b0c6095ea1aa9240d5324575d9fca9f2de45")
	require.NoError(t, err)
	encodedDigest := base64.StdEncoding.EncodeToString(digestBytes)
	expectedHash := "0x" + hex.EncodeToString(digestBytes)

	tests := []struct {
		name           string
		responseHash   string
		responseMethod string
		expectedError  string
	}{
		{
			name:           "unexpected_hash",
			responseHash:   "0xdeadbeef",
			responseMethod: ethereumSignMethodRawHash,
			expectedError:  "ethereum signing response hash mismatch",
		},
		{
			name:           "unexpected_method",
			responseHash:   expectedHash,
			responseMethod: "eip191",
			expectedError:  "ethereum signing response method mismatch",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientID := "client-a"
			providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
			require.NoError(t, err)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
					_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/sign/"+providerKey):
					_, _ = w.Write([]byte(`{"data":{"signature":"0xsigned","hash":"` + tc.responseHash + `","method":"` + tc.responseMethod + `","address":"0xabc"}}`))
				default:
					assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected request", http.StatusInternalServerError)
				}
			}))
			defer server.Close()

			cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
			plugin := newPlugin(cfg, newOpenBaoClient(cfg))

			_, err = plugin.Sign(context.Background(), &proto.SignRequest{
				KeyId:            testEthereumAlias,
				Message:          encodedDigest,
				SigningAlgorithm: signingAlgorithmEthereumSecp256k1,
				MessageType:      stringPtr(messageTypeDigest),
				ClientId:         clientID,
			})
			require.Error(t, err)
			assert.Equal(t, codes.Internal, status.Code(err))
			assert.Equal(t, tc.expectedError, status.Convert(err).Message())
		})
	}
}

func TestEncrypt_EthereumKey_ReturnsFailedPrecondition(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.Encrypt(context.Background(), &proto.EncryptRequest{
		KeyId:               testEthereumAlias,
		Plaintext:           "Zm9v",
		EncryptionAlgorithm: stringPtr(encryptionAlgorithmAES256GCM96),
		ClientId:            clientID,
	})
	require.Error(t, err, "expected Encrypt to reject ethereum keys")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Equal(t, "ETHEREUM keys do not support encryption", status.Convert(err).Message())
}

func TestDecrypt_EthereumKey_ReturnsFailedPrecondition(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	ciphertextBlob, err := encodeCiphertextBlob(schemeEthereum, testEthereumKeyID, providerKey, "0xdeadbeef", encryptionAlgorithmAES256GCM96)
	require.NoError(t, err)

	_, err = plugin.Decrypt(context.Background(), &proto.DecryptRequest{
		CiphertextBlob: ciphertextBlob,
		ClientId:       clientID,
	})
	require.Error(t, err, "expected Decrypt to reject ethereum keys")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Equal(t, "ETHEREUM keys do not support decryption", status.Convert(err).Message())
}

func TestRotateKey_EthereumKey_ReturnsUnimplemented(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.RotateKey(context.Background(), &proto.RotateKeyRequest{
		KeyId:    testEthereumAlias,
		ClientId: clientID,
	})
	require.Error(t, err, "expected RotateKey to reject ethereum keys")
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	assert.Equal(t, "ETHEREUM key rotation is not implemented", status.Convert(err).Message())
}

func stringPtr(value string) *string {
	return &value
}

func uint32Ptr(value uint32) *uint32 {
	return &value
}
