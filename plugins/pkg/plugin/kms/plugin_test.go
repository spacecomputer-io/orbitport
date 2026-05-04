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

func TestCreateKeyStoresMetadata(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testTransitAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

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

	resp, err := plugin.CreateKey(context.Background(), &proto.CreateKeyRequest{
		Description: "desc",
		KeySpec:     keySpecAES256GCM96,
		KeyUsage:    encryptDecryptUsage,
		ClientId:    clientID,
		Alias:       testTransitAlias,
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
	if resp.KeyMetadata.Alias != testTransitAlias {
		t.Fatalf("unexpected alias in response: %+v", resp.KeyMetadata)
	}
	if resp.KeyMetadata.KeySpec != keySpecAES256GCM96 {
		t.Fatalf("expected canonical key spec in response, got %+v", resp.KeyMetadata)
	}
	data, ok := kvBody["data"].(map[string]any)
	if !ok || data["scheme"] != schemeTransit {
		t.Fatalf("expected transit metadata scheme, got %+v", kvBody)
	}
	if data["client_id"] != clientID || data["alias"] != testTransitAlias {
		t.Fatalf("expected client_id and alias in metadata, got %+v", data)
	}
	if data["key_spec"] != keySpecAES256GCM96 {
		t.Fatalf("expected canonical key_spec in metadata, got %+v", data)
	}
}

func TestCreateKeyRejectsDuplicateAlias(t *testing.T) {
	clientID := "client-a"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testTransitKeyID + `","client_id":"` + clientID + `","alias":"` + testTransitAlias + `","scheme":"TRANSIT","provider_key":"tenant_x_` + testTransitAlias + `","key_spec":"AES_256_GCM96","key_usage":"ENCRYPT_DECRYPT","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","tags":[]}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
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
	if err == nil {
		t.Fatal("expected CreateKey to reject duplicate alias")
	}
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected AlreadyExists, got %v", status.Code(err))
	}
}

func TestCreateTransitAsymmetricKeyReturnsPublicKey(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testTransitSignAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	var kvBody map[string]any
	const publicKey = "-----BEGIN PUBLIC KEY-----demo-----END PUBLIC KEY-----"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitSignKeyID):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"latest_version":1,"type":"ecdsa-p256","public_key":"` + publicKey + `"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitSignKeyID):
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

	resp, err := plugin.CreateKey(context.Background(), &proto.CreateKeyRequest{
		Description: "signing key",
		KeySpec:     keySpecECDSAP256,
		KeyUsage:    signVerifyUsage,
		ClientId:    clientID,
		Alias:       testTransitSignAlias,
	})
	if err != nil {
		t.Fatalf("CreateKey returned error: %v", err)
	}
	if resp.KeyMetadata.PublicKey == nil || *resp.KeyMetadata.PublicKey != publicKey {
		t.Fatalf("expected transit public key in response, got %+v", resp.KeyMetadata)
	}
	data, ok := kvBody["data"].(map[string]any)
	if !ok || data["public_key"] != publicKey {
		t.Fatalf("expected transit public key in metadata, got %+v", kvBody)
	}
}

func TestEncryptWrapsTransitCiphertext(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testTransitAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testTransitKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testTransitKeyID + `","client_id":"client-a","alias":"` + testTransitAlias + `","scheme":"TRANSIT","provider_key":"` + providerKey + `","key_spec":"AES_256_GCM96","key_usage":"ENCRYPT_DECRYPT","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","tags":[]}}}`))
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
		KeyId:               testTransitAlias,
		Plaintext:           "Zm9v",
		EncryptionAlgorithm: stringPtr(encryptionAlgorithmAES256GCM96),
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
	if resp.KeyId != testTransitKeyID {
		t.Fatalf("expected canonical key id in response, got %+v", resp)
	}
	if resp.EncryptionAlgorithm != encryptionAlgorithmAES256GCM96 {
		t.Fatalf("expected canonical encryption algorithm in response, got %+v", resp)
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
		KeyId:               testTransitAlias,
		Plaintext:           "Zm9v",
		EncryptionAlgorithm: stringPtr(encryptionAlgorithmAES256GCM96),
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
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

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
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
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
	if err != nil {
		t.Fatalf("CreateKey returned error: %v", err)
	}
	if resp.KeyMetadata.Scheme != schemeEthereum || resp.KeyMetadata.KeyId != testEthereumKeyID {
		t.Fatalf("unexpected metadata: %+v", resp.KeyMetadata)
	}
	if resp.KeyMetadata.Alias != testEthereumAlias {
		t.Fatalf("unexpected alias: %+v", resp.KeyMetadata)
	}
	data, ok := kvBody["data"].(map[string]any)
	if !ok || data["scheme"] != schemeEthereum {
		t.Fatalf("expected ethereum metadata scheme, got %+v", kvBody)
	}
	if data["client_id"] != clientID || data["alias"] != testEthereumAlias {
		t.Fatalf("expected client_id and alias in metadata, got %+v", data)
	}
}

func TestEthereumSignUsesEthereumEngine(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
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
		KeyId:            testEthereumAlias,
		Message:          "hello",
		SigningAlgorithm: signingAlgorithmEthereumSecp256k1,
		MessageType:      stringPtr(messageTypeEIP191),
		ClientId:         clientID,
	})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if resp.Signature != "0xsigned" || resp.KeyId != testEthereumKeyID {
		t.Fatalf("unexpected sign response: %+v", resp)
	}
}

func TestEthereumSignRawHashesDecodedBytes(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	rawMessage := []byte("deploy-bytes")
	encodedMessage := base64.StdEncoding.EncodeToString(rawMessage)
	hasher := sha3.NewLegacyKeccak256()
	_, _ = hasher.Write(rawMessage)
	expectedHash := "0x" + hex.EncodeToString(hasher.Sum(nil))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/sign/"+providerKey):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["hash"] != expectedHash {
				t.Fatalf("unexpected sign body: %+v", body)
			}
			if _, ok := body["message"]; ok {
				t.Fatalf("expected RAW signing to use hash body, got %+v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"signature":"0xsigned","hash":"` + expectedHash + `","method":"` + ethereumSignMethodRawHash + `","address":"0xabc"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.Sign(context.Background(), &proto.SignRequest{
		KeyId:            testEthereumAlias,
		Message:          encodedMessage,
		SigningAlgorithm: signingAlgorithmEthereumSecp256k1,
		MessageType:      stringPtr(messageTypeRaw),
		ClientId:         clientID,
	})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if resp.Signature != "0xsigned" || resp.KeyId != testEthereumKeyID {
		t.Fatalf("unexpected sign response: %+v", resp)
	}
}

func TestEthereumSignDefaultsMissingMessageTypeToRaw(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	rawMessage := []byte("deploy-bytes")
	encodedMessage := base64.StdEncoding.EncodeToString(rawMessage)
	hasher := sha3.NewLegacyKeccak256()
	_, _ = hasher.Write(rawMessage)
	expectedHash := "0x" + hex.EncodeToString(hasher.Sum(nil))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/sign/"+providerKey):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["hash"] != expectedHash {
				t.Fatalf("unexpected sign body: %+v", body)
			}
			if _, ok := body["message"]; ok {
				t.Fatalf("expected missing MessageType to route through hash body, got %+v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"signature":"0xsigned","hash":"` + expectedHash + `","method":"` + ethereumSignMethodRawHash + `","address":"0xabc"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.Sign(context.Background(), &proto.SignRequest{
		KeyId:            testEthereumAlias,
		Message:          encodedMessage,
		SigningAlgorithm: signingAlgorithmEthereumSecp256k1,
		ClientId:         clientID,
	})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if resp.Signature != "0xsigned" || resp.KeyId != testEthereumKeyID {
		t.Fatalf("unexpected sign response: %+v", resp)
	}
}

func TestEthereumSignRawRejectsInvalidBase64(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
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
	if err == nil {
		t.Fatal("expected Sign to reject invalid RAW message")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
	if status.Convert(err).Message() != "ETHEREUM RAW messages must be base64-encoded bytes" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEthereumSignDigestNormalizesBase64Digest(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	digestBytes, err := hex.DecodeString("25f6c888f741660abd3e48fe2316b0c6095ea1aa9240d5324575d9fca9f2de45")
	if err != nil {
		t.Fatalf("hex.DecodeString() error = %v", err)
	}
	encodedDigest := base64.StdEncoding.EncodeToString(digestBytes)
	expectedHash := "0x" + hex.EncodeToString(digestBytes)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/sign/"+providerKey):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["hash"] != expectedHash {
				t.Fatalf("unexpected sign body: %+v", body)
			}
			if _, ok := body["message"]; ok {
				t.Fatalf("expected DIGEST signing to use hash body, got %+v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"signature":"0xsigned","hash":"` + expectedHash + `","method":"` + ethereumSignMethodRawHash + `","address":"0xabc"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.Sign(context.Background(), &proto.SignRequest{
		KeyId:            testEthereumAlias,
		Message:          encodedDigest,
		SigningAlgorithm: signingAlgorithmEthereumSecp256k1,
		MessageType:      stringPtr(messageTypeDigest),
		ClientId:         clientID,
	})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if resp.Signature != "0xsigned" || resp.KeyId != testEthereumKeyID {
		t.Fatalf("unexpected sign response: %+v", resp)
	}
}

func TestEthereumSignDigestAcceptsHexDigest(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	expectedHash := "0x25f6c888f741660abd3e48fe2316b0c6095ea1aa9240d5324575d9fca9f2de45"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/sign/"+providerKey):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["hash"] != expectedHash {
				t.Fatalf("unexpected sign body: %+v", body)
			}
			_, _ = w.Write([]byte(`{"data":{"signature":"0xsigned","hash":"` + expectedHash + `","method":"` + ethereumSignMethodRawHash + `","address":"0xabc"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.Sign(context.Background(), &proto.SignRequest{
		KeyId:            testEthereumAlias,
		Message:          expectedHash,
		SigningAlgorithm: signingAlgorithmEthereumSecp256k1,
		MessageType:      stringPtr(messageTypeDigest),
		ClientId:         clientID,
	})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if resp.Signature != "0xsigned" || resp.KeyId != testEthereumKeyID {
		t.Fatalf("unexpected sign response: %+v", resp)
	}
}

func TestEthereumSignDigestRejectsWrongLength(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
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
	if err == nil {
		t.Fatal("expected Sign to reject short DIGEST message")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
	if status.Convert(err).Message() != "ETHEREUM DIGEST messages must be exactly 32 bytes" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEthereumSignDigestRejectsUnexpectedBackendHash(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	digestBytes, err := hex.DecodeString("25f6c888f741660abd3e48fe2316b0c6095ea1aa9240d5324575d9fca9f2de45")
	if err != nil {
		t.Fatalf("hex.DecodeString() error = %v", err)
	}
	encodedDigest := base64.StdEncoding.EncodeToString(digestBytes)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/sign/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"signature":"0xsigned","hash":"0xdeadbeef","method":"` + ethereumSignMethodRawHash + `","address":"0xabc"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
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
	if err == nil {
		t.Fatal("expected Sign to reject mismatched backend hash")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", status.Code(err))
	}
	if status.Convert(err).Message() != "ethereum signing response hash mismatch" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEthereumSignDigestRejectsUnexpectedBackendMethod(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	digestBytes, err := hex.DecodeString("25f6c888f741660abd3e48fe2316b0c6095ea1aa9240d5324575d9fca9f2de45")
	if err != nil {
		t.Fatalf("hex.DecodeString() error = %v", err)
	}
	encodedDigest := base64.StdEncoding.EncodeToString(digestBytes)
	expectedHash := "0x" + hex.EncodeToString(digestBytes)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/ethereum/sign/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"signature":"0xsigned","hash":"` + expectedHash + `","method":"eip191","address":"0xabc"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
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
	if err == nil {
		t.Fatal("expected Sign to reject mismatched backend method")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", status.Code(err))
	}
	if status.Convert(err).Message() != "ethereum signing response method mismatch" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncryptRejectsUnsupportedEthereumOperation(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
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
	if err == nil {
		t.Fatal("expected Encrypt to reject ethereum keys")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", status.Code(err))
	}
	if status.Convert(err).Message() != "ETHEREUM keys do not support encryption" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptRejectsUnsupportedEthereumOperation(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	ciphertextBlob, err := encodeCiphertextBlob(schemeEthereum, testEthereumKeyID, providerKey, "0xdeadbeef", encryptionAlgorithmAES256GCM96)
	if err != nil {
		t.Fatalf("encodeCiphertextBlob() error = %v", err)
	}

	_, err = plugin.Decrypt(context.Background(), &proto.DecryptRequest{
		CiphertextBlob: ciphertextBlob,
		ClientId:       clientID,
	})
	if err == nil {
		t.Fatal("expected Decrypt to reject ethereum keys")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", status.Code(err))
	}
	if status.Convert(err).Message() != "ETHEREUM keys do not support decryption" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRotateKeyRejectsUnsupportedEthereumOperation(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testEthereumAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testEthereumKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testEthereumKeyID + `","client_id":"client-a","alias":"` + testEthereumAlias + `","scheme":"ETHEREUM","provider_key":"` + providerKey + `","key_spec":"ECC_SECG_P256K1","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","public_key":"0xdef","address":"0xabc","tags":[]}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, EthereumMount: "ethereum", TransitMount: "transit", KVMount: "secret", TimeoutSecs: 10}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.RotateKey(context.Background(), &proto.RotateKeyRequest{
		KeyId:    testEthereumAlias,
		ClientId: clientID,
	})
	if err == nil {
		t.Fatal("expected RotateKey to reject ethereum keys")
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got %v", status.Code(err))
	}
	if status.Convert(err).Message() != "ETHEREUM key rotation is not implemented" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func stringPtr(value string) *string {
	return &value
}
