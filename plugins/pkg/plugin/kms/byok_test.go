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
	testBYOKAlias          = "imported-main"
	testBYOKKeyID          = "kms:imported-main"
	testWrappingAlias      = "target-wrap"
	testWrappingKeyID      = "kms:target-wrap"
	testWrappedKeyMaterial = "openbao-wrapped-key-material"
	testWrappingPublicKey  = "-----BEGIN PUBLIC KEY-----test-----END PUBLIC KEY-----"
)

func TestGetImportParametersReadsTransitWrappingKey(t *testing.T) {
	var sawWrappingKey bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/transit/wrapping_key"):
			sawWrappingKey = true
			_, _ = w.Write([]byte(`{"data":{"public_key":"` + testWrappingPublicKey + `"}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.GetImportParameters(context.Background(), &proto.GetImportParametersRequest{
		ClientId:     "client-a",
		KeySpec:      keySpecAES256GCM96,
		KeyUsage:     encryptDecryptUsage,
		HashFunction: stringPtr(hashFunctionSHA384),
	})
	if err != nil {
		t.Fatalf("GetImportParameters returned error: %v", err)
	}
	if !sawWrappingKey {
		t.Fatal("expected wrapping key endpoint to be called")
	}
	if resp.WrappingKey != testWrappingPublicKey {
		t.Fatalf("unexpected wrapping key: %q", resp.WrappingKey)
	}
	if resp.WrappingAlgorithm != transitImportWrappingAlgorithm {
		t.Fatalf("unexpected wrapping algorithm: %q", resp.WrappingAlgorithm)
	}
	if resp.HashFunction != hashFunctionSHA384 {
		t.Fatalf("unexpected hash function: %q", resp.HashFunction)
	}
	if resp.KeyMaterialFormat != keyMaterialFormatRaw {
		t.Fatalf("unexpected key material format: %q", resp.KeyMaterialFormat)
	}
}

func TestImportKeyMaterialStoresImportedMetadata(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testBYOKAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	var importBody map[string]any
	var kvBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey+"/import"):
			_ = json.NewDecoder(r.Body).Decode(&importBody)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"latest_version":1,"type":"aes256-gcm96"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			var kvBody map[string]any
			_ = json.NewDecoder(r.Body).Decode(&kvBody)
			kvBodies = append(kvBodies, kvBody)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))
	plugin.now = func() time.Time { return time.Unix(1, 0).UTC() }

	resp, err := plugin.ImportKeyMaterial(context.Background(), &proto.ImportKeyMaterialRequest{
		ClientId:     clientID,
		Alias:        testBYOKAlias,
		KeySpec:      keySpecAES256GCM96,
		KeyUsage:     encryptDecryptUsage,
		Ciphertext:   testWrappedKeyMaterial,
		Description:  "imported AES key",
		HashFunction: stringPtr(hashFunctionSHA256),
	})
	if err != nil {
		t.Fatalf("ImportKeyMaterial returned error: %v", err)
	}
	if importBody["type"] != "aes256-gcm96" || importBody["ciphertext"] != testWrappedKeyMaterial {
		t.Fatalf("unexpected import body: %+v", importBody)
	}
	if importBody["hash_function"] != hashFunctionSHA256 {
		t.Fatalf("unexpected hash function in body: %+v", importBody)
	}
	if importBody["exportable"] != true || importBody["allow_plaintext_backup"] != false || importBody["allow_rotation"] != false {
		t.Fatalf("expected exportable/non-plaintext/non-rotating import body: %+v", importBody)
	}
	if resp.KeyMetadata.GetOrigin() != metadataOriginImported || resp.KeyMetadata.GetPublicOnly() || !resp.KeyMetadata.GetExportable() {
		t.Fatalf("unexpected metadata response: %+v", resp.KeyMetadata)
	}
	if len(kvBodies) != 2 {
		t.Fatalf("expected pending and final metadata writes, got %d", len(kvBodies))
	}
	pendingData, ok := kvBodies[0]["data"].(map[string]any)
	if !ok || pendingData["enabled"] != false || pendingData["status"] != metadataStatusImportPending {
		t.Fatalf("expected pending import metadata, got %+v", kvBodies[0])
	}
	data, ok := kvBodies[1]["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected metadata body, got %+v", kvBodies[1])
	}
	if data["origin"] != metadataOriginImported || data["public_only"] == true || data["exportable"] != true || data["status"] != metadataStatusEnabled {
		t.Fatalf("expected imported metadata, got %+v", data)
	}
	if data["client_id"] != clientID || data["provider_key"] != providerKey {
		t.Fatalf("expected tenant-scoped metadata, got %+v", data)
	}
}

func TestImportKeyMaterialHonorsExplicitNonExportable(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testBYOKAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	var importBody map[string]any
	var finalMetadata map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey+"/import"):
			_ = json.NewDecoder(r.Body).Decode(&importBody)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"latest_version":1,"type":"aes256-gcm96"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			var kvBody map[string]any
			_ = json.NewDecoder(r.Body).Decode(&kvBody)
			finalMetadata, _ = kvBody["data"].(map[string]any)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))
	exportable := false

	resp, err := plugin.ImportKeyMaterial(context.Background(), &proto.ImportKeyMaterialRequest{
		ClientId:     clientID,
		Alias:        testBYOKAlias,
		KeySpec:      keySpecAES256GCM96,
		KeyUsage:     encryptDecryptUsage,
		Ciphertext:   testWrappedKeyMaterial,
		HashFunction: stringPtr(hashFunctionSHA256),
		Exportable:   &exportable,
	})
	if err != nil {
		t.Fatalf("ImportKeyMaterial returned error: %v", err)
	}
	if importBody["exportable"] != false {
		t.Fatalf("expected explicit non-exportable import body, got %+v", importBody)
	}
	if resp.KeyMetadata.GetExportable() {
		t.Fatalf("expected non-exportable response metadata, got %+v", resp.KeyMetadata)
	}
	if finalMetadata["exportable"] != false {
		t.Fatalf("expected non-exportable stored metadata, got %+v", finalMetadata)
	}
}

func TestImportKeyMaterialBackendBadRequestIsGenericInvalidArgument(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testBYOKAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	var pendingMetadataWritten bool
	var pendingMetadataDeleted bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			pendingMetadataWritten = true
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey+"/import"):
			http.Error(w, "invalid wrapped key for /v1/transit/keys/"+providerKey+"/import", http.StatusBadRequest)
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			pendingMetadataDeleted = true
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.ImportKeyMaterial(context.Background(), &proto.ImportKeyMaterialRequest{
		ClientId:     clientID,
		Alias:        testBYOKAlias,
		KeySpec:      keySpecAES256GCM96,
		KeyUsage:     encryptDecryptUsage,
		Ciphertext:   testWrappedKeyMaterial,
		HashFunction: stringPtr(hashFunctionSHA256),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v (%v)", status.Code(err), err)
	}
	if got := status.Convert(err).Message(); got != "invalid BYOK key material" {
		t.Fatalf("expected generic BYOK error, got %q", got)
	}
	if !pendingMetadataWritten || !pendingMetadataDeleted {
		t.Fatalf("expected pending metadata write and cleanup, wrote=%v deleted=%v", pendingMetadataWritten, pendingMetadataDeleted)
	}
}

func TestImportKeyMaterialMetadataFailureSoftDeletesTransitKey(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testBYOKAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	var metadataWrites int
	var deletionAllowed bool
	var transitDeleted bool
	var pendingMetadataDeleted bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			metadataWrites++
			if metadataWrites == 2 {
				http.Error(w, "metadata write failed for http://openbao.internal", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey+"/import"):
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"latest_version":1,"type":"aes256-gcm96"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey+"/config"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			deletionAllowed = body["deletion_allowed"] == true
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			transitDeleted = true
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			pendingMetadataDeleted = true
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.ImportKeyMaterial(context.Background(), &proto.ImportKeyMaterialRequest{
		ClientId:     clientID,
		Alias:        testBYOKAlias,
		KeySpec:      keySpecAES256GCM96,
		KeyUsage:     encryptDecryptUsage,
		Ciphertext:   testWrappedKeyMaterial,
		HashFunction: stringPtr(hashFunctionSHA256),
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v (%v)", status.Code(err), err)
	}
	if got := status.Convert(err).Message(); got != kmsBackendErrorMessage {
		t.Fatalf("expected generic backend error, got %q", got)
	}
	if metadataWrites != 2 || !deletionAllowed || !transitDeleted || !pendingMetadataDeleted {
		t.Fatalf("expected pending/final writes plus cleanup, writes=%d deletionAllowed=%v transitDeleted=%v metadataDeleted=%v", metadataWrites, deletionAllowed, transitDeleted, pendingMetadataDeleted)
	}
}

func TestImportKeyMaterialDuplicateCheckDoesNotDecodeMetadata(t *testing.T) {
	clientID := "client-a"
	var imported bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			_, _ = w.Write([]byte(`{not-json`))
		case r.Method == http.MethodPost:
			imported = true
			t.Fatalf("duplicate check should stop before import")
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err := plugin.ImportKeyMaterial(context.Background(), &proto.ImportKeyMaterialRequest{
		ClientId:     clientID,
		Alias:        testBYOKAlias,
		KeySpec:      keySpecAES256GCM96,
		KeyUsage:     encryptDecryptUsage,
		Ciphertext:   testWrappedKeyMaterial,
		HashFunction: stringPtr(hashFunctionSHA256),
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected AlreadyExists, got %v (%v)", status.Code(err), err)
	}
	if imported {
		t.Fatal("import should not have been called")
	}
}

func TestImportKeyMaterialVersionUpdatesMetadata(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testBYOKAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	var importVersionBody map[string]any
	var kvBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testBYOKKeyID + `","client_id":"` + clientID + `","alias":"` + testBYOKAlias + `","scheme":"TRANSIT","provider_key":"` + providerKey + `","key_spec":"AES_256_GCM96","key_usage":"ENCRYPT_DECRYPT","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","origin":"IMPORTED","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey+"/import_version"):
			_ = json.NewDecoder(r.Body).Decode(&importVersionBody)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"latest_version":2,"type":"aes256-gcm96"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			_ = json.NewDecoder(r.Body).Decode(&kvBody)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.ImportKeyMaterialVersion(context.Background(), &proto.ImportKeyMaterialVersionRequest{
		ClientId:     clientID,
		KeyId:        testBYOKAlias,
		Ciphertext:   testWrappedKeyMaterial,
		HashFunction: stringPtr(hashFunctionSHA512),
		Version:      uint32Ptr(2),
	})
	if err != nil {
		t.Fatalf("ImportKeyMaterialVersion returned error: %v", err)
	}
	if importVersionBody["ciphertext"] != testWrappedKeyMaterial || importVersionBody["hash_function"] != hashFunctionSHA512 {
		t.Fatalf("unexpected import-version body: %+v", importVersionBody)
	}
	if importVersionBody["version"].(float64) != 2 {
		t.Fatalf("unexpected version in body: %+v", importVersionBody)
	}
	if resp.KeyMetadata.PrimaryVersion != 2 {
		t.Fatalf("expected primary version 2, got %+v", resp.KeyMetadata)
	}
	data, ok := kvBody["data"].(map[string]any)
	if !ok || data["primary_version"].(float64) != 2 {
		t.Fatalf("expected updated metadata, got %+v", kvBody)
	}
}

func TestRegisterExportWrappingKeyStoresPublicOnlyMetadata(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testWrappingAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	var importBody map[string]any
	var kvBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testWrappingKeyID):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey+"/import"):
			_ = json.NewDecoder(r.Body).Decode(&importBody)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			_, _ = w.Write([]byte(`{"data":{"latest_version":1,"type":"rsa-4096","public_key":"` + testWrappingPublicKey + `"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testWrappingKeyID):
			_ = json.NewDecoder(r.Body).Decode(&kvBody)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.RegisterExportWrappingKey(context.Background(), &proto.RegisterExportWrappingKeyRequest{
		ClientId:    clientID,
		Alias:       testWrappingAlias,
		PublicKey:   testWrappingPublicKey,
		Description: "target KMS wrapping public key",
	})
	if err != nil {
		t.Fatalf("RegisterExportWrappingKey returned error: %v", err)
	}
	if importBody["type"] != "rsa-4096" || importBody["public_key"] != testWrappingPublicKey {
		t.Fatalf("unexpected public-key import body: %+v", importBody)
	}
	if resp.KeyMetadata.GetOrigin() != metadataOriginPublicOnly || !resp.KeyMetadata.GetPublicOnly() || resp.KeyMetadata.KeyUsage != keyUsageKeyWrap {
		t.Fatalf("unexpected wrapping metadata response: %+v", resp.KeyMetadata)
	}
	data, ok := kvBody["data"].(map[string]any)
	if !ok || data["origin"] != metadataOriginPublicOnly || data["public_only"] != true || data["key_usage"] != keyUsageKeyWrap {
		t.Fatalf("expected public-only metadata, got %+v", kvBody)
	}
}

func TestExportKeyMaterialUsesTransitByokExport(t *testing.T) {
	clientID := "client-a"
	sourceProviderKey, err := scopedBackendKey(clientID, testBYOKAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey(source) error = %v", err)
	}
	destinationProviderKey, err := scopedBackendKey(clientID, testWrappingAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey(destination) error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testBYOKKeyID + `","client_id":"` + clientID + `","alias":"` + testBYOKAlias + `","scheme":"TRANSIT","provider_key":"` + sourceProviderKey + `","key_spec":"AES_256_GCM96","key_usage":"ENCRYPT_DECRYPT","enabled":true,"primary_version":2,"created_at":"2024-01-01T00:00:00Z","origin":"IMPORTED","exportable":true,"tags":[]}}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testWrappingKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testWrappingKeyID + `","client_id":"` + clientID + `","alias":"` + testWrappingAlias + `","scheme":"TRANSIT","provider_key":"` + destinationProviderKey + `","key_spec":"RSA_4096","key_usage":"KEY_WRAP","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","origin":"PUBLIC_ONLY","public_only":true,"tags":[]}}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/transit/byok-export/"+destinationProviderKey+"/"+sourceProviderKey+"/2"):
			if r.URL.Query().Get("hash") != hashFunctionSHA512 {
				t.Fatalf("unexpected query: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"data":{"name":"` + sourceProviderKey + `","keys":{"2":"wrapped-v2"}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	resp, err := plugin.ExportKeyMaterial(context.Background(), &proto.ExportKeyMaterialRequest{
		ClientId:         clientID,
		KeyId:            testBYOKAlias,
		DestinationKeyId: testWrappingAlias,
		Version:          uint32Ptr(2),
		HashFunction:     stringPtr(hashFunctionSHA512),
	})
	if err != nil {
		t.Fatalf("ExportKeyMaterial returned error: %v", err)
	}
	if resp.KeyId != testBYOKKeyID || resp.DestinationKeyId != testWrappingKeyID {
		t.Fatalf("unexpected export response ids: %+v", resp)
	}
	if resp.HashFunction != hashFunctionSHA512 || resp.WrappedKeyMaterialByVersion["2"] != "wrapped-v2" {
		t.Fatalf("unexpected export response: %+v", resp)
	}
}

func TestExportKeyMaterialRejectsNonExportableSource(t *testing.T) {
	clientID := "client-a"
	sourceProviderKey, err := scopedBackendKey(clientID, testBYOKAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey(source) error = %v", err)
	}
	destinationProviderKey, err := scopedBackendKey(clientID, testWrappingAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey(destination) error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testBYOKKeyID + `","client_id":"` + clientID + `","alias":"` + testBYOKAlias + `","scheme":"TRANSIT","provider_key":"` + sourceProviderKey + `","key_spec":"AES_256_GCM96","key_usage":"ENCRYPT_DECRYPT","enabled":true,"primary_version":2,"created_at":"2024-01-01T00:00:00Z","origin":"IMPORTED","exportable":false,"tags":[]}}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testWrappingKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testWrappingKeyID + `","client_id":"` + clientID + `","alias":"` + testWrappingAlias + `","scheme":"TRANSIT","provider_key":"` + destinationProviderKey + `","key_spec":"RSA_4096","key_usage":"KEY_WRAP","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","origin":"PUBLIC_ONLY","public_only":true,"tags":[]}}}`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/v1/transit/byok-export/"):
			t.Fatalf("byok-export should not be called for non-exportable source")
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.ExportKeyMaterial(context.Background(), &proto.ExportKeyMaterialRequest{
		ClientId:         clientID,
		KeyId:            testBYOKAlias,
		DestinationKeyId: testWrappingAlias,
		HashFunction:     stringPtr(hashFunctionSHA256),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v (%v)", status.Code(err), err)
	}
	if !strings.Contains(status.Convert(err).Message(), "non-exportable") {
		t.Fatalf("expected non-exportable error, got %q", status.Convert(err).Message())
	}
}

func TestExportKeyMaterialBackendErrorIsGenericInternal(t *testing.T) {
	clientID := "client-a"
	sourceProviderKey, err := scopedBackendKey(clientID, testBYOKAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey(source) error = %v", err)
	}
	destinationProviderKey, err := scopedBackendKey(clientID, testWrappingAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey(destination) error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testBYOKKeyID + `","client_id":"` + clientID + `","alias":"` + testBYOKAlias + `","scheme":"TRANSIT","provider_key":"` + sourceProviderKey + `","key_spec":"AES_256_GCM96","key_usage":"ENCRYPT_DECRYPT","enabled":true,"primary_version":2,"created_at":"2024-01-01T00:00:00Z","origin":"IMPORTED","exportable":true,"tags":[]}}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testWrappingKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testWrappingKeyID + `","client_id":"` + clientID + `","alias":"` + testWrappingAlias + `","scheme":"TRANSIT","provider_key":"` + destinationProviderKey + `","key_spec":"RSA_4096","key_usage":"KEY_WRAP","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","origin":"PUBLIC_ONLY","public_only":true,"tags":[]}}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/transit/byok-export/"+destinationProviderKey+"/"+sourceProviderKey):
			http.Error(w, "permission denied for http://openbao.internal/v1/transit/byok-export", http.StatusForbidden)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.ExportKeyMaterial(context.Background(), &proto.ExportKeyMaterialRequest{
		ClientId:         clientID,
		KeyId:            testBYOKAlias,
		DestinationKeyId: testWrappingAlias,
		HashFunction:     stringPtr(hashFunctionSHA256),
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v (%v)", status.Code(err), err)
	}
	if got := status.Convert(err).Message(); got != kmsBackendErrorMessage {
		t.Fatalf("expected generic backend error, got %q", got)
	}
}

func TestDeleteKeyHardDeletesTransitKeyAndMarksMetadata(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testBYOKAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	var deletionAllowed bool
	var deleted bool
	var kvBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testBYOKKeyID + `","client_id":"` + clientID + `","alias":"` + testBYOKAlias + `","scheme":"TRANSIT","provider_key":"` + providerKey + `","key_spec":"AES_256_GCM96","key_usage":"ENCRYPT_DECRYPT","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","origin":"IMPORTED","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey+"/config"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			deletionAllowed = body["deletion_allowed"] == true
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			deleted = true
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			var kvBody map[string]any
			_ = json.NewDecoder(r.Body).Decode(&kvBody)
			kvBodies = append(kvBodies, kvBody)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))
	plugin.now = func() time.Time { return time.Unix(2, 0).UTC() }

	resp, err := plugin.DeleteKey(context.Background(), &proto.DeleteKeyRequest{
		ClientId: clientID,
		KeyId:    testBYOKAlias,
	})
	if err != nil {
		t.Fatalf("DeleteKey returned error: %v", err)
	}
	if resp.KeyId != testBYOKKeyID {
		t.Fatalf("unexpected delete response: %+v", resp)
	}
	if !deletionAllowed {
		t.Fatal("expected OpenBao deletion_allowed config endpoint to be called")
	}
	if !deleted {
		t.Fatal("expected OpenBao hard-delete endpoint to be called")
	}
	if len(kvBodies) != 2 {
		t.Fatalf("expected pending-delete and final metadata writes, got %d", len(kvBodies))
	}
	pendingData, ok := kvBodies[0]["data"].(map[string]any)
	if !ok || pendingData["enabled"] != false || pendingData["status"] != metadataStatusDeletePending || pendingData["deleted_at"] != nil {
		t.Fatalf("expected pending-delete metadata, got %+v", kvBodies[0])
	}
	data, ok := kvBodies[1]["data"].(map[string]any)
	if !ok || data["enabled"] != false || data["status"] != metadataStatusDeleted || data["deleted_at"] == "" {
		t.Fatalf("expected deleted metadata with deleted_at, got %+v", kvBodies[1])
	}
}

func TestDeleteKeyBackendFailureLeavesMetadataDeletePending(t *testing.T) {
	clientID := "client-a"
	providerKey, err := scopedBackendKey(clientID, testBYOKAlias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}

	var pendingBody map[string]any
	var finalMetadataWritten bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + testBYOKKeyID + `","client_id":"` + clientID + `","alias":"` + testBYOKAlias + `","scheme":"TRANSIT","provider_key":"` + providerKey + `","key_spec":"AES_256_GCM96","key_usage":"ENCRYPT_DECRYPT","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","origin":"IMPORTED","status":"ENABLED","tags":[]}}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+testBYOKKeyID):
			if pendingBody != nil {
				finalMetadataWritten = true
			}
			_ = json.NewDecoder(r.Body).Decode(&pendingBody)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey+"/config"):
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/v1/transit/keys/"+providerKey):
			http.Error(w, "backend delete failed for http://openbao.internal", http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.DeleteKey(context.Background(), &proto.DeleteKeyRequest{
		ClientId: clientID,
		KeyId:    testBYOKAlias,
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v (%v)", status.Code(err), err)
	}
	if got := status.Convert(err).Message(); got != kmsBackendErrorMessage {
		t.Fatalf("expected generic backend error, got %q", got)
	}
	data, ok := pendingBody["data"].(map[string]any)
	if !ok || data["enabled"] != false || data["status"] != metadataStatusDeletePending {
		t.Fatalf("expected fail-closed pending-delete metadata, got %+v", pendingBody)
	}
	if finalMetadataWritten {
		t.Fatal("final deleted metadata should not be written when backend delete fails")
	}
}

func TestExportKeyMaterialRejectsWrongTenant(t *testing.T) {
	requestClientID := "client-b"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(requestClientID)+"/"+testBYOKKeyID):
			http.NotFound(w, r)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err := plugin.ExportKeyMaterial(context.Background(), &proto.ExportKeyMaterialRequest{
		ClientId:         requestClientID,
		KeyId:            testBYOKAlias,
		DestinationKeyId: testWrappingAlias,
	})
	if err == nil {
		t.Fatal("expected ExportKeyMaterial to reject wrong tenant")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", status.Code(err))
	}
}

func TestDecryptRejectsImportedSigningKeyBeforeOpenBao(t *testing.T) {
	clientID := "client-a"
	alias := "imported-signer"
	keyID := "kms:" + alias
	providerKey, err := scopedBackendKey(clientID, alias)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}
	ciphertextBlob, err := encodeCiphertextBlob(schemeTransit, keyID, providerKey, "vault:v1:ciphertext", encryptionAlgorithmAES256GCM96)
	if err != nil {
		t.Fatalf("encodeCiphertextBlob() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/secret/data/kms/metadata/"+tenantNamespace(clientID)+"/"+keyID):
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"` + keyID + `","client_id":"` + clientID + `","alias":"` + alias + `","scheme":"TRANSIT","provider_key":"` + providerKey + `","key_spec":"ECDSA_P256","key_usage":"SIGN_VERIFY","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","origin":"IMPORTED","tags":[]}}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err = plugin.Decrypt(context.Background(), &proto.DecryptRequest{
		ClientId:       clientID,
		CiphertextBlob: ciphertextBlob,
	})
	if err == nil {
		t.Fatal("expected Decrypt to reject imported signing key")
	}
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "key does not support encryption") {
		t.Fatalf("expected key-usage FailedPrecondition, got %v", err)
	}
}

func TestImportKeyMaterialRequiresPATImportScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	cfg := &kmsConfig{OpenBaoProxyURL: server.URL}
	plugin := newPlugin(cfg, newOpenBaoClient(cfg))

	_, err := plugin.ImportKeyMaterial(context.Background(), &proto.ImportKeyMaterialRequest{
		ClientId:     "client-a",
		Alias:        testBYOKAlias,
		KeySpec:      keySpecAES256GCM96,
		KeyUsage:     encryptDecryptUsage,
		Ciphertext:   testWrappedKeyMaterial,
		AuthzContext: &proto.AuthzContext{IsPat: true, CredentialId: "pat-1"},
	})
	if err == nil {
		t.Fatal("expected ImportKeyMaterial to reject missing PAT scope")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", status.Code(err))
	}
}

func TestKMSDefaultCedarPolicyAllowsScopedPAT(t *testing.T) {
	authorizer, err := newKMSAuthorizer(&kmsConfig{CedarPolicyPath: "cedar/kms_default.cedar"})
	if err != nil {
		t.Fatalf("newKMSAuthorizer returned error: %v", err)
	}

	err = authorizer.authorize("client-a", &proto.AuthzContext{
		IsPat:        true,
		CredentialId: "pat-1",
		Scopes:       []string{"kms:import"},
	}, kmsActionImportKeyMaterial, kmsPolicyResource{
		KeyID:    testBYOKKeyID,
		Alias:    testBYOKAlias,
		Scheme:   schemeTransit,
		KeySpec:  keySpecAES256GCM96,
		KeyUsage: encryptDecryptUsage,
		Origin:   metadataOriginImported,
	})
	if err != nil {
		t.Fatalf("expected scoped PAT to be allowed: %v", err)
	}
}

func uint32Ptr(value uint32) *uint32 {
	return &value
}
