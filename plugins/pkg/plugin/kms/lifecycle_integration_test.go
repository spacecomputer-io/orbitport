package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Run only against an isolated local dev-mode OpenBao, never a shared environment.
func TestTransitLifecycleOpenBaoIntegration(t *testing.T) {
	address := os.Getenv("ORBITPORT_TEST_OPENBAO_ADDR")
	if address == "" {
		t.Skip("set ORBITPORT_TEST_OPENBAO_ADDR for an isolated local OpenBao 2.5.1")
	}
	target, err := url.Parse(address)
	require.NoError(t, err)
	require.Equal(t, "http", target.Scheme)
	require.Contains(t, []string{"127.0.0.1", "localhost", "::1"}, target.Hostname())
	token := os.Getenv("ORBITPORT_TEST_OPENBAO_TOKEN")
	require.NotEmpty(t, token)
	client := &http.Client{Timeout: 5 * time.Second}
	request := func(method, path string, body any) int {
		raw, marshalErr := json.Marshal(body)
		require.NoError(t, marshalErr)
		req, reqErr := http.NewRequest(method, address+"/v1/"+path, bytes.NewReader(raw))
		require.NoError(t, reqErr)
		req.Header.Set("X-Vault-Token", token)
		req.Header.Set("Content-Type", "application/json")
		resp, callErr := client.Do(req)
		require.NoError(t, callErr)
		_, copyErr := io.Copy(io.Discard, resp.Body)
		require.NoError(t, copyErr)
		require.NoError(t, resp.Body.Close())
		return resp.StatusCode
	}
	prefix := "lifecycle-test-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	transit, kv := prefix+"-transit", prefix+"-kv"
	require.Equal(t, 204, request("POST", "sys/mounts/"+transit, map[string]any{"type": "transit"}))
	t.Cleanup(func() { require.Equal(t, 204, request("DELETE", "sys/mounts/"+transit, nil)) })
	require.Equal(t, 204, request("POST", "sys/mounts/"+kv, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}))
	t.Cleanup(func() { require.Equal(t, 204, request("DELETE", "sys/mounts/"+kv, nil)) })
	proxy := &httputil.ReverseProxy{Rewrite: func(req *httputil.ProxyRequest) {
		req.SetURL(target)
		req.Out.Header.Set("X-Vault-Token", token)
	}}
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)
	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, TransitMount: transit, KVMount: kv, DeletionSweepInterval: "0"}
	p := newPlugin(cfg, newOpenBaoClient(cfg))
	t.Cleanup(p.Close)
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	ctx := context.Background()
	create := func(alias string) *proto.CreateKeyResponse {
		created, createErr := p.CreateKey(ctx, &proto.CreateKeyRequest{
			ClientId: "integration-tenant", Alias: alias, KeySpec: "AES_256_GCM96", KeyUsage: encryptDecryptUsage,
		})
		require.NoError(t, createErr)
		return created
	}
	key := create("aes").KeyMetadata.KeyId
	encrypted, err := p.Encrypt(ctx, &proto.EncryptRequest{ClientId: "integration-tenant", KeyId: key, Plaintext: "aGVsbG8="})
	require.NoError(t, err)
	_, err = p.DisableKey(ctx, &proto.DisableKeyRequest{ClientId: "integration-tenant", KeyId: key})
	require.NoError(t, err)
	_, err = p.Decrypt(ctx, &proto.DecryptRequest{ClientId: "integration-tenant", CiphertextBlob: encrypted.CiphertextBlob})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = p.EnableKey(ctx, &proto.EnableKeyRequest{ClientId: "integration-tenant", KeyId: key})
	require.NoError(t, err)
	decrypted, err := p.Decrypt(ctx, &proto.DecryptRequest{ClientId: "integration-tenant", CiphertextBlob: encrypted.CiphertextBlob})
	require.NoError(t, err)
	require.Equal(t, "aGVsbG8=", decrypted.Plaintext)
	_, err = p.ScheduleKeyDeletion(ctx, &proto.ScheduleKeyDeletionRequest{ClientId: "integration-tenant", KeyId: key})
	require.NoError(t, err)
	_, err = p.CancelKeyDeletion(ctx, &proto.CancelKeyDeletionRequest{ClientId: "integration-tenant", KeyId: key})
	require.NoError(t, err)
	_, err = p.ScheduleKeyDeletion(ctx, &proto.ScheduleKeyDeletionRequest{ClientId: "integration-tenant", KeyId: key})
	require.NoError(t, err)
	now = now.Add(31 * 24 * time.Hour) // test clock only; no production deadline override
	p.sweepDeletedKeys(ctx)
	list, err := p.ListKeys(ctx, &proto.ListKeysRequest{ClientId: "integration-tenant"})
	require.NoError(t, err)
	require.Empty(t, list.KeyIds)
	_, err = p.GetKeyMetadata(ctx, &proto.GetKeyMetadataRequest{ClientId: "integration-tenant", KeyId: key})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	backend, err := scopedBackendKey("integration-tenant", "aes")
	require.NoError(t, err)
	require.Equal(t, 404, request("GET", transit+"/keys/"+backend, nil))
	_, err = p.CreateKey(ctx, &proto.CreateKeyRequest{ClientId: "integration-tenant", Alias: "aes"})
	require.Equal(t, codes.AlreadyExists, status.Code(err))
	signer, err := p.CreateKey(ctx, &proto.CreateKeyRequest{ClientId: "integration-tenant", Alias: "signer", KeySpec: "ECDSA_P256", KeyUsage: signVerifyUsage})
	require.NoError(t, err)
	_, err = p.DisableKey(ctx, &proto.DisableKeyRequest{ClientId: "integration-tenant", KeyId: signer.KeyMetadata.KeyId})
	require.NoError(t, err)
	public, err := p.GetPublicKey(ctx, &proto.GetPublicKeyRequest{ClientId: "integration-tenant", KeyId: signer.KeyMetadata.KeyId})
	require.NoError(t, err)
	require.NotEmpty(t, public.PublicKey)
	_, err = p.Sign(ctx, &proto.SignRequest{ClientId: "integration-tenant", KeyId: signer.KeyMetadata.KeyId, Message: "aGVsbG8=", SigningAlgorithm: "ECDSA_SHA_256"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}
