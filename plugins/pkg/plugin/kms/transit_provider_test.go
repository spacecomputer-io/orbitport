package kms

import (
	"context"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

func TestTransitProviderCreateKey(t *testing.T) {

	t.Run("happy path", func(t *testing.T) {

		//first create make the parameters for create key function
		keyid := "kms:test-key"
		now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
		ctx := context.Background()
		req := &proto.CreateKeyRequest{
			Description: "key used for transit provider unit test",
			KeySpec:     "AES_256_GCM96",
			KeyUsage:    "ENCRYPT_DECRYPT",
			ClientId:    "test-tenant",
			Alias:       "test-key",
		}

		//set up mocked openbao server
		fakeOpenBao := func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost:
				w.WriteHeader(http.StatusOK)
			case r.Method == http.MethodGet:
				_, _ = w.Write([]byte(`{"data":{"latest_version":1,"type":"aes256-gcm96","public_key":"test-public-key"}}`))
			default:
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				http.Error(w, "unexpected request", http.StatusInternalServerError)
			}

		}

		handler := http.HandlerFunc(fakeOpenBao)
		server := httptest.NewServer(handler)
		defer server.Close()

		//sets up the client to call the mock server
		cfg := &kmsConfig{
			OpenBaoProxyURL: server.URL,
		}
		client := newOpenBaoClient(cfg)
		provider := newTransitProvider(client)

		metadata, err := provider.CreateKey(ctx, req, keyid, now)
		require.NoError(t, err)
		require.NotNil(t, metadata)
		//check the indivdual parts of metadata
		require.Equal(t, keyid, metadata.KeyID)
		require.Equal(t, req.Alias, metadata.Alias)
		require.Equal(t, req.ClientId, metadata.ClientID)
		require.Equal(t, schemeTransit, metadata.Scheme)
		require.Equal(t, uint32(1), metadata.PrimaryVersion)
		require.Equal(t, "test-public-key", metadata.PublicKey)
	})
}

func TestTransitProviderEncrypt(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {

		ctx := context.Background()
		metadata := &keyMetadataRecord{
			KeyID:       "kms:test-key",
			Scheme:      schemeTransit,
			ProviderKey: "tenant-test_test-key",
			KeySpec:     "AES_256_GCM96",
			KeyUsage:    "ENCRYPT_DECRYPT",
		}

		req := &proto.EncryptRequest{
			//this is base64 for "test"
			Plaintext: "dGVzdA==",
		}

		//set up mocked openbao server again, but we only need to handle post this time
		fakeOpenBao := func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost:
				_, _ = w.Write([]byte(`{"data":{"ciphertext": "vault:v1:test-ciphertext"}}`))

			default:
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				http.Error(w, "unexpected request", http.StatusInternalServerError)
			}

		}

		handler := http.HandlerFunc(fakeOpenBao)
		server := httptest.NewServer(handler)
		defer server.Close()

		//sets up the client to call the mock server (like before)
		cfg := &kmsConfig{
			OpenBaoProxyURL: server.URL,
		}

		client := newOpenBaoClient(cfg)
		provider := &transitProvider{
			client: client,
		}

		response, err := provider.Encrypt(ctx, metadata, req)

		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, metadata.KeyID, response.KeyId)
		require.Equal(t, encryptionAlgorithmAES256GCM96, response.EncryptionAlgorithm)

		blob, err := decodeCiphertextBlob(response.CiphertextBlob)
		//validate the indivdual components of decoded ciphertext
		require.NoError(t, err)
		require.NotNil(t, blob)

		require.Equal(t, metadata.Scheme, blob.Scheme)
		require.Equal(t, metadata.KeyID, blob.KeyID)
		require.Equal(t, metadata.backendKey(), blob.backendKey())
		require.Equal(t, "vault:v1:test-ciphertext", blob.Ciphertext)
		require.Equal(t, encryptionAlgorithmAES256GCM96, blob.Algorithm)
	})
}
func TestTransitProviderSign(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ctx := context.Background()
		metadata := &keyMetadataRecord{
			KeyID:       "kms:test-key",
			Scheme:      schemeTransit,
			ProviderKey: "tenant-test_test-key",
			KeySpec:     keySpecECDSAP256,
			KeyUsage:    signVerifyUsage,
		}

		req := &proto.SignRequest{
			Message:          "dGVzdA==",
			SigningAlgorithm: "ECDSA_SHA_256",
		}

		fakeOpenBao := func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost:
				_, _ = w.Write([]byte(`{"data":{"signature":"vault:v1:test-signature"}}`))

			default:
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				http.Error(w, "unexpected request", http.StatusInternalServerError)
			}

		}

		handler := http.HandlerFunc(fakeOpenBao)
		server := httptest.NewServer(handler)
		defer server.Close()

		cfg := &kmsConfig{
			OpenBaoProxyURL: server.URL,
		}

		client := newOpenBaoClient(cfg)
		provider := &transitProvider{
			client: client,
		}
		response, err := provider.Sign(ctx, metadata, req)
		require.NoError(t, err)
		require.NotNil(t, response)

		require.Equal(t, "kms:test-key", response.KeyId)
		require.Equal(t, "vault:v1:test-signature", response.Signature)
		require.Equal(t, "ECDSA_SHA_256", response.SigningAlgorithm)
	})

}
