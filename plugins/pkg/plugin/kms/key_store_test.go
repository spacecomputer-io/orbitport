package kms

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testKeyStoreName              = "github/prod"
	testKeyStoreDefaultPolicyPath = "cedar/key_store_default.cedar"
)

func TestKeyStorePut_ValidRequest_StoresSecretInTenantPath(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)
	var body map[string]any

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/key-store/data/owners/"+owner+"/"+testKeyStoreName:
			if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&body)) {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			writeKeyStoreJSON(t, w, map[string]any{"data": map[string]any{"version": 2}})
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	plugin.now = func() time.Time { return time.Unix(1, 0).UTC() }

	resp, err := plugin.KeyStorePut(context.Background(), &proto.KeyStorePutRequest{
		ClientId:   clientID,
		Name:       testKeyStoreName,
		SecretJson: `{"api_key":"secret-value","metadata":{"env":"prod"}}`,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, testKeyStoreName, resp.Name)
	assert.Equal(t, uint32(2), resp.Version)

	data, ok := body["data"].(map[string]any)
	require.True(t, ok)
	secretJSON, ok := data["secret_json"].(string)
	require.True(t, ok)
	assert.Equal(t, `{"api_key":"secret-value","metadata":{"env":"prod"}}`, secretJSON)
	assert.NotContains(t, data, "secret")
	assert.Equal(t, owner, data["owner"])
	assert.Equal(t, testKeyStoreName, data["name"])
}

func TestKeyStorePut_HighPrecisionNumbers_PreservesJSONText(t *testing.T) {
	var body map[string]any

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&body)) {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		writeKeyStoreJSON(t, w, map[string]any{"data": map[string]any{"version": 1}})
	}))
	defer server.Close()

	secret := `{"max_wei":123456789012345678901234567890,"pi":3.14159265358979323846}`
	_, err := plugin.KeyStorePut(context.Background(), &proto.KeyStorePutRequest{
		ClientId:   "client-a",
		Name:       testKeyStoreName,
		SecretJson: secret,
	})
	require.NoError(t, err)
	data, ok := body["data"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, secret, data["secret_json"])
	assert.NotContains(t, data, "secret")
}

func TestKeyStorePut_BackendError_ReturnsGenericInternal(t *testing.T) {
	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "missing mount at http://openbao.internal/v1/key-store", http.StatusNotFound)
	}))
	defer server.Close()

	_, err := plugin.KeyStorePut(context.Background(), &proto.KeyStorePutRequest{
		ClientId:   "client-a",
		Name:       testKeyStoreName,
		SecretJson: `{}`,
	})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Equal(t, "key-store backend error", status.Convert(err).Message())
}

func TestKeyStoreGet_ExistingSecret_ReturnsSecret(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/key-store/data/owners/"+owner+"/"+testKeyStoreName:
			writeKeyStoreJSON(t, w, map[string]any{
				"data": map[string]any{
					"data": map[string]any{
						"name":        testKeyStoreName,
						"owner":       owner,
						"secret_json": `{"api_key":"secret-value"}`,
						"updated_at":  "2026-01-01T00:00:00Z",
					},
				},
			})
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreGet(context.Background(), &proto.KeyStoreGetRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, testKeyStoreName, resp.Name)
	assert.Equal(t, `{"api_key":"secret-value"}`, resp.SecretJson)
}

func TestKeyStoreGet_HighPrecisionNumbers_PreservesJSONText(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)
	secret := `{"max_wei":123456789012345678901234567890,"pi":3.14159265358979323846}`

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/key-store/data/owners/"+owner+"/"+testKeyStoreName:
			writeKeyStoreJSON(t, w, map[string]any{
				"data": map[string]any{
					"data": map[string]any{
						"name":        testKeyStoreName,
						"owner":       owner,
						"secret_json": secret,
					},
				},
			})
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreGet(context.Background(), &proto.KeyStoreGetRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, secret, resp.SecretJson)
}

func TestKeyStoreGet_ForbiddenBackendError_ReturnsGenericInternal(t *testing.T) {
	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "permission denied for /v1/key-store/data/owners/client-a", http.StatusForbidden)
	}))
	defer server.Close()

	_, err := plugin.KeyStoreGet(context.Background(), &proto.KeyStoreGetRequest{
		ClientId: "client-a",
		Name:     testKeyStoreName,
	})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Equal(t, "key-store backend error", status.Convert(err).Message())
}

func TestKeyStoreGet_WrongTenantPayload_ReturnsPermissionDenied(t *testing.T) {
	clientID := "client-a"

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeKeyStoreJSON(t, w, map[string]any{
				"data": map[string]any{
					"data": map[string]any{
						"name":        testKeyStoreName,
						"owner":       tenantNamespace("client-b"),
						"secret_json": `{"api_key":"secret-value"}`,
					},
				},
			})
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	_, err := plugin.KeyStoreGet(context.Background(), &proto.KeyStoreGetRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestKeyStoreGet_NullStoredSecretJSON_ReturnsPermissionDenied(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeKeyStoreRawJSON(t, w, `{"data":{"data":{"name":"`+testKeyStoreName+`","owner":"`+owner+`","secret_json":"null"}}}`)
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	_, err := plugin.KeyStoreGet(context.Background(), &proto.KeyStoreGetRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestKeyStoreList_NoPrefix_ReturnsSingleLevelTenantNamespace(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "LIST" && r.URL.Path == "/v1/key-store/metadata/owners/"+owner:
			writeKeyStoreJSON(t, w, map[string]any{"data": map[string]any{"keys": []string{"github/", "slack"}}})
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreList(context.Background(), &proto.KeyStoreListRequest{
		ClientId: clientID,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	want := []string{"github/", "slack"}
	assert.Equal(t, want, resp.Names)
}

func TestKeyStoreList_UnsafeOpenBaoKeys_SkipsUnsafeNames(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "LIST" && r.URL.Path == "/v1/key-store/metadata/owners/"+owner:
			writeKeyStoreJSON(t, w, map[string]any{
				"data": map[string]any{
					"keys": []string{"valid", "../", "bad/name", "github/", "also-valid", strings.Repeat("a", maxKeyStoreNameLen+1)},
				},
			})
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreList(context.Background(), &proto.KeyStoreListRequest{
		ClientId: clientID,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	want := []string{"also-valid", "github/", "valid"}
	assert.Equal(t, want, resp.Names)
}

func TestKeyStoreList_MissingNamespace_ReturnsEmpty(t *testing.T) {
	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no value found at /v1/key-store/metadata/owners/client-a", http.StatusNotFound)
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreList(context.Background(), &proto.KeyStoreListRequest{
		ClientId: "client-a",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Names)
}

func TestKeyStoreList_DeepPrefix_ReturnsPrefixedNames(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)
	deepPrefix := "a/b/c/d"

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "LIST" && r.URL.Path == "/v1/key-store/metadata/owners/"+owner+"/"+deepPrefix:
			writeKeyStoreJSON(t, w, map[string]any{"data": map[string]any{"keys": []string{"token", "ci/"}}})
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreList(context.Background(), &proto.KeyStoreListRequest{
		ClientId: clientID,
		Prefix:   stringPtr(deepPrefix),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	want := []string{"a/b/c/d/ci/", "a/b/c/d/token"}
	assert.Equal(t, want, resp.Names)
}

func TestKeyStoreList_ReturnedFolders_DoesNotRecurse(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "LIST" && r.URL.Path == "/v1/key-store/metadata/owners/"+owner:
			writeKeyStoreJSON(t, w, map[string]any{"data": map[string]any{"keys": []string{"a/", "root"}}})
		case r.Method == "LIST" && r.URL.Path == "/v1/key-store/metadata/owners/"+owner+"/a":
			assert.Fail(t, "list should not recurse into returned folders")
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreList(context.Background(), &proto.KeyStoreListRequest{
		ClientId: clientID,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	want := []string{"a/", "root"}
	assert.Equal(t, want, resp.Names)
}

func TestKeyStoreDelete_ExistingEntry_DeletesSecret(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)
	deleteCalled := false

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/key-store/metadata/owners/"+owner+"/"+testKeyStoreName:
			writeKeyStoreJSON(t, w, map[string]any{"data": map[string]any{"version": 1}})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/key-store/metadata/owners/"+owner+"/"+testKeyStoreName:
			deleteCalled = true
			writeKeyStoreJSON(t, w, map[string]any{})
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreDelete(context.Background(), &proto.KeyStoreDeleteRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, testKeyStoreName, resp.Name)
	assert.True(t, deleteCalled, "expected backend delete request")
}

func TestKeyStoreDelete_MissingEntry_ReturnsNotFound(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/key-store/metadata/owners/"+owner+"/"+testKeyStoreName:
			http.NotFound(w, r)
		case r.Method == http.MethodDelete:
			assert.Fail(t, "delete should not be called when metadata is missing")
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	_, err := plugin.KeyStoreDelete(context.Background(), &proto.KeyStoreDeleteRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestKeyStoreDelete_BackendDeleteFailsAfterExistenceCheck_ReturnsGenericInternal(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/key-store/metadata/owners/"+owner+"/"+testKeyStoreName:
			writeKeyStoreJSON(t, w, map[string]any{"data": map[string]any{"version": 1}})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/key-store/metadata/owners/"+owner+"/"+testKeyStoreName:
			http.NotFound(w, r)
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	_, err := plugin.KeyStoreDelete(context.Background(), &proto.KeyStoreDeleteRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Equal(t, "key-store backend error", status.Convert(err).Message())
}

func TestKeyStoreGet_TraversalWithPermissiveCedar_RejectsBeforeOpenBao(t *testing.T) {
	policyFile := writeTempKeyStorePolicy(t, `permit (
		principal,
		action,
		resource
	);`)

	plugin, server := newKeyStoreTestPluginWithPolicy(t, policyFile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Failf(t, "OpenBao should not be called for an unsafe key-store name", "%s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := plugin.KeyStoreGet(context.Background(), &proto.KeyStoreGetRequest{
		ClientId: "client-a",
		Name:     "../tenant_b/github/prod",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestKeyStorePathBuilder_Traversal_ReturnsError(t *testing.T) {
	cfg := &kmsConfig{
		OpenBaoProxyURL: "http://openbao",
		KeyStoreMount:   "key-store",
		TimeoutSecs:     10,
	}
	client := newOpenBaoClient(cfg)

	_, err := client.keyStoreDataPath("client-a", "../tenant_b/github/prod")
	assert.Error(t, err)
	_, err = client.keyStoreMetadataPath("client-a", "github/../prod")
	assert.Error(t, err)
}

func TestKeyStoreDataPath_DeepName_ReturnsTenantScopedPath(t *testing.T) {
	cfg := &kmsConfig{
		OpenBaoProxyURL: "http://openbao",
		KeyStoreMount:   "key-store",
		TimeoutSecs:     10,
	}
	client := newOpenBaoClient(cfg)

	got, err := client.keyStoreDataPath("client-a", "github/prod/ci/token")
	require.NoError(t, err)
	want := "http://openbao/v1/key-store/data/owners/" + tenantNamespace("client-a") + "/github/prod/ci/token"
	assert.Equal(t, want, got)
}

func TestKeyStoreDelete_CedarForbidOverridesOwnerPermit_ReturnsPermissionDenied(t *testing.T) {
	defaultPolicy, err := os.ReadFile(testKeyStoreDefaultPolicyPath)
	require.NoError(t, err)
	policyFile := writeTempKeyStorePolicy(t, string(defaultPolicy)+`

forbid (
		principal,
		action == Action::"kms_keystore.Delete",
		resource
	);`)

	plugin, server := newKeyStoreTestPluginWithPolicy(t, policyFile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err = plugin.KeyStoreDelete(context.Background(), &proto.KeyStoreDeleteRequest{
		ClientId: "client-a",
		Name:     testKeyStoreName,
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func newKeyStoreTestPlugin(t *testing.T, handler http.Handler) (*Plugin, *httptest.Server) {
	t.Helper()
	return newKeyStoreTestPluginWithPolicy(t, "", handler)
}

func newKeyStoreTestPluginWithPolicy(t *testing.T, policyPath string, handler http.Handler) (*Plugin, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	if policyPath == "" {
		policyPath = testKeyStoreDefaultPolicyPath
	}
	cfg := &kmsConfig{
		OpenBaoProxyURL:         server.URL,
		EthereumMount:           "ethereum",
		TransitMount:            "transit",
		KVMount:                 "secret",
		KeyStoreMount:           "key-store",
		KeyStoreCedarPolicyPath: policyPath,
		TimeoutSecs:             10,
	}
	return newPlugin(cfg, newOpenBaoClient(cfg)), server
}

func writeKeyStoreJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	assert.NoError(t, json.NewEncoder(w).Encode(value))
}

func writeKeyStoreRawJSON(t *testing.T, w http.ResponseWriter, value string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	_, err := w.Write([]byte(value))
	assert.NoError(t, err)
}

func writeTempKeyStorePolicy(t *testing.T, policy string) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "key-store-*.cedar")
	require.NoError(t, err)
	defer func() {
		_ = file.Close()
	}()
	_, err = file.WriteString(policy)
	require.NoError(t, err)
	return file.Name()
}
