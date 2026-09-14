package kms

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testKeyStoreName              = "github/prod"
	testKeyStoreDefaultPolicyPath = "cedar/key_store_default.cedar"
)

func TestKeyStorePutStoresSecretInTenantPath(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)
	var body map[string]any

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/key-store/data/owners/"+owner+"/"+testKeyStoreName:
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			writeKeyStoreJSON(t, w, map[string]any{"data": map[string]any{"version": 2}})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	plugin.now = func() time.Time { return time.Unix(1, 0).UTC() }

	resp, err := plugin.KeyStorePut(context.Background(), &proto.KeyStorePutRequest{
		ClientId:   clientID,
		Name:       testKeyStoreName,
		SecretJson: `{"api_key":"secret-value","metadata":{"env":"prod"}}`,
	})
	if err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	if resp.Name != testKeyStoreName || resp.Version != 2 {
		t.Fatalf("unexpected response: %+v", resp)
	}

	data, ok := body["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected KV v2 data wrapper, got %+v", body)
	}
	secretJSON, ok := data["secret_json"].(string)
	if !ok || secretJSON != `{"api_key":"secret-value","metadata":{"env":"prod"}}` {
		t.Fatalf("expected secret_json string in body, got %+v", data)
	}
	if _, ok := data["secret"]; ok {
		t.Fatalf("secret must not be stored as a nested object, got %+v", data)
	}
	if data["owner"] != owner || data["name"] != testKeyStoreName {
		t.Fatalf("expected tenant owner and name in body, got %+v", data)
	}
}

func TestKeyStorePutStoresSecretAsJSONText(t *testing.T) {
	var body map[string]any

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
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
	if err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	data, ok := body["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected KV v2 data wrapper, got %+v", body)
	}
	if data["secret_json"] != secret {
		t.Fatalf("expected exact JSON text in secret_json, got %+v", data["secret_json"])
	}
	if _, ok := data["secret"]; ok {
		t.Fatalf("secret must not be stored as a nested object, got %+v", data)
	}
}

func TestKeyStorePutBackendErrorIsGenericInternal(t *testing.T) {
	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "missing mount at http://openbao.internal/v1/key-store", http.StatusNotFound)
	}))
	defer server.Close()

	_, err := plugin.KeyStorePut(context.Background(), &proto.KeyStorePutRequest{
		ClientId:   "client-a",
		Name:       testKeyStoreName,
		SecretJson: `{}`,
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v (%v)", status.Code(err), err)
	}
	if got := status.Convert(err).Message(); got != "key-store backend error" {
		t.Fatalf("expected generic backend error, got %q", got)
	}
}

func TestKeyStoreGetReturnsSecret(t *testing.T) {
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
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreGet(context.Background(), &proto.KeyStoreGetRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if resp.Name != testKeyStoreName || resp.SecretJson != `{"api_key":"secret-value"}` {
		t.Fatalf("unexpected secret json: %s", resp.SecretJson)
	}
}

func TestKeyStoreGetReturnsSecretJSONTextUnchanged(t *testing.T) {
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
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreGet(context.Background(), &proto.KeyStoreGetRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if resp.SecretJson != secret {
		t.Fatalf("expected exact secret JSON text, got %s", resp.SecretJson)
	}
}

func TestKeyStoreGetForbiddenBackendErrorIsGenericInternal(t *testing.T) {
	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "permission denied for /v1/key-store/data/owners/client-a", http.StatusForbidden)
	}))
	defer server.Close()

	_, err := plugin.KeyStoreGet(context.Background(), &proto.KeyStoreGetRequest{
		ClientId: "client-a",
		Name:     testKeyStoreName,
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v (%v)", status.Code(err), err)
	}
	if got := status.Convert(err).Message(); got != "key-store backend error" {
		t.Fatalf("expected generic backend error, got %q", got)
	}
}

func TestKeyStoreGetRejectsWrongTenantPayload(t *testing.T) {
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
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := plugin.KeyStoreGet(context.Background(), &proto.KeyStoreGetRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v (%v)", status.Code(err), err)
	}
}

func TestKeyStoreGetRejectsNullStoredSecretJSON(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeKeyStoreRawJSON(t, w, `{"data":{"data":{"name":"`+testKeyStoreName+`","owner":"`+owner+`","secret_json":"null"}}}`)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := plugin.KeyStoreGet(context.Background(), &proto.KeyStoreGetRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v (%v)", status.Code(err), err)
	}
}

func TestKeyStoreListReturnsSingleLevelTenantNamespace(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "LIST" && r.URL.Path == "/v1/key-store/metadata/owners/"+owner:
			writeKeyStoreJSON(t, w, map[string]any{"data": map[string]any{"keys": []string{"github/", "slack"}}})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreList(context.Background(), &proto.KeyStoreListRequest{
		ClientId: clientID,
	})
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	want := []string{"github/", "slack"}
	if !reflect.DeepEqual(resp.Names, want) {
		t.Fatalf("got names %+v, want %+v", resp.Names, want)
	}
}

func TestKeyStoreListSkipsUnsafeOpenBaoKeys(t *testing.T) {
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
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreList(context.Background(), &proto.KeyStoreListRequest{
		ClientId: clientID,
	})
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	want := []string{"also-valid", "github/", "valid"}
	if !reflect.DeepEqual(resp.Names, want) {
		t.Fatalf("got names %+v, want %+v", resp.Names, want)
	}
}

func TestKeyStoreListReturnsEmptyWhenNamespaceMissing(t *testing.T) {
	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no value found at /v1/key-store/metadata/owners/client-a", http.StatusNotFound)
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreList(context.Background(), &proto.KeyStoreListRequest{
		ClientId: "client-a",
	})
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(resp.Names) != 0 {
		t.Fatalf("expected empty list, got %+v", resp.Names)
	}
}

func TestKeyStoreListAcceptsDeepPrefixWithSingleOpenBaoCall(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)
	deepPrefix := "a/b/c/d"

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "LIST" && r.URL.Path == "/v1/key-store/metadata/owners/"+owner+"/"+deepPrefix:
			writeKeyStoreJSON(t, w, map[string]any{"data": map[string]any{"keys": []string{"token", "ci/"}}})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreList(context.Background(), &proto.KeyStoreListRequest{
		ClientId: clientID,
		Prefix:   stringPtr(deepPrefix),
	})
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	want := []string{"a/b/c/d/ci/", "a/b/c/d/token"}
	if !reflect.DeepEqual(resp.Names, want) {
		t.Fatalf("got names %+v, want %+v", resp.Names, want)
	}
}

func TestKeyStoreListDoesNotRecurseIntoFolders(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "LIST" && r.URL.Path == "/v1/key-store/metadata/owners/"+owner:
			writeKeyStoreJSON(t, w, map[string]any{"data": map[string]any{"keys": []string{"a/", "root"}}})
		case r.Method == "LIST" && r.URL.Path == "/v1/key-store/metadata/owners/"+owner+"/a":
			t.Fatalf("list should not recurse into returned folders")
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreList(context.Background(), &proto.KeyStoreListRequest{
		ClientId: clientID,
	})
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	want := []string{"a/", "root"}
	if !reflect.DeepEqual(resp.Names, want) {
		t.Fatalf("got names %+v, want %+v", resp.Names, want)
	}
}

func TestKeyStoreDeleteRequiresExistingEntry(t *testing.T) {
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
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	resp, err := plugin.KeyStoreDelete(context.Background(), &proto.KeyStoreDeleteRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	if err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}
	if resp.Name != testKeyStoreName || !deleteCalled {
		t.Fatalf("expected delete success, resp=%+v deleteCalled=%v", resp, deleteCalled)
	}
}

func TestKeyStoreDeleteReturnsNotFoundWhenEntryMissing(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/key-store/metadata/owners/"+owner+"/"+testKeyStoreName:
			http.NotFound(w, r)
		case r.Method == http.MethodDelete:
			t.Fatalf("delete should not be called when metadata is missing")
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := plugin.KeyStoreDelete(context.Background(), &proto.KeyStoreDeleteRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v (%v)", status.Code(err), err)
	}
}

func TestKeyStoreDeleteReturnsInternalWhenDeleteFailsAfterExistenceCheck(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/key-store/metadata/owners/"+owner+"/"+testKeyStoreName:
			writeKeyStoreJSON(t, w, map[string]any{"data": map[string]any{"version": 1}})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/key-store/metadata/owners/"+owner+"/"+testKeyStoreName:
			http.NotFound(w, r)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := plugin.KeyStoreDelete(context.Background(), &proto.KeyStoreDeleteRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v (%v)", status.Code(err), err)
	}
	if got := status.Convert(err).Message(); got != "key-store backend error" {
		t.Fatalf("expected generic backend error, got %q", got)
	}
}

func TestKeyStoreRejectsTraversalBeforeOpenBaoWithPermissiveCedar(t *testing.T) {
	policyFile := writeTempKeyStorePolicy(t, `permit (
		principal,
		action,
		resource
	);`)

	plugin, server := newKeyStoreTestPluginWithPolicy(t, policyFile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("OpenBao should not be called for an unsafe key-store name: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	_, err := plugin.KeyStoreGet(context.Background(), &proto.KeyStoreGetRequest{
		ClientId: "client-a",
		Name:     "../tenant_b/github/prod",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v (%v)", status.Code(err), err)
	}
}

func TestKeyStorePathBuilderRejectsTraversal(t *testing.T) {
	cfg := &kmsConfig{
		OpenBaoProxyURL: "http://openbao",
		KeyStoreMount:   "key-store",
		TimeoutSecs:     10,
	}
	client := newOpenBaoClient(cfg)

	if _, err := client.keyStoreDataPath("client-a", "../tenant_b/github/prod"); err == nil {
		t.Fatal("expected key-store data path builder to reject traversal")
	}
	if _, err := client.keyStoreMetadataPath("client-a", "github/../prod"); err == nil {
		t.Fatal("expected key-store metadata path builder to reject traversal")
	}
}

func TestKeyStorePathBuilderAllowsDeepNames(t *testing.T) {
	cfg := &kmsConfig{
		OpenBaoProxyURL: "http://openbao",
		KeyStoreMount:   "key-store",
		TimeoutSecs:     10,
	}
	client := newOpenBaoClient(cfg)

	got, err := client.keyStoreDataPath("client-a", "github/prod/ci/token")
	if err != nil {
		t.Fatalf("expected deep key-store path to be allowed: %v", err)
	}
	want := "http://openbao/v1/key-store/data/owners/" + tenantNamespace("client-a") + "/github/prod/ci/token"
	if got != want {
		t.Fatalf("got path %q, want %q", got, want)
	}
}

func TestKeyStoreCedarForbidOverridesDefaultOwnerPermit(t *testing.T) {
	defaultPolicy, err := os.ReadFile(testKeyStoreDefaultPolicyPath)
	if err != nil {
		t.Fatalf("read default key-store policy: %v", err)
	}
	policyFile := writeTempKeyStorePolicy(t, string(defaultPolicy)+`

forbid (
		principal,
		action == Action::"kms_keystore.Delete",
		resource
	);`)

	plugin, server := newKeyStoreTestPluginWithPolicy(t, policyFile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	_, err = plugin.KeyStoreDelete(context.Background(), &proto.KeyStoreDeleteRequest{
		ClientId: "client-a",
		Name:     testKeyStoreName,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v (%v)", status.Code(err), err)
	}
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
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("write json: %v", err)
	}
}

func writeKeyStoreRawJSON(t *testing.T, w http.ResponseWriter, value string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(value)); err != nil {
		t.Fatalf("write raw json: %v", err)
	}
}

func writeTempKeyStorePolicy(t *testing.T, policy string) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "key-store-*.cedar")
	if err != nil {
		t.Fatalf("create temp policy: %v", err)
	}
	defer func() {
		_ = file.Close()
	}()
	if _, err := file.WriteString(policy); err != nil {
		t.Fatalf("write temp policy: %v", err)
	}
	return file.Name()
}
