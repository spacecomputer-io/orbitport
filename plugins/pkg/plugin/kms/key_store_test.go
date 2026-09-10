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

const testKeyStoreName = "github/prod"

func TestKeyStoreImportStoresSecretInTenantPath(t *testing.T) {
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

	resp, err := plugin.Import(context.Background(), &proto.KeyStoreImportRequest{
		ClientId:   clientID,
		Name:       testKeyStoreName,
		SecretJson: `{"api_key":"secret-value","metadata":{"env":"prod"}}`,
	})
	if err != nil {
		t.Fatalf("Import returned error: %v", err)
	}
	if resp.Name != testKeyStoreName || resp.Version != 2 {
		t.Fatalf("unexpected response: %+v", resp)
	}

	data, ok := body["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected KV v2 data wrapper, got %+v", body)
	}
	secret, ok := data["secret"].(map[string]any)
	if !ok || secret["api_key"] != "secret-value" {
		t.Fatalf("expected secret object in body, got %+v", data)
	}
	if data["owner"] != owner || data["name"] != testKeyStoreName {
		t.Fatalf("expected tenant owner and name in body, got %+v", data)
	}
}

func TestKeyStoreExportReturnsWrapToken(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/key-store/data/owners/"+owner+"/"+testKeyStoreName:
			if got := r.Header.Get(wrapTTLHeader); got != "60s" {
				t.Fatalf("expected wrap header 60s, got %q", got)
			}
			writeKeyStoreJSON(t, w, map[string]any{
				"wrap_info": map[string]any{
					"token":         "wrap-token",
					"ttl":           60,
					"creation_time": "2026-01-01T00:00:00Z",
				},
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	resp, err := plugin.Export(context.Background(), &proto.KeyStoreExportRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	if err != nil {
		t.Fatalf("Export returned error: %v", err)
	}
	if resp.WrapToken != "wrap-token" || resp.TtlSeconds != 60 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.ExpiresAt != "2026-01-01T00:01:00Z" {
		t.Fatalf("unexpected expiry: %s", resp.ExpiresAt)
	}
}

func TestKeyStoreExportRejectsTTLAboveMax(t *testing.T) {
	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	ttl := uint32(301)
	_, err := plugin.Export(context.Background(), &proto.KeyStoreExportRequest{
		ClientId:       "client-a",
		Name:           testKeyStoreName,
		WrapTtlSeconds: &ttl,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v (%v)", status.Code(err), err)
	}
}

func TestKeyStoreUnwrapVerifiesCreationPath(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)
	lookupPath := "key-store/data/owners/" + owner + "/" + testKeyStoreName

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/wrapping/lookup":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode lookup body: %v", err)
			}
			if body["token"] != "wrap-token" {
				t.Fatalf("unexpected lookup token body: %+v", body)
			}
			writeKeyStoreJSON(t, w, map[string]any{
				"data": map[string]any{
					"creation_path": lookupPath,
					"creation_ttl":  60,
					"creation_time": "2026-01-01T00:00:00Z",
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/wrapping/unwrap":
			writeKeyStoreJSON(t, w, map[string]any{
				"data": map[string]any{
					"data": map[string]any{
						"name":       testKeyStoreName,
						"owner":      owner,
						"secret":     map[string]any{"api_key": "secret-value"},
						"updated_at": "2026-01-01T00:00:00Z",
					},
				},
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	resp, err := plugin.Unwrap(context.Background(), &proto.KeyStoreUnwrapRequest{
		ClientId:  clientID,
		Name:      testKeyStoreName,
		WrapToken: "wrap-token",
	})
	if err != nil {
		t.Fatalf("Unwrap returned error: %v", err)
	}
	if !strings.Contains(resp.SecretJson, `"api_key":"secret-value"`) {
		t.Fatalf("unexpected secret json: %s", resp.SecretJson)
	}
}

func TestKeyStoreUnwrapRejectsTokenForDifferentPath(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)
	unwrapCalled := false

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/wrapping/lookup":
			writeKeyStoreJSON(t, w, map[string]any{
				"data": map[string]any{
					"creation_path": "key-store/data/owners/" + owner + "/other/key",
					"creation_ttl":  60,
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/wrapping/unwrap":
			unwrapCalled = true
			t.Fatalf("unwrap should not be called after path mismatch")
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := plugin.Unwrap(context.Background(), &proto.KeyStoreUnwrapRequest{
		ClientId:  clientID,
		Name:      testKeyStoreName,
		WrapToken: "wrap-token",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v (%v)", status.Code(err), err)
	}
	if unwrapCalled {
		t.Fatal("unwrap was called")
	}
}

func TestKeyStoreListRecursesTenantNamespace(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "LIST" && r.URL.Path == "/v1/key-store/metadata/owners/"+owner:
			writeKeyStoreJSON(t, w, map[string]any{"data": map[string]any{"keys": []string{"github/", "slack"}}})
		case r.Method == "LIST" && r.URL.Path == "/v1/key-store/metadata/owners/"+owner+"/github":
			writeKeyStoreJSON(t, w, map[string]any{"data": map[string]any{"keys": []string{"prod", "dev"}}})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	resp, err := plugin.List(context.Background(), &proto.KeyStoreListRequest{
		ClientId: clientID,
	})
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	want := []string{"github/dev", "github/prod", "slack"}
	if !reflect.DeepEqual(resp.Names, want) {
		t.Fatalf("got names %+v, want %+v", resp.Names, want)
	}
}

func TestKeyStoreDeleteUsesMetadataPath(t *testing.T) {
	clientID := "client-a"
	owner := tenantNamespace(clientID)
	deleteCalled := false

	plugin, server := newKeyStoreTestPlugin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/key-store/metadata/owners/"+owner+"/"+testKeyStoreName:
			deleteCalled = true
			writeKeyStoreJSON(t, w, map[string]any{})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	resp, err := plugin.Delete(context.Background(), &proto.KeyStoreDeleteRequest{
		ClientId: clientID,
		Name:     testKeyStoreName,
	})
	if err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}
	if !resp.Deleted || !deleteCalled {
		t.Fatalf("expected delete success, resp=%+v deleteCalled=%v", resp, deleteCalled)
	}
}

func TestKeyStoreCedarForbidOverridesDefaultOwnerPermit(t *testing.T) {
	policyFile := writeTempKeyStorePolicy(t, `forbid (
		principal,
		action == Action::"kms.Delete",
		resource
	);`)

	plugin, server := newKeyStoreTestPluginWithPolicy(t, policyFile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	_, err := plugin.Delete(context.Background(), &proto.KeyStoreDeleteRequest{
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
	cfg := &kmsConfig{
		OpenBaoProxyURL:                 server.URL,
		EthereumMount:                   "ethereum",
		TransitMount:                    "transit",
		KVMount:                         "secret",
		KeyStoreMount:                   "key-store",
		KeyStoreWrapTTLSecs:             60,
		KeyStoreMaxWrapTTLSecs:          300,
		KeyStoreCedarPolicyPath:         policyPath,
		KeyStoreCedarDefaultOwnerPolicy: true,
		TimeoutSecs:                     10,
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
