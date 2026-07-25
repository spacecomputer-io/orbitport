package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestRunMigrationDryRunApplyAndRerun(t *testing.T) {
	clientID := "client-a"
	keyID := "kms:payments-main"
	legacyNamespace := tenantNamespaceForBytes(clientID, legacyNamespaceBytes)
	targetNamespace := tenantNamespace(clientID)
	providerKey := legacyNamespace + "_payments-main"

	fixture := newMetadataFixture(t, "secret", map[string]map[string]any{
		fixtureKey(legacyNamespace, keyID): {
			"key_id":          keyID,
			"client_id":       clientID,
			"alias":           "payments-main",
			"scheme":          defaultTransitScheme,
			"provider_key":    providerKey,
			"description":     "legacy key",
			"key_spec":        "AES_256_GCM96",
			"key_usage":       "ENCRYPT_DECRYPT",
			"enabled":         true,
			"primary_version": 3,
			"created_at":      "2024-01-01T00:00:00Z",
			"tags":            []any{},
		},
	})
	defer fixture.server.Close()

	var dryRunOut strings.Builder
	dryRunReport, err := runMigration(context.Background(), migrationConfig{
		OpenBaoProxyURL: fixture.server.URL,
		KVMount:         "secret",
		TimeoutSecs:     10,
	}, migrationOptions{
		Writer: &dryRunOut,
	})
	if err != nil {
		t.Fatalf("runMigration(dry-run) error = %v", err)
	}
	if dryRunReport.LegacyNamespaces != 1 || dryRunReport.RecordsScanned != 1 || dryRunReport.RecordsPlanned != 1 || dryRunReport.RecordsCopied != 0 || dryRunReport.RecordsSkipped != 0 {
		t.Fatalf("unexpected dry-run report: %+v", dryRunReport)
	}
	if strings.Contains(dryRunOut.String(), "copied ") {
		t.Fatalf("dry-run output should not report copies: %s", dryRunOut.String())
	}
	if _, ok := fixture.get(targetNamespace, keyID); ok {
		t.Fatal("dry-run should not write migrated metadata")
	}

	var applyOut strings.Builder
	applyReport, err := runMigration(context.Background(), migrationConfig{
		OpenBaoProxyURL: fixture.server.URL,
		KVMount:         "secret",
		TimeoutSecs:     10,
	}, migrationOptions{
		Apply:  true,
		Writer: &applyOut,
	})
	if err != nil {
		t.Fatalf("runMigration(apply) error = %v", err)
	}
	if applyReport.LegacyNamespaces != 1 || applyReport.RecordsScanned != 1 || applyReport.RecordsPlanned != 1 || applyReport.RecordsCopied != 1 || applyReport.RecordsSkipped != 0 {
		t.Fatalf("unexpected apply report: %+v", applyReport)
	}

	migrated, ok := fixture.get(targetNamespace, keyID)
	if !ok {
		t.Fatal("expected migrated metadata at target namespace")
	}
	if got := recordBackendKey(migrated); got != providerKey {
		t.Fatalf("expected provider_key %q to be preserved, got %q", providerKey, got)
	}

	var rerunOut strings.Builder
	rerunReport, err := runMigration(context.Background(), migrationConfig{
		OpenBaoProxyURL: fixture.server.URL,
		KVMount:         "secret",
		TimeoutSecs:     10,
	}, migrationOptions{
		Apply:  true,
		Writer: &rerunOut,
	})
	if err != nil {
		t.Fatalf("runMigration(rerun) error = %v", err)
	}
	if rerunReport.LegacyNamespaces != 1 || rerunReport.RecordsScanned != 1 || rerunReport.RecordsPlanned != 0 || rerunReport.RecordsCopied != 0 || rerunReport.RecordsSkipped != 1 {
		t.Fatalf("unexpected rerun report: %+v", rerunReport)
	}
	if !strings.Contains(rerunOut.String(), "already-migrated") {
		t.Fatalf("expected rerun to report already-migrated, got %s", rerunOut.String())
	}
}

func TestLegacyMetadataNamespacesFiltersForEightByteNamespaces(t *testing.T) {
	legacy := tenantNamespaceForBytes("client-a", legacyNamespaceBytes)
	current := tenantNamespace("client-a")
	got := legacyMetadataNamespaces([]string{
		legacy + "/",
		current + "/",
		"misc/",
		"",
	})

	if !slices.Equal(got, []string{legacy}) {
		t.Fatalf("unexpected legacy namespaces: %#v", got)
	}
}

type metadataFixture struct {
	kvMount string
	mu      sync.Mutex
	server  *httptest.Server
	store   map[string]map[string]any
	t       *testing.T
}

func newMetadataFixture(t *testing.T, kvMount string, initial map[string]map[string]any) *metadataFixture {
	fixture := &metadataFixture{
		kvMount: kvMount,
		store:   make(map[string]map[string]any, len(initial)),
		t:       t,
	}
	for key, value := range initial {
		fixture.store[key] = cloneRecord(value)
	}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.handle))
	return fixture
}

func (f *metadataFixture) get(namespace, keyID string) (map[string]any, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.store[fixtureKey(namespace, keyID)]
	return cloneRecord(record), ok
}

func (f *metadataFixture) handle(w http.ResponseWriter, r *http.Request) {
	root := "/v1/" + f.kvMount
	switch {
	case strings.HasPrefix(r.URL.Path, root+"/metadata/kms/metadata"):
		f.handleList(w, r, strings.TrimPrefix(r.URL.Path, root+"/metadata/kms/metadata"))
	case strings.HasPrefix(r.URL.Path, root+"/data/kms/metadata/"):
		f.handleData(w, r, strings.TrimPrefix(r.URL.Path, root+"/data/kms/metadata/"))
	default:
		f.t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	}
}

func (f *metadataFixture) handleList(w http.ResponseWriter, r *http.Request, suffix string) {
	if r.Method != "LIST" {
		f.t.Fatalf("unexpected list method %s", r.Method)
	}

	suffix = strings.TrimPrefix(suffix, "/")
	f.mu.Lock()
	defer f.mu.Unlock()

	var keys []string
	if suffix == "" {
		keys = f.listNamespaces()
	} else {
		keys = f.listKeyIDs(suffix)
	}
	if len(keys) == 0 {
		http.NotFound(w, r)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{
			"keys": keys,
		},
	})
}

func (f *metadataFixture) handleData(w http.ResponseWriter, r *http.Request, suffix string) {
	parts := strings.SplitN(suffix, "/", 2)
	if len(parts) != 2 {
		f.t.Fatalf("unexpected metadata path %s", r.URL.Path)
	}
	namespace := parts[0]
	keyID, err := url.PathUnescape(parts[1])
	if err != nil {
		f.t.Fatalf("PathUnescape() error = %v", err)
	}

	switch r.Method {
	case http.MethodGet:
		f.mu.Lock()
		record, ok := f.store[fixtureKey(namespace, keyID)]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data": record,
			},
		})
	case http.MethodPost:
		var payload struct {
			Data map[string]any `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			f.t.Fatalf("Decode() error = %v", err)
		}
		f.mu.Lock()
		f.store[fixtureKey(namespace, keyID)] = cloneRecord(payload.Data)
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	default:
		f.t.Fatalf("unexpected data method %s", r.Method)
	}
}

func (f *metadataFixture) listNamespaces() []string {
	namespaces := make([]string, 0)
	seen := make(map[string]struct{})
	for key := range f.store {
		namespace, _, found := strings.Cut(key, "\x00")
		if !found {
			continue
		}
		if _, ok := seen[namespace]; ok {
			continue
		}
		seen[namespace] = struct{}{}
		namespaces = append(namespaces, namespace+"/")
	}
	slices.Sort(namespaces)
	return namespaces
}

func (f *metadataFixture) listKeyIDs(namespace string) []string {
	keyIDs := make([]string, 0)
	for key := range f.store {
		recordNamespace, keyID, found := strings.Cut(key, "\x00")
		if !found || recordNamespace != namespace {
			continue
		}
		keyIDs = append(keyIDs, keyID)
	}
	slices.Sort(keyIDs)
	return keyIDs
}

func fixtureKey(namespace, keyID string) string {
	return namespace + "\x00" + keyID
}
