package kms

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type lifecycleKV struct {
	record  json.RawMessage
	version uint64
}

type lifecycleFixture struct {
	mu        sync.Mutex
	kv        map[string]lifecycleKV
	material  map[string]bool
	allowed   map[string]bool
	versions  map[string]uint32
	requests  []string
	fail      string
	beforeCAS func(string)
}

func newLifecycleFixture(t *testing.T) (*Plugin, *lifecycleFixture) {
	t.Helper()
	return newLifecycleFixtureWithConfig(t, nil)
}

func newLifecycleFixtureWithConfig(t *testing.T, cfg *kmsConfig) (*Plugin, *lifecycleFixture) {
	t.Helper()
	fixture := &lifecycleFixture{kv: map[string]lifecycleKV{}, material: map[string]bool{}, allowed: map[string]bool{}, versions: map[string]uint32{}}
	server := httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(server.Close)
	cfg = withKMSConfigDefaults(cfg)
	cfg.OpenBaoProxyURL = server.URL
	cfg.DeletionSweepInterval = "0"
	p := newPlugin(cfg, newOpenBaoClient(cfg))
	p.now = func() time.Time { return time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(p.Close)
	return p, fixture
}

func (f *lifecycleFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	request := r.Method + " " + path
	f.requests = append(f.requests, request)
	if f.fail == request {
		http.Error(w, "private-backend-host/internal/path", http.StatusForbidden)
		return
	}
	dataPrefix := "/v1/secret/data/"
	metaPrefix := "/v1/secret/metadata/"
	writeJSON := func(value any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	}
	switch {
	case strings.HasPrefix(path, dataPrefix) && r.Method == http.MethodGet:
		entry, ok := f.kv[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(map[string]any{"data": map[string]any{"data": entry.record, "metadata": map[string]uint64{"version": entry.version}}})
	case strings.HasPrefix(path, dataPrefix) && r.Method == http.MethodPost:
		var body struct {
			Data    json.RawMessage `json:"data"`
			Options struct {
				CAS *uint64 `json:"cas"`
			} `json:"options"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if f.beforeCAS != nil {
			f.beforeCAS(path)
		}
		current := f.kv[path]
		if body.Options.CAS != nil && *body.Options.CAS != current.version {
			http.Error(w, "check-and-set parameter did not match the current version", http.StatusBadRequest)
			return
		}
		f.kv[path] = lifecycleKV{record: body.Data, version: current.version + 1}
		writeJSON(map[string]any{"data": map[string]uint64{"version": current.version + 1}})
	case strings.HasPrefix(path, metaPrefix) && r.Method == "LIST":
		prefix := dataPrefix + strings.TrimPrefix(path, metaPrefix) + "/"
		found := map[string]bool{}
		for key := range f.kv {
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			name := strings.TrimPrefix(key, prefix)
			if slash := strings.IndexByte(name, '/'); slash >= 0 {
				name = name[:slash+1]
			}
			found[name] = true
		}
		if len(found) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		keys := make([]string, 0, len(found))
		for key := range found {
			keys = append(keys, key)
		}
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
		writeJSON(map[string]any{"data": map[string]any{"keys": keys}})
	case strings.HasPrefix(path, metaPrefix) && r.Method == http.MethodDelete:
		delete(f.kv, dataPrefix+strings.TrimPrefix(path, metaPrefix))
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(path, "/v1/transit/keys/"):
		key := strings.TrimPrefix(path, "/v1/transit/keys/")
		if r.Method == http.MethodGet {
			if !f.material[key] {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			version := f.versions[key]
			if version == 0 {
				version = 1
			}
			writeJSON(map[string]any{"data": map[string]any{"latest_version": version}})
		} else if r.Method == http.MethodPost && strings.HasSuffix(key, "/rotate") {
			key = strings.TrimSuffix(key, "/rotate")
			f.versions[key] = 2
			writeJSON(map[string]any{})
		} else if r.Method == http.MethodPost && strings.HasSuffix(key, "/config") {
			f.allowed[strings.TrimSuffix(key, "/config")] = true
			writeJSON(map[string]any{})
		} else if r.Method == http.MethodDelete && f.allowed[key] {
			delete(f.material, key)
			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, "unexpected Transit request", http.StatusBadRequest)
		}
	default:
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}
}

func (f *lifecycleFixture) add(t *testing.T, clientID, alias, scheme string) *keyMetadataRecord {
	t.Helper()
	backend, err := scopedBackendKey(clientID, alias)
	require.NoError(t, err)
	record := &keyMetadataRecord{KeyID: "kms:" + alias, ClientID: clientID, Alias: alias, Scheme: scheme,
		ProviderKey: backend, Enabled: true, KeySpec: "AES_256_GCM96", KeyUsage: encryptDecryptUsage, PrimaryVersion: 1}
	f.save(t, record)
	f.material[backend] = true
	return record
}

func (f *lifecycleFixture) save(t *testing.T, record *keyMetadataRecord) {
	t.Helper()
	raw, err := json.Marshal(record)
	require.NoError(t, err)
	path := "/v1/secret/data/kms/metadata/" + tenantNamespace(record.ClientID) + "/" + record.KeyID
	current := f.kv[path]
	f.kv[path] = lifecycleKV{record: raw, version: current.version + 1}
}

func TestListKeysTenantPagingUsesExactlyOneList(t *testing.T) {
	p, f := newLifecycleFixture(t)
	for i := 0; i < 102; i++ {
		scheme := []string{schemeTransit, schemeEthereum, schemePQC}[i%3]
		f.add(t, "a", fmt.Sprintf("key-%03d", i), scheme)
	}
	f.add(t, "b", "foreign", schemeTransit)
	f.kv["/v1/secret/data/kms/metadata/"+tenantNamespace("a")+"/unsafe/key"] = lifecycleKV{}
	first, err := p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: "a"})
	require.NoError(t, err)
	require.Len(t, first.KeyIds, 100)
	require.Equal(t, "kms:key-000", first.KeyIds[0])
	require.NotNil(t, first.NextToken)
	require.Equal(t, []string{"LIST /v1/secret/metadata/kms/metadata/" + tenantNamespace("a")}, f.requests)
	second, err := p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: "a", NextToken: first.NextToken})
	require.NoError(t, err)
	require.Equal(t, []string{"kms:key-100", "kms:key-101"}, second.KeyIds)
	require.Nil(t, second.NextToken)
	empty, err := p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: "empty"})
	require.NoError(t, err)
	require.Empty(t, empty.KeyIds)
	// A cursor from another tenant never changes the lookup namespace.
	other, err := p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: "b", NextToken: first.NextToken})
	require.NoError(t, err)
	require.NotContains(t, other.KeyIds, "kms:key-100")
}

func TestListKeysRejectsInvalidInputWithoutBackendCalls(t *testing.T) {
	p, f := newLifecycleFixture(t)
	for _, limit := range []uint32{0, 1001} {
		_, err := p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: "a", Limit: &limit})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}
	for _, token := range []string{"", "bad", strings.Repeat("x", 513), "eyJ2IjoxLCJhZnRlciI6Ii4uLyJ9"} {
		_, err := p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: "a", NextToken: &token})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}
	require.Empty(t, f.requests)
}

func TestListKeysConfiguredDefaultsAndMaximum(t *testing.T) {
	p, f := newLifecycleFixtureWithConfig(t, &kmsConfig{ListKeysDefaultLimit: 2, ListKeysMaxLimit: 3})
	for i := 0; i < 5; i++ {
		f.add(t, "a", fmt.Sprintf("key-%d", i), schemeTransit)
	}
	first, err := p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: "a"})
	require.NoError(t, err)
	require.Equal(t, []string{"kms:key-0", "kms:key-1"}, first.KeyIds)
	require.NotNil(t, first.NextToken)
	require.Len(t, f.requests, 1)

	limit := uint32(3)
	second, err := p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: "a", Limit: &limit, NextToken: first.NextToken})
	require.NoError(t, err)
	require.Equal(t, []string{"kms:key-2", "kms:key-3", "kms:key-4"}, second.KeyIds)
	require.Nil(t, second.NextToken)
	require.Len(t, f.requests, 2)

	limit = 4
	_, err = p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: "a", Limit: &limit})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(t, "Limit must be between 1 and 3", status.Convert(err).Message())
	require.Len(t, f.requests, 2)

	limit = 1
	page, err := p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: "a", Limit: &limit})
	require.NoError(t, err)
	require.Equal(t, []string{"kms:key-0"}, page.KeyIds)
	require.Len(t, f.requests, 3)
}

func TestScheduleKeyDeletionConfiguredDefaultAndOverride(t *testing.T) {
	p, f := newLifecycleFixtureWithConfig(t, &kmsConfig{DefaultDeletionWindowDays: 14})
	first := f.add(t, "a", "configured-default", schemeTransit)
	scheduled, err := p.ScheduleKeyDeletion(context.Background(), &proto.ScheduleKeyDeletionRequest{ClientId: "a", KeyId: first.KeyID})
	require.NoError(t, err)
	require.Equal(t, uint32(14), scheduled.PendingWindowInDays)
	require.Equal(t, "2026-11-25T12:00:00Z", scheduled.KeyMetadata.GetDeletionDate())

	second := f.add(t, "a", "request-override", schemeTransit)
	window := uint32(7)
	scheduled, err = p.ScheduleKeyDeletion(context.Background(), &proto.ScheduleKeyDeletionRequest{ClientId: "a", KeyId: second.KeyID, PendingWindowInDays: &window})
	require.NoError(t, err)
	require.Equal(t, window, scheduled.PendingWindowInDays)
	require.Equal(t, "2026-11-18T12:00:00Z", scheduled.KeyMetadata.GetDeletionDate())
}

func TestTransitLifecycleAndLegacyState(t *testing.T) {
	p, f := newLifecycleFixture(t)
	record := f.add(t, "a", "key", schemeTransit) // no key_state in the legacy record
	disabled, err := p.DisableKey(context.Background(), &proto.DisableKeyRequest{ClientId: "a", KeyId: record.KeyID})
	require.NoError(t, err)
	require.Equal(t, keyStateDisabled, disabled.KeyMetadata.GetKeyState())
	require.False(t, disabled.KeyMetadata.Enabled)
	blob, err := encodeCiphertextBlob(schemeTransit, record.KeyID, record.ProviderKey, "vault:v1:fixture", encryptionAlgorithmAES256GCM96)
	require.NoError(t, err)
	_, err = p.Decrypt(context.Background(), &proto.DecryptRequest{ClientId: "a", CiphertextBlob: blob})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	foreign, err := encodeCiphertextBlob(schemeTransit, record.KeyID, "foreign-backend", "vault:v1:fixture", encryptionAlgorithmAES256GCM96)
	require.NoError(t, err)
	_, err = p.Decrypt(context.Background(), &proto.DecryptRequest{ClientId: "a", CiphertextBlob: foreign})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = p.Sign(context.Background(), &proto.SignRequest{ClientId: "a", KeyId: record.KeyID, Message: "aA==", SigningAlgorithm: "ECDSA_SHA_256"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = p.GenerateDataKey(context.Background(), &proto.GenerateDataKeyRequest{ClientId: "a", KeyId: record.KeyID})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	before := len(f.requests)
	_, err = p.DisableKey(context.Background(), &proto.DisableKeyRequest{ClientId: "a", KeyId: record.KeyID})
	require.NoError(t, err)
	require.Len(t, f.requests, before+1) // GET only, no redundant write
	_, err = p.Encrypt(context.Background(), &proto.EncryptRequest{ClientId: "a", KeyId: record.KeyID, Plaintext: "aGVsbG8="})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = p.RotateKey(context.Background(), &proto.RotateKeyRequest{ClientId: "a", KeyId: record.KeyID})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	enabled, err := p.EnableKey(context.Background(), &proto.EnableKeyRequest{ClientId: "a", KeyId: record.KeyID})
	require.NoError(t, err)
	require.True(t, enabled.KeyMetadata.Enabled)
	scheduled, err := p.ScheduleKeyDeletion(context.Background(), &proto.ScheduleKeyDeletionRequest{ClientId: "a", KeyId: record.KeyID})
	require.NoError(t, err)
	require.Equal(t, uint32(30), scheduled.PendingWindowInDays)
	require.Equal(t, "2026-12-11T12:00:00Z", scheduled.KeyMetadata.GetDeletionDate())
	_, err = p.EnableKey(context.Background(), &proto.EnableKeyRequest{ClientId: "a", KeyId: record.KeyID})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	cancelled, err := p.CancelKeyDeletion(context.Background(), &proto.CancelKeyDeletionRequest{ClientId: "a", KeyId: record.KeyID})
	require.NoError(t, err)
	require.Equal(t, keyStateDisabled, cancelled.KeyMetadata.GetKeyState())
	require.Nil(t, cancelled.KeyMetadata.DeletionDate)
	require.True(t, f.material[record.ProviderKey])
}

func TestLifecycleRejectsOtherTenantsAndEngines(t *testing.T) {
	p, f := newLifecycleFixture(t)
	f.add(t, "a", "key", schemeTransit)
	_, err := p.DisableKey(context.Background(), &proto.DisableKeyRequest{ClientId: "b", KeyId: "kms:key"})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	for _, scheme := range []string{schemeEthereum, schemePQC} {
		record := f.add(t, "a", strings.ToLower(scheme), scheme)
		_, err = p.DisableKey(context.Background(), &proto.DisableKeyRequest{ClientId: "a", KeyId: record.KeyID})
		require.Equal(t, codes.Unimplemented, status.Code(err))
		_, err = p.ScheduleKeyDeletion(context.Background(), &proto.ScheduleKeyDeletionRequest{ClientId: "a", KeyId: record.KeyID})
		require.Equal(t, codes.Unimplemented, status.Code(err))
		require.True(t, f.material[record.ProviderKey])
	}
}

func TestSchedulingFailureRetainsSafeIndex(t *testing.T) {
	p, f := newLifecycleFixture(t)
	record := f.add(t, "a", "key", schemeTransit)
	f.fail = "POST /v1/secret/data/kms/metadata/" + tenantNamespace("a") + "/" + record.KeyID
	_, err := p.ScheduleKeyDeletion(context.Background(), &proto.ScheduleKeyDeletionRequest{ClientId: "a", KeyId: record.KeyID})
	require.Equal(t, codes.Internal, status.Code(err))
	require.Equal(t, "KMS backend error", status.Convert(err).Message())
	f.fail = ""
	p.now = func() time.Time { return time.Date(2026, 12, 12, 12, 0, 0, 0, time.UTC) }
	p.sweepDeletedKeys(context.Background())
	require.True(t, f.material[record.ProviderKey])
	for path := range f.kv {
		require.NotContains(t, path, "/pending-deletion/")
	}
}

func TestDeletionWorkerRetriesEveryPartialFailure(t *testing.T) {
	for _, step := range []string{"claim", "tombstone", "config", "material", "metadata", "index"} {
		t.Run(step, func(t *testing.T) {
			p, f := newLifecycleFixture(t)
			record := f.add(t, "a", "key", schemeTransit)
			_, err := p.ScheduleKeyDeletion(context.Background(), &proto.ScheduleKeyDeletionRequest{ClientId: "a", KeyId: record.KeyID})
			require.NoError(t, err)
			tenant := tenantNamespace("a")
			metadata, err := p.client.getMetadata(context.Background(), "a", record.KeyID)
			require.NoError(t, err)
			failure := map[string]string{
				"claim":     "POST /v1/secret/data/kms/metadata/" + tenant + "/" + record.KeyID,
				"tombstone": "POST /v1/secret/data/kms/deleted/" + tenant + "/" + record.KeyID,
				"config":    "POST /v1/transit/keys/" + record.ProviderKey + "/config",
				"material":  "DELETE /v1/transit/keys/" + record.ProviderKey,
				"metadata":  "DELETE /v1/secret/metadata/kms/metadata/" + tenant + "/" + record.KeyID,
				"index":     "DELETE /v1/secret/metadata/kms/pending-deletion/" + tenant + "/" + metadata.DeletionIndex,
			}
			p.now = func() time.Time { return time.Date(2026, 12, 12, 12, 0, 0, 0, time.UTC) }
			f.fail = failure[step]
			p.sweepDeletedKeys(context.Background())
			f.fail = ""
			p.sweepDeletedKeys(context.Background())
			require.False(t, f.material[record.ProviderKey])
			require.NotContains(t, f.kv, "/v1/secret/data/kms/metadata/"+tenant+"/"+record.KeyID)
			require.Contains(t, f.kv, "/v1/secret/data/kms/deleted/"+tenant+"/"+record.KeyID)
			_, err = p.CreateKey(context.Background(), &proto.CreateKeyRequest{ClientId: "a", Alias: "key"})
			require.Equal(t, codes.AlreadyExists, status.Code(err))
			_, err = p.GetKeyMetadata(context.Background(), &proto.GetKeyMetadataRequest{ClientId: "a", KeyId: record.KeyID})
			require.Equal(t, codes.PermissionDenied, status.Code(err))
		})
	}
}

func TestCancelCASConflictAndDeadline(t *testing.T) {
	p, f := newLifecycleFixture(t)
	record := f.add(t, "a", "key", schemeTransit)
	_, err := p.ScheduleKeyDeletion(context.Background(), &proto.ScheduleKeyDeletionRequest{ClientId: "a", KeyId: record.KeyID})
	require.NoError(t, err)
	path := "/v1/secret/data/kms/metadata/" + tenantNamespace("a") + "/" + record.KeyID
	f.beforeCAS = func(target string) {
		if target != path {
			return
		}
		entry := f.kv[path]
		entry.version++
		var current keyMetadataRecord
		require.NoError(t, json.Unmarshal(entry.record, &current))
		current.DeletionStartedAt = "2026-12-11T12:00:00Z"
		entry.record, _ = json.Marshal(current)
		f.kv[path] = entry
		f.beforeCAS = nil
	}
	_, err = p.CancelKeyDeletion(context.Background(), &proto.CancelKeyDeletionRequest{ClientId: "a", KeyId: record.KeyID})
	require.Equal(t, codes.Aborted, status.Code(err))
	_, err = p.CancelKeyDeletion(context.Background(), &proto.CancelKeyDeletionRequest{ClientId: "a", KeyId: record.KeyID})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	p.now = func() time.Time { return time.Date(2026, 12, 11, 12, 0, 0, 0, time.UTC) }
	_, err = p.CancelKeyDeletion(context.Background(), &proto.CancelKeyDeletionRequest{ClientId: "a", KeyId: record.KeyID})
	require.Equal(t, "deletion date has passed", status.Convert(err).Message())
}

func TestWorkerCancellationAndMultipleReplicas(t *testing.T) {
	p, f := newLifecycleFixture(t)
	record := f.add(t, "a", "key", schemeTransit)
	_, err := p.ScheduleKeyDeletion(context.Background(), &proto.ScheduleKeyDeletionRequest{ClientId: "a", KeyId: record.KeyID})
	require.NoError(t, err)
	p.now = func() time.Time { return time.Date(2026, 12, 12, 12, 0, 0, 0, time.UTC) }
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); p.sweepDeletedKeys(context.Background()) }()
	}
	wg.Wait()
	require.False(t, f.material[record.ProviderKey])
	p.deletionInterval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)
	cancel()
	done := make(chan struct{})
	go func() { p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}

func TestRotationCannotOverwriteConcurrentDisable(t *testing.T) {
	p, f := newLifecycleFixture(t)
	record := f.add(t, "a", "key", schemeTransit)
	path := "/v1/secret/data/kms/metadata/" + tenantNamespace("a") + "/" + record.KeyID
	f.beforeCAS = func(target string) {
		if target != path {
			return
		}
		record.KeyState, record.Enabled = keyStateDisabled, false
		f.save(t, record)
		f.beforeCAS = nil
	}
	_, err := p.RotateKey(context.Background(), &proto.RotateKeyRequest{ClientId: "a", KeyId: record.KeyID})
	require.Equal(t, codes.Aborted, status.Code(err))
	current, err := p.client.getMetadata(context.Background(), "a", record.KeyID)
	require.NoError(t, err)
	require.False(t, current.Enabled)
	require.Equal(t, keyStateDisabled, current.KeyState)
	require.Equal(t, uint32(2), f.versions[record.ProviderKey]) // the engine operation cannot be rolled back
}

func TestWorkerSkipsFutureAndRejectsForeignProviderReference(t *testing.T) {
	p, f := newLifecycleFixture(t)
	record := f.add(t, "a", "key", schemeTransit)
	_, err := p.ScheduleKeyDeletion(context.Background(), &proto.ScheduleKeyDeletionRequest{ClientId: "a", KeyId: record.KeyID})
	require.NoError(t, err)
	f.requests = nil
	p.sweepDeletedKeys(context.Background())
	require.Len(t, f.requests, 2) // pending tenant + entry LIST, no key metadata read
	current, err := p.client.getMetadata(context.Background(), "a", record.KeyID)
	require.NoError(t, err)
	current.ProviderKey, err = scopedBackendKey("b", "key")
	require.NoError(t, err)
	f.material[current.ProviderKey] = true
	f.save(t, current)
	p.now = func() time.Time { return time.Date(2026, 12, 12, 12, 0, 0, 0, time.UTC) }
	f.requests = nil
	p.sweepDeletedKeys(context.Background())
	require.True(t, f.material[current.ProviderKey])
	for _, request := range f.requests {
		require.NotContains(t, request, "/v1/transit/")
	}
}

func TestCancelIndexCleanupFailureCannotDeleteCancelledKey(t *testing.T) {
	p, f := newLifecycleFixture(t)
	record := f.add(t, "a", "key", schemeTransit)
	_, err := p.ScheduleKeyDeletion(context.Background(), &proto.ScheduleKeyDeletionRequest{ClientId: "a", KeyId: record.KeyID})
	require.NoError(t, err)
	current, err := p.client.getMetadata(context.Background(), "a", record.KeyID)
	require.NoError(t, err)
	f.fail = "DELETE /v1/secret/metadata/kms/pending-deletion/" + tenantNamespace("a") + "/" + current.DeletionIndex
	_, err = p.CancelKeyDeletion(context.Background(), &proto.CancelKeyDeletionRequest{ClientId: "a", KeyId: record.KeyID})
	require.NoError(t, err)
	f.fail = ""
	p.now = func() time.Time { return time.Date(2026, 12, 12, 12, 0, 0, 0, time.UTC) }
	p.sweepDeletedKeys(context.Background())
	require.True(t, f.material[record.ProviderKey])
	current, err = p.client.getMetadata(context.Background(), "a", record.KeyID)
	require.NoError(t, err)
	require.Equal(t, keyStateDisabled, current.KeyState)
}

func TestListKeysTwoThousandKeysWithMaximumPage(t *testing.T) {
	p, f := newLifecycleFixture(t)
	for i := 0; i < 2000; i++ {
		f.add(t, "a", fmt.Sprintf("key-%04d", i), schemeTransit)
	}
	limit := uint32(1000)
	first, err := p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: "a", Limit: &limit})
	require.NoError(t, err)
	require.Len(t, first.KeyIds, 1000)
	second, err := p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: "a", Limit: &limit, NextToken: first.NextToken})
	require.NoError(t, err)
	require.Len(t, second.KeyIds, 1000)
	require.Nil(t, second.NextToken)
	require.Equal(t, "kms:key-1000", second.KeyIds[0])
	require.Len(t, f.requests, 2)
}

func TestCancelRejectsMismatchedScheduleWithoutWriting(t *testing.T) {
	p, f := newLifecycleFixture(t)
	record := f.add(t, "a", "key", schemeTransit)
	record.Enabled = false
	record.KeyState = keyStatePendingDeletion
	record.DeletionDate = "2026-12-11T12:00:00Z"
	record.DeletionIndex = "kms:other_20261211T120000Z_12345678"
	f.save(t, record)
	_, err := p.CancelKeyDeletion(context.Background(), &proto.CancelKeyDeletionRequest{ClientId: "a", KeyId: record.KeyID})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Len(t, f.requests, 1)
	require.True(t, strings.HasPrefix(f.requests[0], "GET "))
}
