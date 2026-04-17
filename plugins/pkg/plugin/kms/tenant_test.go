package kms

import "testing"

func TestTenantNamespaceIsDeterministic(t *testing.T) {
	first := tenantNamespace("auth0|tenant-a")
	second := tenantNamespace("auth0|tenant-a")
	third := tenantNamespace("auth0|tenant-b")

	if first == "" {
		t.Fatal("expected non-empty tenant namespace")
	}
	if first != second {
		t.Fatalf("expected deterministic namespace, got %q and %q", first, second)
	}
	if first == third {
		t.Fatalf("expected different client IDs to produce different namespaces, got %q", first)
	}
}

func TestScopedBackendKeyUsesTenantNamespace(t *testing.T) {
	keyID := "kms:11111111-1111-1111-1111-111111111111"
	keyA, err := scopedBackendKey("tenant-a", keyID)
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}
	keyB, err := scopedBackendKey("tenant-b", keyID)
	if err != nil {
		t.Fatalf("scopedBackendKey() second error = %v", err)
	}

	if keyA == keyB {
		t.Fatalf("expected tenant scoping to affect backend key, got %q", keyA)
	}
	if keyA == keyID {
		t.Fatalf("expected backend key to be tenant-scoped, got %q", keyA)
	}
	if keyA != tenantNamespace("tenant-a")+"_11111111-1111-1111-1111-111111111111" {
		t.Fatalf("unexpected backend key %q", keyA)
	}
}

func TestScopedBackendKeyRejectsNonUUIDKeyID(t *testing.T) {
	if _, err := scopedBackendKey("tenant-a", "kms:not-a-uuid"); err == nil {
		t.Fatal("expected scopedBackendKey to reject non-UUID key IDs")
	}
}
