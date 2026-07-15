package kms

import (
	"strings"
	"testing"
)

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

func TestTenantNamespaceUsesSixteenBytesOfHash(t *testing.T) {
	namespace := tenantNamespace("auth0|tenant-a")
	if got := len(strings.TrimPrefix(namespace, tenantNamespacePrefix)); got != tenantNamespaceBytes*2 {
		t.Fatalf("expected %d hex chars in tenant namespace, got %d", tenantNamespaceBytes*2, got)
	}
}

func TestScopedBackendKeyUsesTenantNamespace(t *testing.T) {
	keyA, err := scopedBackendKey("tenant-a", "payments-main")
	if err != nil {
		t.Fatalf("scopedBackendKey() error = %v", err)
	}
	keyB, err := scopedBackendKey("tenant-b", "payments-main")
	if err != nil {
		t.Fatalf("scopedBackendKey() second error = %v", err)
	}

	if keyA == keyB {
		t.Fatalf("expected tenant scoping to affect backend key, got %q", keyA)
	}
	if keyA != tenantNamespace("tenant-a")+"_payments-main" {
		t.Fatalf("unexpected backend key %q", keyA)
	}
}

func TestCanonicalKeyIDUsesAlias(t *testing.T) {
	keyID, err := canonicalKeyID("payments-main")
	if err != nil {
		t.Fatalf("canonicalKeyID() error = %v", err)
	}
	if keyID != "kms:payments-main" {
		t.Fatalf("unexpected key id %q", keyID)
	}
}

func TestResolveKeyRefNormalizesAliasAndCanonicalID(t *testing.T) {
	keyID, alias, err := resolveKeyRef("payments-main")
	if err != nil {
		t.Fatalf("resolveKeyRef(alias) error = %v", err)
	}
	if keyID != "kms:payments-main" || alias != "payments-main" {
		t.Fatalf("unexpected alias resolution result keyID=%q alias=%q", keyID, alias)
	}

	keyID, alias, err = resolveKeyRef("kms:payments-main")
	if err != nil {
		t.Fatalf("resolveKeyRef(keyID) error = %v", err)
	}
	if keyID != "kms:payments-main" || alias != "payments-main" {
		t.Fatalf("unexpected key id resolution result keyID=%q alias=%q", keyID, alias)
	}
}

func TestResolveKeyRefRejectsInvalidAlias(t *testing.T) {
	if _, _, err := resolveKeyRef("payments_main"); err == nil {
		t.Fatal("expected resolveKeyRef to reject underscores")
	}
	if _, _, err := resolveKeyRef("kms:payments/main"); err == nil {
		t.Fatal("expected resolveKeyRef to reject slashes")
	}
}
