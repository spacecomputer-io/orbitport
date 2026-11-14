package kms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/spacecomputer-io/orbitport/plugins/internal/openbao"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var kmsTenantPattern = regexp.MustCompile(`^tenant_[0-9a-f]{32}$`)

func (c *openBaoClient) kmsMetadataURL(tenant, category, name string, metadata bool) (string, error) {
	if !kmsTenantPattern.MatchString(tenant) {
		return "", fmt.Errorf("invalid KMS tenant namespace")
	}
	switch category {
	case "metadata", "deleted":
		if name != "" && !isCanonicalKeyID(name) {
			return "", fmt.Errorf("invalid KMS key ID")
		}
	case "pending-deletion":
		if name != "" {
			if _, _, err := parseDeletionEntry(name); err != nil {
				return "", err
			}
		}
	default:
		return "", fmt.Errorf("invalid KMS metadata category")
	}
	kind := "data"
	if metadata {
		kind = "metadata"
	}
	parts := []string{"v1", c.kvMount, kind, "kms", category, tenant}
	if name != "" {
		parts = append(parts, name)
	}
	return c.joinPath(parts...), nil
}

func isOpenBaoNotFound(err error) bool {
	var backend *openbao.StatusError
	return errors.As(err, &backend) && backend.StatusCode == http.StatusNotFound
}

func (c *openBaoClient) listKMSMetadata(ctx context.Context, tenant, category string) ([]string, error) {
	target, err := c.kmsMetadataURL(tenant, category, "", true)
	if err != nil {
		return nil, err
	}
	return c.listKMSPath(ctx, target)
}

func (c *openBaoClient) listKMSPath(ctx context.Context, target string) ([]string, error) {
	var response struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := c.List(ctx, target, &response); err != nil {
		if isOpenBaoNotFound(err) {
			return []string{}, nil
		}
		return nil, err
	}
	return response.Data.Keys, nil
}

func (c *openBaoClient) ensureAliasNotDeleted(ctx context.Context, clientID, keyID string) error {
	target, err := c.kmsMetadataURL(tenantNamespace(clientID), "deleted", keyID, false)
	if err != nil {
		return status.Error(codes.Internal, "KMS backend error")
	}
	err = c.Get(ctx, target, nil)
	if err == nil {
		return status.Error(codes.AlreadyExists, "alias belonged to a deleted key and cannot be reused")
	}
	if isOpenBaoNotFound(err) {
		return nil
	}
	return kmsBackendStatus("check retired alias", err)
}

func (c *openBaoClient) putDeletionEntry(ctx context.Context, tenant, entry string, record *keyMetadataRecord) error {
	target, err := c.kmsMetadataURL(tenant, "pending-deletion", entry, false)
	if err != nil {
		return err
	}
	return c.Post(ctx, target, map[string]any{
		"options": map[string]any{"cas": 0},
		"data":    map[string]string{"key_id": record.KeyID, "deletion_date": record.DeletionDate},
	}, nil)
}

func (c *openBaoClient) deleteDeletionEntry(ctx context.Context, tenant, entry string) error {
	target, err := c.kmsMetadataURL(tenant, "pending-deletion", entry, true)
	if err != nil {
		return err
	}
	return c.Delete(ctx, target, nil)
}

func (c *openBaoClient) putKeyTombstone(ctx context.Context, tenant string, record *keyMetadataRecord, deletedAt string) error {
	target, err := c.kmsMetadataURL(tenant, "deleted", record.KeyID, false)
	if err != nil {
		return err
	}
	return c.Post(ctx, target, map[string]any{"data": map[string]string{
		"key_id": record.KeyID, "alias": record.Alias, "scheme": record.Scheme,
		"key_spec": record.KeySpec, "created_at": record.CreatedAt, "deleted_at": deletedAt,
	}}, nil)
}

func (c *openBaoClient) deleteTransitKey(ctx context.Context, key string) error {
	if _, err := c.readTransitKey(ctx, key); err != nil {
		if isOpenBaoNotFound(err) {
			return nil
		}
		return err
	}
	err := c.Post(ctx, c.transitPath("keys", key, "config"), map[string]any{"deletion_allowed": true}, nil)
	if err == nil {
		err = c.Delete(ctx, c.transitPath("keys", key), nil)
	}
	if err != nil {
		// Another replica may have finished after our read. Only confirmed absence is success.
		if _, readErr := c.readTransitKey(ctx, key); isOpenBaoNotFound(readErr) {
			return nil
		}
	}
	return err
}

func (c *openBaoClient) pendingDeletionTenants(ctx context.Context) ([]string, error) {
	target := c.joinPath("v1", c.kvMount, "metadata", "kms", "pending-deletion")
	folders, err := c.listKMSPath(ctx, target)
	if err != nil {
		return nil, err
	}
	tenants := make([]string, 0, len(folders))
	for _, folder := range folders {
		tenant := strings.TrimSuffix(folder, "/")
		if !strings.HasSuffix(folder, "/") || !kmsTenantPattern.MatchString(tenant) {
			logger.Warnf("skipping unsafe deletion tenant folder=%q", folder)
			continue
		}
		tenants = append(tenants, tenant)
	}
	return tenants, nil
}
