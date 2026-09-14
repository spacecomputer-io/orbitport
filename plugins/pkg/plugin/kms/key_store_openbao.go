package kms

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type keyStoreRecord struct {
	Name      string          `json:"name"`
	Owner     string          `json:"owner"`
	Secret    json.RawMessage `json:"secret"`
	UpdatedAt string          `json:"updated_at"`
}

func (c *openBaoClient) putKeyStoreSecret(ctx context.Context, clientID, name string, secret json.RawMessage, updatedAt time.Time) (uint32, error) {
	var resp struct {
		Data struct {
			Version uint32 `json:"version"`
		} `json:"data"`
	}
	record := keyStoreRecord{
		Name:      name,
		Owner:     tenantNamespace(clientID),
		Secret:    secret,
		UpdatedAt: updatedAt.UTC().Format(time.RFC3339),
	}
	target, err := c.keyStoreDataPath(clientID, name)
	if err != nil {
		return 0, err
	}
	if err := c.Post(ctx, target, map[string]any{"data": record}, &resp); err != nil {
		return 0, err
	}
	return resp.Data.Version, nil
}

func (c *openBaoClient) getKeyStoreSecret(ctx context.Context, clientID, name string) (*keyStoreRecord, error) {
	var resp struct {
		Data struct {
			Data keyStoreRecord `json:"data"`
		} `json:"data"`
	}
	target, err := c.keyStoreDataPath(clientID, name)
	if err != nil {
		return nil, err
	}
	if err := c.Get(ctx, target, &resp); err != nil {
		return nil, err
	}
	return &resp.Data.Data, nil
}

func (c *openBaoClient) ensureKeyStoreSecretExists(ctx context.Context, clientID, name string) error {
	target, err := c.keyStoreMetadataPath(clientID, name)
	if err != nil {
		return err
	}
	return c.Get(ctx, target, nil)
}

func (c *openBaoClient) listKeyStoreSecrets(ctx context.Context, clientID, prefix string) ([]string, error) {
	var resp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	target, err := c.keyStoreMetadataPath(clientID, prefix)
	if err != nil {
		return nil, err
	}
	if err := c.List(ctx, target, &resp); err != nil {
		return nil, err
	}

	var names []string
	owner := tenantNamespace(clientID)
	for _, key := range resp.Data.Keys {
		isFolder := strings.HasSuffix(key, "/")
		segment := strings.TrimSuffix(key, "/")
		if err := validateKeyStoreSegment("path", segment); err != nil {
			logger.Warnf("key-store list skipped unsafe OpenBao key owner=%s raw_key=%q: %v", owner, key, err)
			continue
		}
		name := joinKeyStoreName(prefix, segment)
		if len(name) > maxKeyStoreNameLen {
			logger.Warnf(
				"key-store list skipped over-length OpenBao key owner=%s raw_key=%q full_name=%q max_length=%d",
				owner,
				key,
				name,
				maxKeyStoreNameLen,
			)
			continue
		}
		if isFolder {
			names = append(names, name+"/")
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (c *openBaoClient) deleteKeyStoreSecret(ctx context.Context, clientID, name string) error {
	target, err := c.keyStoreMetadataPath(clientID, name)
	if err != nil {
		return err
	}
	return c.Delete(ctx, target, nil)
}

func (c *openBaoClient) keyStoreDataPath(clientID, name string) (string, error) {
	parts := []string{"v1", c.keyStoreMount, "data", "owners", tenantNamespace(clientID)}
	nameParts, err := keyStorePathParts(name)
	if err != nil {
		return "", err
	}
	parts = append(parts, nameParts...)
	return c.joinPath(parts...), nil
}

func (c *openBaoClient) keyStoreMetadataPath(clientID, prefix string) (string, error) {
	parts := []string{"v1", c.keyStoreMount, "metadata", "owners", tenantNamespace(clientID)}
	prefixParts, err := keyStorePathParts(prefix)
	if err != nil {
		return "", err
	}
	parts = append(parts, prefixParts...)
	return c.joinPath(parts...), nil
}

func keyStorePathParts(value string) ([]string, error) {
	value = strings.Trim(value, "/")
	if value == "" {
		return nil, nil
	}
	segments := strings.Split(value, "/")
	for _, segment := range segments {
		if err := validateKeyStoreSegment("path", segment); err != nil {
			return nil, fmt.Errorf("unsafe key-store path: %w", err)
		}
	}
	return segments, nil
}

func joinKeyStoreName(prefix, name string) string {
	prefix = strings.Trim(prefix, "/")
	name = strings.Trim(name, "/")
	if prefix == "" {
		return name
	}
	if name == "" {
		return prefix
	}
	return prefix + "/" + name
}
