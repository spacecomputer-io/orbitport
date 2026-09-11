package kms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/internal/openbao"
)

const wrapTTLHeader = "X-Vault-Wrap-TTL"

type keyStoreRecord struct {
	Name      string         `json:"name"`
	Owner     string         `json:"owner"`
	Secret    map[string]any `json:"secret"`
	UpdatedAt string         `json:"updated_at"`
}

type keyStoreWrapInfo struct {
	Token        string
	TTLSeconds   int
	CreationTime string
}

type keyStoreWrappingLookupInfo struct {
	CreationPath string
	CreationTTL  int
	CreationTime string
}

func (c *openBaoClient) putKeyStoreSecret(ctx context.Context, clientID, name string, secret map[string]any, updatedAt time.Time) (uint32, error) {
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

func (c *openBaoClient) wrapKeyStoreSecret(ctx context.Context, clientID, name string, ttlSeconds int) (*keyStoreWrapInfo, error) {
	var resp struct {
		WrapInfo struct {
			Token        string `json:"token"`
			TTL          int    `json:"ttl"`
			CreationTime string `json:"creation_time"`
		} `json:"wrap_info"`
	}
	target, err := c.keyStoreDataPath(clientID, name)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{
		wrapTTLHeader: fmt.Sprintf("%ds", ttlSeconds),
	}
	if err := c.GetWithHeaders(ctx, target, headers, &resp); err != nil {
		return nil, err
	}
	if resp.WrapInfo.Token == "" {
		return nil, fmt.Errorf("OpenBao did not return a wrapping token")
	}
	ttl := resp.WrapInfo.TTL
	if ttl == 0 {
		ttl = ttlSeconds
	}
	return &keyStoreWrapInfo{
		Token:        resp.WrapInfo.Token,
		TTLSeconds:   ttl,
		CreationTime: resp.WrapInfo.CreationTime,
	}, nil
}

func (c *openBaoClient) lookupWrappingToken(ctx context.Context, token string) (*keyStoreWrappingLookupInfo, error) {
	var resp struct {
		Data struct {
			CreationPath string `json:"creation_path"`
			CreationTTL  int    `json:"creation_ttl"`
			CreationTime string `json:"creation_time"`
		} `json:"data"`
	}
	if err := c.Post(ctx, c.systemPath("wrapping", "lookup"), map[string]any{"token": token}, &resp); err != nil {
		return nil, err
	}
	return &keyStoreWrappingLookupInfo{
		CreationPath: resp.Data.CreationPath,
		CreationTTL:  resp.Data.CreationTTL,
		CreationTime: resp.Data.CreationTime,
	}, nil
}

func (c *openBaoClient) unwrapKeyStoreSecret(ctx context.Context, token string) (*keyStoreRecord, error) {
	var resp struct {
		Data struct {
			Data keyStoreRecord `json:"data"`
		} `json:"data"`
	}
	if err := c.Post(ctx, c.systemPath("wrapping", "unwrap"), map[string]any{"token": token}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data.Data, nil
}

func (c *openBaoClient) ensureKeyStoreSecretExists(ctx context.Context, clientID, name string) error {
	var resp struct {
		Data map[string]any `json:"data"`
	}
	target, err := c.keyStoreMetadataPath(clientID, name)
	if err != nil {
		return err
	}
	return c.Get(ctx, target, &resp)
}

func (c *openBaoClient) listKeyStoreSecrets(ctx context.Context, clientID, prefix string) ([]string, error) {
	prefixParts, err := keyStorePathParts(prefix, c.keyStoreMaxDepth)
	if err != nil {
		return nil, err
	}
	names, err := c.listKeyStoreSecretsRecursive(ctx, clientID, prefix, len(prefixParts))
	if err != nil {
		var statusErr *openbao.StatusError
		if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
			return []string{}, nil
		}
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func (c *openBaoClient) listKeyStoreSecretsRecursive(ctx context.Context, clientID, prefix string, depth int) ([]string, error) {
	maxDepth := effectiveKeyStoreMaxDepth(c.keyStoreMaxDepth)
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
	for _, key := range resp.Data.Keys {
		segment := strings.TrimSuffix(key, "/")
		if err := validateKeyStoreSegment("path", segment); err != nil {
			return nil, fmt.Errorf("unsafe key-store path: %w", err)
		}
		childDepth := depth + 1
		if err := validateKeyStoreDepth("path", childDepth, c.keyStoreMaxDepth); err != nil {
			return nil, err
		}
		if strings.HasSuffix(key, "/") {
			if childDepth >= maxDepth {
				return nil, fmt.Errorf("%w: list would exceed maximum depth of %d path segments", errKeyStoreMaxDepthExceeded, maxDepth)
			}
			childPrefix := joinKeyStoreName(prefix, segment)
			childNames, err := c.listKeyStoreSecretsRecursive(ctx, clientID, childPrefix, childDepth)
			if err != nil {
				return nil, err
			}
			names = append(names, childNames...)
			continue
		}
		names = append(names, joinKeyStoreName(prefix, segment))
	}
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
	nameParts, err := keyStorePathParts(name, c.keyStoreMaxDepth)
	if err != nil {
		return "", err
	}
	parts = append(parts, nameParts...)
	return c.joinPath(parts...), nil
}

func (c *openBaoClient) keyStoreMetadataPath(clientID, prefix string) (string, error) {
	parts := []string{"v1", c.keyStoreMount, "metadata", "owners", tenantNamespace(clientID)}
	prefixParts, err := keyStorePathParts(prefix, c.keyStoreMaxDepth)
	if err != nil {
		return "", err
	}
	parts = append(parts, prefixParts...)
	return c.joinPath(parts...), nil
}

func (c *openBaoClient) keyStoreCreationPath(clientID, name string) (string, error) {
	parts := []string{c.keyStoreMount, "data", "owners", tenantNamespace(clientID)}
	nameParts, err := keyStorePathParts(name, c.keyStoreMaxDepth)
	if err != nil {
		return "", err
	}
	parts = append(parts, nameParts...)
	return path.Join(parts...), nil
}

func (c *openBaoClient) systemPath(parts ...string) string {
	all := append([]string{"v1", "sys"}, parts...)
	return c.joinPath(all...)
}

func keyStorePathParts(value string, maxDepth int) ([]string, error) {
	value = strings.Trim(value, "/")
	if value == "" {
		return nil, nil
	}
	segments := strings.Split(value, "/")
	if err := validateKeyStoreDepth("path", len(segments), maxDepth); err != nil {
		return nil, fmt.Errorf("unsafe key-store path: %w", err)
	}
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

func normalizeOpenBaoCreationPath(value string) string {
	value = strings.Trim(value, "/")
	value = strings.TrimPrefix(value, "v1/")
	if decoded, err := url.PathUnescape(value); err == nil {
		value = decoded
	}
	return value
}
