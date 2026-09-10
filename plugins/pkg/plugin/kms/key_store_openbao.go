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
	if err := c.Post(ctx, c.keyStoreDataPath(clientID, name), map[string]any{"data": record}, &resp); err != nil {
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
	headers := map[string]string{
		wrapTTLHeader: fmt.Sprintf("%ds", ttlSeconds),
	}
	if err := c.GetWithHeaders(ctx, c.keyStoreDataPath(clientID, name), headers, &resp); err != nil {
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

func (c *openBaoClient) listKeyStoreSecrets(ctx context.Context, clientID, prefix string) ([]string, error) {
	names, err := c.listKeyStoreSecretsRecursive(ctx, clientID, prefix)
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

func (c *openBaoClient) listKeyStoreSecretsRecursive(ctx context.Context, clientID, prefix string) ([]string, error) {
	var resp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := c.List(ctx, c.keyStoreMetadataPath(clientID, prefix), &resp); err != nil {
		return nil, err
	}

	var names []string
	for _, key := range resp.Data.Keys {
		if strings.HasSuffix(key, "/") {
			childPrefix := joinKeyStoreName(prefix, strings.TrimSuffix(key, "/"))
			childNames, err := c.listKeyStoreSecretsRecursive(ctx, clientID, childPrefix)
			if err != nil {
				return nil, err
			}
			names = append(names, childNames...)
			continue
		}
		names = append(names, joinKeyStoreName(prefix, key))
	}
	return names, nil
}

func (c *openBaoClient) deleteKeyStoreSecret(ctx context.Context, clientID, name string) error {
	return c.Delete(ctx, c.keyStoreMetadataPath(clientID, name), nil)
}

func (c *openBaoClient) keyStoreDataPath(clientID, name string) string {
	parts := []string{"v1", c.keyStoreMount, "data", "owners", tenantNamespace(clientID)}
	parts = append(parts, keyStorePathParts(name)...)
	return c.joinPath(parts...)
}

func (c *openBaoClient) keyStoreMetadataPath(clientID, prefix string) string {
	parts := []string{"v1", c.keyStoreMount, "metadata", "owners", tenantNamespace(clientID)}
	parts = append(parts, keyStorePathParts(prefix)...)
	return c.joinPath(parts...)
}

func (c *openBaoClient) keyStoreCreationPath(clientID, name string) string {
	parts := []string{c.keyStoreMount, "data", "owners", tenantNamespace(clientID)}
	parts = append(parts, keyStorePathParts(name)...)
	return path.Join(parts...)
}

func (c *openBaoClient) systemPath(parts ...string) string {
	all := append([]string{"v1", "sys"}, parts...)
	return c.joinPath(all...)
}

func keyStorePathParts(value string) []string {
	value = strings.Trim(value, "/")
	if value == "" {
		return nil
	}
	return strings.Split(value, "/")
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
