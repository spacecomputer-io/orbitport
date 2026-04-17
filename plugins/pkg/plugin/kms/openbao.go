package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type openBaoClient struct {
	baseURL       string
	ethereumMount string
	httpClient    *http.Client
	kvMount       string
	transitMount  string
}

type keyMetadataRecord struct {
	KeyID          string       `json:"key_id"`
	ClientID       string       `json:"client_id"`
	Scheme         string       `json:"scheme"`
	ProviderKey    string       `json:"provider_key,omitempty"`
	TransitKey     string       `json:"transit_key,omitempty"`
	Description    string       `json:"description"`
	KeySpec        string       `json:"key_spec"`
	KeyUsage       string       `json:"key_usage"`
	Enabled        bool         `json:"enabled"`
	PrimaryVersion uint32       `json:"primary_version"`
	CreatedAt      string       `json:"created_at"`
	PublicKey      string       `json:"public_key,omitempty"`
	Address        string       `json:"address,omitempty"`
	Tags           []*pluginTag `json:"tags"`
}

type pluginTag struct {
	TagKey   string `json:"tag_key"`
	TagValue string `json:"tag_value"`
}

type openBaoStatusError struct {
	statusCode int
	status     string
}

func (e *openBaoStatusError) Error() string {
	return fmt.Sprintf("openbao returned %s", e.status)
}

type transitKeyInfo struct {
	LatestVersion uint32 `json:"latest_version"`
	Type          string `json:"type"`
}

type ethereumKeyInfo struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	CreatedAt string `json:"created_at"`
}

type ethereumSignInfo struct {
	Signature string `json:"signature"`
	Hash      string `json:"hash"`
	Method    string `json:"method"`
	Address   string `json:"address"`
}

func newOpenBaoClient(cfg *kmsConfig) *openBaoClient {
	logger.Infof(
		"initializing OpenBao client with base_url=%s transit_mount=%s kv_mount=%s ethereum_mount=%s timeout_secs=%d",
		strings.TrimRight(cfg.OpenBaoProxyURL, "/"),
		cfg.TransitMount,
		cfg.KVMount,
		cfg.EthereumMount,
		cfg.TimeoutSecs,
	)
	return &openBaoClient{
		baseURL:       strings.TrimRight(cfg.OpenBaoProxyURL, "/"),
		ethereumMount: cfg.EthereumMount,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSecs) * time.Second,
		},
		kvMount:      cfg.KVMount,
		transitMount: cfg.TransitMount,
	}
}

func (m *keyMetadataRecord) normalize() {
	if m.Scheme == "" {
		m.Scheme = schemeTransit
	}
	if m.ProviderKey == "" {
		m.ProviderKey = m.TransitKey
	}
}

func (m *keyMetadataRecord) backendKey() string {
	if m.ProviderKey != "" {
		return m.ProviderKey
	}
	return m.TransitKey
}

func (c *openBaoClient) createTransitKey(ctx context.Context, name, keyType string) (*transitKeyInfo, error) {
	if err := c.post(ctx, c.transitPath("keys", name), map[string]any{"type": keyType}, nil); err != nil {
		return nil, err
	}
	return c.readTransitKey(ctx, name)
}

func (c *openBaoClient) readTransitKey(ctx context.Context, name string) (*transitKeyInfo, error) {
	var resp struct {
		Data transitKeyInfo `json:"data"`
	}
	if err := c.get(ctx, c.transitPath("keys", name), &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *openBaoClient) encrypt(ctx context.Context, transitKey, plaintext string) (string, error) {
	var resp struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	err := c.post(ctx, c.transitPath("encrypt", transitKey), map[string]any{
		"plaintext": plaintext,
	}, &resp)
	if err != nil {
		return "", err
	}
	return resp.Data.Ciphertext, nil
}

func (c *openBaoClient) decrypt(ctx context.Context, transitKey, ciphertext string) (string, error) {
	var resp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	err := c.post(ctx, c.transitPath("decrypt", transitKey), map[string]any{
		"ciphertext": ciphertext,
	}, &resp)
	if err != nil {
		return "", err
	}
	return resp.Data.Plaintext, nil
}

func (c *openBaoClient) sign(ctx context.Context, transitKey, message string, mapping *signMapping) (string, error) {
	body := map[string]any{
		"input":     message,
		"prehashed": mapping.prehashed,
	}
	if mapping.signatureAlgorithm != "" {
		body["signature_algorithm"] = mapping.signatureAlgorithm
	}

	var resp struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	err := c.post(ctx, c.transitPath("sign", transitKey, mapping.pathAlgorithm), body, &resp)
	if err != nil {
		return "", err
	}
	return resp.Data.Signature, nil
}

func (c *openBaoClient) generateDataKey(ctx context.Context, transitKey string, bits int) (string, string, error) {
	var resp struct {
		Data struct {
			Plaintext  string `json:"plaintext"`
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	err := c.post(ctx, c.transitPath("datakey", "plaintext", transitKey), map[string]any{
		"bits": bits,
	}, &resp)
	if err != nil {
		return "", "", err
	}
	return resp.Data.Plaintext, resp.Data.Ciphertext, nil
}

func (c *openBaoClient) rotateTransitKey(ctx context.Context, transitKey string) (*transitKeyInfo, error) {
	if err := c.post(ctx, c.transitPath("keys", transitKey, "rotate"), map[string]any{}, nil); err != nil {
		return nil, err
	}
	return c.readTransitKey(ctx, transitKey)
}

func (c *openBaoClient) createEthereumKey(ctx context.Context, name string) (*ethereumKeyInfo, error) {
	var resp struct {
		Data ethereumKeyInfo `json:"data"`
	}
	if err := c.post(ctx, c.ethereumPath("keys", name), map[string]any{}, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *openBaoClient) signEthereumHash(ctx context.Context, keyName, hash string) (*ethereumSignInfo, error) {
	return c.signEthereum(ctx, keyName, map[string]any{"hash": hash})
}

func (c *openBaoClient) signEthereumMessage(ctx context.Context, keyName, message string) (*ethereumSignInfo, error) {
	return c.signEthereum(ctx, keyName, map[string]any{"message": message})
}

func (c *openBaoClient) signEthereum(ctx context.Context, keyName string, body map[string]any) (*ethereumSignInfo, error) {
	var resp struct {
		Data ethereumSignInfo `json:"data"`
	}
	if err := c.post(ctx, c.ethereumPath("sign", keyName), body, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *openBaoClient) putMetadata(ctx context.Context, clientID, keyID string, metadata *keyMetadataRecord) error {
	return c.post(ctx, c.metadataPath(clientID, keyID), map[string]any{
		"data": metadata,
	}, nil)
}

func (c *openBaoClient) getMetadata(ctx context.Context, clientID, keyID string) (*keyMetadataRecord, error) {
	var resp struct {
		Data struct {
			Data keyMetadataRecord `json:"data"`
		} `json:"data"`
	}
	if err := c.get(ctx, c.metadataPath(clientID, keyID), &resp); err != nil {
		return nil, err
	}
	record := &resp.Data.Data
	record.normalize()
	if record.ClientID != "" && record.ClientID != clientID {
		return nil, fmt.Errorf("metadata owner does not match request owner")
	}
	return record, nil
}

func (c *openBaoClient) metadataPath(clientID, keyID string) string {
	return c.kvPath("kms", "metadata", tenantNamespace(clientID), url.PathEscape(keyID))
}

func (c *openBaoClient) kvPath(parts ...string) string {
	all := append([]string{"v1", c.kvMount, "data"}, parts...)
	return c.joinPath(all...)
}

func (c *openBaoClient) transitPath(parts ...string) string {
	all := append([]string{"v1", c.transitMount}, parts...)
	return c.joinPath(all...)
}

func (c *openBaoClient) ethereumPath(parts ...string) string {
	all := append([]string{"v1", c.ethereumMount}, parts...)
	return c.joinPath(all...)
}

func (c *openBaoClient) joinPath(parts ...string) string {
	u, _ := url.Parse(c.baseURL)
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		clean = append(clean, strings.Trim(part, "/"))
	}
	u.Path = path.Join(append([]string{u.Path}, clean...)...)
	return u.String()
}

func (c *openBaoClient) post(ctx context.Context, target string, payload any, into any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal openbao payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create openbao request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, into)
}

func (c *openBaoClient) get(ctx context.Context, target string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("create openbao request: %w", err)
	}
	return c.do(req, into)
}

func (c *openBaoClient) do(req *http.Request, into any) error {
	logger.Debugf("OpenBao request %s %s", req.Method, req.URL.Path)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Warnf("OpenBao request failed %s %s: %v", req.Method, req.URL.Path, err)
		return fmt.Errorf("openbao request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warnf("failed reading OpenBao response body for %s %s: %v", req.Method, req.URL.Path, err)
		return fmt.Errorf("read openbao response: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		logger.Warnf("OpenBao returned %s for %s %s", resp.Status, req.Method, req.URL.Path)
		return &openBaoStatusError{
			statusCode: resp.StatusCode,
			status:     resp.Status,
		}
	}
	if into == nil {
		return nil
	}
	if err := json.Unmarshal(body, into); err != nil {
		logger.Warnf("failed decoding OpenBao response for %s %s: %v", req.Method, req.URL.Path, err)
		return fmt.Errorf("decode openbao response: %w", err)
	}
	return nil
}
