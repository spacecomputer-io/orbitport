package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

const (
	tenantNamespacePrefix = "tenant_"
	legacyNamespaceBytes  = 8
	currentNamespaceBytes = 16
	defaultKVMount        = "secret"
	defaultTimeoutSecs    = 10
	defaultTransitScheme  = "TRANSIT"
	defaultTimeoutEnvVar  = "ORBITPORT_KMS_TIMEOUT_SECS"
	openBaoProxyURLEnvVar = "ORBITPORT_KMS_OPENBAO_PROXY_URL"
	kvMountEnvVar         = "ORBITPORT_KMS_KV_MOUNT"
)

type migrationConfig struct {
	OpenBaoProxyURL string
	KVMount         string
	TimeoutSecs     int
}

type migrationOptions struct {
	Apply  bool
	Writer io.Writer
}

type migrationReport struct {
	LegacyNamespaces int
	RecordsScanned   int
	RecordsPlanned   int
	RecordsCopied    int
	RecordsSkipped   int
}

type openBaoClient struct {
	baseURL    string
	httpClient *http.Client
	kvMount    string
}

type openBaoStatusError struct {
	statusCode int
	status     string
}

func (e *openBaoStatusError) Error() string {
	return fmt.Sprintf("openbao returned %s", e.status)
}

func main() {
	cfg, opts, err := parseConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "kms-migrate-tenant-metadata: %v\n", err)
		os.Exit(2)
	}

	report, err := runMigration(context.Background(), cfg, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kms-migrate-tenant-metadata: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(
		os.Stdout,
		"done legacy_namespaces=%d records_scanned=%d records_planned=%d records_copied=%d records_skipped=%d\n",
		report.LegacyNamespaces,
		report.RecordsScanned,
		report.RecordsPlanned,
		report.RecordsCopied,
		report.RecordsSkipped,
	)
}

func parseConfig(args []string) (migrationConfig, migrationOptions, error) {
	fs := flag.NewFlagSet("kms_migrate_tenant_metadata", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		apply   bool
		envFile string
	)
	fs.BoolVar(&apply, "apply", false, "write migrated metadata to the 16-byte tenant namespace")
	fs.StringVar(&envFile, "e", "", "optional env file to load before reading ORBITPORT_KMS_* settings")
	if err := fs.Parse(args); err != nil {
		return migrationConfig{}, migrationOptions{}, err
	}

	if envFile != "" {
		if err := godotenv.Load(envFile); err != nil {
			return migrationConfig{}, migrationOptions{}, fmt.Errorf("load env file %s: %w", envFile, err)
		}
	}

	timeoutSecs := defaultTimeoutSecs
	if raw := strings.TrimSpace(os.Getenv(defaultTimeoutEnvVar)); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return migrationConfig{}, migrationOptions{}, fmt.Errorf("parse %s: %w", defaultTimeoutEnvVar, err)
		}
		timeoutSecs = parsed
	}

	cfg := migrationConfig{
		OpenBaoProxyURL: strings.TrimSpace(os.Getenv(openBaoProxyURLEnvVar)),
		KVMount:         strings.TrimSpace(os.Getenv(kvMountEnvVar)),
		TimeoutSecs:     timeoutSecs,
	}
	if cfg.OpenBaoProxyURL == "" {
		return migrationConfig{}, migrationOptions{}, fmt.Errorf("%s is required", openBaoProxyURLEnvVar)
	}
	if cfg.KVMount == "" {
		cfg.KVMount = defaultKVMount
	}

	return cfg, migrationOptions{
		Apply:  apply,
		Writer: os.Stdout,
	}, nil
}

func runMigration(ctx context.Context, cfg migrationConfig, opts migrationOptions) (*migrationReport, error) {
	if opts.Writer == nil {
		opts.Writer = io.Discard
	}

	client := &openBaoClient{
		baseURL: strings.TrimRight(cfg.OpenBaoProxyURL, "/"),
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSecs) * time.Second,
		},
		kvMount: cfg.KVMount,
	}

	namespaces, err := client.listMetadataNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("list KMS tenant namespaces: %w", err)
	}

	legacyNamespaces := legacyMetadataNamespaces(namespaces)
	sort.Strings(legacyNamespaces)

	report := &migrationReport{LegacyNamespaces: len(legacyNamespaces)}
	if _, err := fmt.Fprintf(opts.Writer, "mode=%s legacy_namespaces=%d\n", migrationMode(opts.Apply), report.LegacyNamespaces); err != nil {
		return nil, err
	}

	for _, legacyNamespace := range legacyNamespaces {
		keyIDs, err := client.listMetadataKeys(ctx, "kms", "metadata", legacyNamespace)
		if err != nil {
			return report, fmt.Errorf("list legacy metadata keys for namespace %s: %w", legacyNamespace, err)
		}
		sort.Strings(keyIDs)

		for _, listedKeyID := range keyIDs {
			if strings.HasSuffix(listedKeyID, "/") {
				continue
			}

			keyID := normalizeListedKeyID(listedKeyID)
			report.RecordsScanned++

			record, err := client.getMetadataForNamespace(ctx, legacyNamespace, keyID)
			if err != nil {
				return report, fmt.Errorf("read legacy metadata for namespace %s key_id %s: %w", legacyNamespace, keyID, err)
			}
			if err := validateRecord(record, keyID); err != nil {
				return report, fmt.Errorf("invalid legacy metadata for namespace %s key_id %s: %w", legacyNamespace, keyID, err)
			}

			targetNamespace := tenantNamespace(recordClientID(record))
			existing, err := client.getMetadataForNamespace(ctx, targetNamespace, keyID)
			switch {
			case err == nil:
				if !recordsEqual(existing, record, keyID) {
					return report, fmt.Errorf("target metadata already exists with different contents for namespace %s key_id %s", targetNamespace, keyID)
				}
				report.RecordsSkipped++
				if _, err := fmt.Fprintf(opts.Writer, "skip namespace=%s key_id=%s target=%s reason=already-migrated\n", legacyNamespace, keyID, targetNamespace); err != nil {
					return nil, err
				}
				continue
			default:
				if !isMetadataNotFound(err) {
					return report, fmt.Errorf("read target metadata for namespace %s key_id %s: %w", targetNamespace, keyID, err)
				}
			}

			report.RecordsPlanned++
			if !opts.Apply {
				if _, err := fmt.Fprintf(opts.Writer, "plan copy namespace=%s key_id=%s target=%s provider_key=%s\n", legacyNamespace, keyID, targetNamespace, recordBackendKey(record)); err != nil {
					return nil, err
				}
				continue
			}

			if err := client.putMetadataForNamespace(ctx, targetNamespace, keyID, record); err != nil {
				return report, fmt.Errorf("write migrated metadata for namespace %s key_id %s: %w", targetNamespace, keyID, err)
			}
			report.RecordsCopied++
			if _, err := fmt.Fprintf(opts.Writer, "copied namespace=%s key_id=%s target=%s provider_key=%s\n", legacyNamespace, keyID, targetNamespace, recordBackendKey(record)); err != nil {
				return nil, err
			}
		}
	}

	if _, err := fmt.Fprintf(
		opts.Writer,
		"summary mode=%s legacy_namespaces=%d records_scanned=%d records_planned=%d records_copied=%d records_skipped=%d\n",
		migrationMode(opts.Apply),
		report.LegacyNamespaces,
		report.RecordsScanned,
		report.RecordsPlanned,
		report.RecordsCopied,
		report.RecordsSkipped,
	); err != nil {
		return nil, err
	}

	return report, nil
}

func migrationMode(apply bool) string {
	if apply {
		return "apply"
	}
	return "dry-run"
}

func legacyMetadataNamespaces(namespaces []string) []string {
	legacy := make([]string, 0, len(namespaces))
	for _, namespace := range namespaces {
		namespace = strings.TrimSuffix(strings.TrimSpace(namespace), "/")
		if namespace == "" || !strings.HasPrefix(namespace, tenantNamespacePrefix) {
			continue
		}
		hashSuffix := strings.TrimPrefix(namespace, tenantNamespacePrefix)
		if len(hashSuffix) != legacyNamespaceBytes*2 {
			continue
		}
		if _, err := hex.DecodeString(hashSuffix); err != nil {
			continue
		}
		legacy = append(legacy, namespace)
	}
	return legacy
}

func tenantNamespace(clientID string) string {
	return tenantNamespaceForBytes(clientID, currentNamespaceBytes)
}

func tenantNamespaceForBytes(clientID string, size int) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(clientID)))
	if size > len(sum) {
		size = len(sum)
	}
	return tenantNamespacePrefix + hex.EncodeToString(sum[:size])
}

func normalizeListedKeyID(keyID string) string {
	trimmed := strings.TrimSpace(keyID)
	unescaped, err := url.PathUnescape(trimmed)
	if err == nil {
		return unescaped
	}
	return trimmed
}

func validateRecord(record map[string]any, listedKeyID string) error {
	if record == nil {
		return fmt.Errorf("metadata record is missing")
	}
	if strings.TrimSpace(recordClientID(record)) == "" {
		return fmt.Errorf("metadata record is missing client_id")
	}
	if strings.TrimSpace(recordKeyID(record)) == "" {
		record["key_id"] = listedKeyID
	}
	if recordKeyID(record) != listedKeyID {
		return fmt.Errorf("metadata record key_id %q does not match path key_id %q", recordKeyID(record), listedKeyID)
	}
	if strings.TrimSpace(recordBackendKey(record)) == "" {
		return fmt.Errorf("metadata record is missing provider_key")
	}
	return nil
}

func recordClientID(record map[string]any) string {
	return stringField(record, "client_id")
}

func recordKeyID(record map[string]any) string {
	return stringField(record, "key_id")
}

func recordBackendKey(record map[string]any) string {
	if providerKey := stringField(record, "provider_key"); providerKey != "" {
		return providerKey
	}
	return stringField(record, "transit_key")
}

func stringField(record map[string]any, key string) string {
	value, ok := record[key]
	if !ok {
		return ""
	}
	str, ok := value.(string)
	if !ok {
		return ""
	}
	return str
}

func recordsEqual(left, right map[string]any, keyID string) bool {
	return bytes.Equal(canonicalRecordJSON(left, keyID), canonicalRecordJSON(right, keyID))
}

func canonicalRecordJSON(record map[string]any, keyID string) []byte {
	clone := cloneRecord(record)
	if clone == nil {
		return nil
	}
	if stringField(clone, "scheme") == "" {
		clone["scheme"] = defaultTransitScheme
	}
	if stringField(clone, "provider_key") == "" && stringField(clone, "transit_key") != "" {
		clone["provider_key"] = stringField(clone, "transit_key")
	}
	if stringField(clone, "key_id") == "" {
		clone["key_id"] = keyID
	}
	if tags, ok := clone["tags"]; !ok || tags == nil {
		clone["tags"] = []any{}
	}
	raw, _ := json.Marshal(clone)
	return raw
}

func cloneRecord(record map[string]any) map[string]any {
	if record == nil {
		return nil
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return nil
	}
	var clone map[string]any
	if err := json.Unmarshal(raw, &clone); err != nil {
		return nil
	}
	return clone
}

func isMetadataNotFound(err error) bool {
	if err == nil {
		return false
	}
	var statusErr *openBaoStatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	return statusErr.statusCode == http.StatusNotFound
}

func (c *openBaoClient) listMetadataNamespaces(ctx context.Context) ([]string, error) {
	return c.listMetadataKeys(ctx, "kms", "metadata")
}

func (c *openBaoClient) listMetadataKeys(ctx context.Context, parts ...string) ([]string, error) {
	var resp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}

	req, err := http.NewRequestWithContext(ctx, "LIST", c.kvMetadataPath(parts...), nil)
	if err != nil {
		return nil, fmt.Errorf("create openbao request: %w", err)
	}
	if err := c.do(req, &resp); err != nil {
		if isMetadataNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return resp.Data.Keys, nil
}

func (c *openBaoClient) getMetadataForNamespace(ctx context.Context, namespace, keyID string) (map[string]any, error) {
	var resp struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := c.get(ctx, c.kvDataPath("kms", "metadata", namespace, url.PathEscape(keyID)), &resp); err != nil {
		return nil, err
	}
	return resp.Data.Data, nil
}

func (c *openBaoClient) putMetadataForNamespace(ctx context.Context, namespace, keyID string, record map[string]any) error {
	return c.post(ctx, c.kvDataPath("kms", "metadata", namespace, url.PathEscape(keyID)), map[string]any{
		"data": record,
	}, nil)
}

func (c *openBaoClient) kvDataPath(parts ...string) string {
	all := append([]string{"v1", c.kvMount, "data"}, parts...)
	return c.joinPath(all...)
}

func (c *openBaoClient) kvMetadataPath(parts ...string) string {
	all := append([]string{"v1", c.kvMount, "metadata"}, parts...)
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
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("openbao request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read openbao response: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return &openBaoStatusError{
			statusCode: resp.StatusCode,
			status:     resp.Status,
		}
	}
	if into == nil {
		return nil
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("decode openbao response: %w", err)
	}
	return nil
}
