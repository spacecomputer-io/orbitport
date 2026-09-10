package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/internal/openbao"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxKeyStoreNameLen   = 256
	keyStoreActionImport = "kms.Import"
	keyStoreActionExport = "kms.Export"
	keyStoreActionUnwrap = "kms.Unwrap"
	keyStoreActionList   = "kms.List"
	keyStoreActionDelete = "kms.Delete"
)

var keyStoreSegmentRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func (p *Plugin) Import(ctx context.Context, req *proto.KeyStoreImportRequest) (*proto.KeyStoreImportResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	name, err := normalizeKeyStoreName(req.Name)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	secret, err := decodeKeyStoreSecretJSON(req.SecretJson)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.keyStoreAuthorizer.authorize(req.ClientId, keyStoreActionImport, keyStoreKeyType, name, ""); err != nil {
		return nil, err
	}

	version, err := p.client.putKeyStoreSecret(ctx, req.ClientId, name, secret, p.now().UTC())
	if err != nil {
		return nil, keyStoreOpenBaoStatus(err, "key-store key not found")
	}
	logger.Debugf("key-store import completed name=%s owner=%s version=%d", name, tenantNamespace(req.ClientId), version)
	return &proto.KeyStoreImportResponse{Name: name, Version: version}, nil
}

func (p *Plugin) Export(ctx context.Context, req *proto.KeyStoreExportRequest) (*proto.KeyStoreExportResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	name, err := normalizeKeyStoreName(req.Name)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	ttlSeconds, err := p.keyStoreWrapTTL(req.WrapTtlSeconds)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.keyStoreAuthorizer.authorize(req.ClientId, keyStoreActionExport, keyStoreKeyType, name, ""); err != nil {
		return nil, err
	}

	wrapInfo, err := p.client.wrapKeyStoreSecret(ctx, req.ClientId, name, ttlSeconds)
	if err != nil {
		return nil, keyStoreOpenBaoStatus(err, "key-store key not found")
	}
	expiresAt := keyStoreTokenExpiry(wrapInfo.CreationTime, wrapInfo.TTLSeconds, p.now)
	logger.Debugf("key-store export completed name=%s owner=%s ttl_seconds=%d", name, tenantNamespace(req.ClientId), wrapInfo.TTLSeconds)
	return &proto.KeyStoreExportResponse{
		Name:       name,
		WrapToken:  wrapInfo.Token,
		TtlSeconds: uint32(wrapInfo.TTLSeconds),
		ExpiresAt:  expiresAt,
	}, nil
}

func (p *Plugin) Unwrap(ctx context.Context, req *proto.KeyStoreUnwrapRequest) (*proto.KeyStoreUnwrapResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	name, err := normalizeKeyStoreName(req.Name)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	wrapToken := strings.TrimSpace(req.WrapToken)
	if wrapToken == "" {
		return nil, status.Error(codes.InvalidArgument, "WrapToken is required")
	}
	if err := p.keyStoreAuthorizer.authorize(req.ClientId, keyStoreActionUnwrap, keyStoreKeyType, name, ""); err != nil {
		return nil, err
	}

	lookup, err := p.client.lookupWrappingToken(ctx, wrapToken)
	if err != nil {
		return nil, keyStoreOpenBaoStatus(err, "wrap token is invalid or expired")
	}
	expectedPath := normalizeOpenBaoCreationPath(p.client.keyStoreCreationPath(req.ClientId, name))
	actualPath := normalizeOpenBaoCreationPath(lookup.CreationPath)
	if actualPath != expectedPath {
		logger.Warnf("key-store unwrap rejected path mismatch owner=%s expected=%s actual=%s", tenantNamespace(req.ClientId), expectedPath, actualPath)
		return nil, status.Error(codes.PermissionDenied, "wrap token does not belong to the requested key")
	}

	record, err := p.client.unwrapKeyStoreSecret(ctx, wrapToken)
	if err != nil {
		return nil, keyStoreOpenBaoStatus(err, "wrap token is invalid or expired")
	}
	if record == nil || record.Owner != tenantNamespace(req.ClientId) || record.Name != name || record.Secret == nil {
		logger.Warnf("key-store unwrap rejected invalid wrapped payload owner=%s name=%s", tenantNamespace(req.ClientId), name)
		return nil, status.Error(codes.PermissionDenied, "wrap token payload does not belong to the requested key")
	}
	secretJSON, err := encodeKeyStoreSecretJSON(record.Secret)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	logger.Debugf("key-store unwrap completed name=%s owner=%s", name, tenantNamespace(req.ClientId))
	return &proto.KeyStoreUnwrapResponse{Name: name, SecretJson: secretJSON}, nil
}

func (p *Plugin) List(ctx context.Context, req *proto.KeyStoreListRequest) (*proto.KeyStoreListResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	prefix, err := normalizeKeyStorePrefix(optionalString(req.Prefix))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.keyStoreAuthorizer.authorize(req.ClientId, keyStoreActionList, keyStoreNamespaceType, "", prefix); err != nil {
		return nil, err
	}

	names, err := p.client.listKeyStoreSecrets(ctx, req.ClientId, prefix)
	if err != nil {
		return nil, keyStoreOpenBaoStatus(err, "key-store namespace not found")
	}
	logger.Debugf("key-store list completed owner=%s prefix=%q count=%d", tenantNamespace(req.ClientId), prefix, len(names))
	return &proto.KeyStoreListResponse{Names: names}, nil
}

func (p *Plugin) Delete(ctx context.Context, req *proto.KeyStoreDeleteRequest) (*proto.KeyStoreDeleteResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	name, err := normalizeKeyStoreName(req.Name)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.keyStoreAuthorizer.authorize(req.ClientId, keyStoreActionDelete, keyStoreKeyType, name, ""); err != nil {
		return nil, err
	}

	if err := p.client.deleteKeyStoreSecret(ctx, req.ClientId, name); err != nil {
		return nil, keyStoreOpenBaoStatus(err, "key-store key not found")
	}
	logger.Debugf("key-store delete completed name=%s owner=%s", name, tenantNamespace(req.ClientId))
	return &proto.KeyStoreDeleteResponse{Name: name, Deleted: true}, nil
}

func (p *Plugin) keyStoreWrapTTL(requested *uint32) (int, error) {
	ttlSeconds := p.keyStoreWrapTTLSeconds
	if requested != nil {
		ttlSeconds = int(*requested)
	}
	if ttlSeconds <= 0 {
		return 0, fmt.Errorf("wrap_ttl_seconds must be greater than 0")
	}
	if ttlSeconds > p.keyStoreMaxTTLSeconds {
		return 0, fmt.Errorf("wrap_ttl_seconds must be at most %d", p.keyStoreMaxTTLSeconds)
	}
	return ttlSeconds, nil
}

func normalizeKeyStoreName(value string) (string, error) {
	name := strings.TrimSpace(value)
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if len(name) > maxKeyStoreNameLen {
		return "", fmt.Errorf("name must be at most %d characters", maxKeyStoreNameLen)
	}
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
		return "", fmt.Errorf("name must not start or end with /")
	}
	for _, segment := range strings.Split(name, "/") {
		if err := validateKeyStoreSegment("name", segment); err != nil {
			return "", err
		}
	}
	return name, nil
}

func normalizeKeyStorePrefix(value string) (string, error) {
	prefix := strings.Trim(strings.TrimSpace(value), "/")
	if prefix == "" {
		return "", nil
	}
	if len(prefix) > maxKeyStoreNameLen {
		return "", fmt.Errorf("prefix must be at most %d characters", maxKeyStoreNameLen)
	}
	for _, segment := range strings.Split(prefix, "/") {
		if err := validateKeyStoreSegment("prefix", segment); err != nil {
			return "", err
		}
	}
	return prefix, nil
}

func validateKeyStoreSegment(fieldName, segment string) error {
	if segment == "" || segment == "." || segment == ".." {
		return fmt.Errorf("%s contains an invalid path segment", fieldName)
	}
	if !keyStoreSegmentRe.MatchString(segment) {
		return fmt.Errorf("%s contains unsupported characters", fieldName)
	}
	return nil
}

func decodeKeyStoreSecretJSON(value string) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader([]byte(value)))
	decoder.UseNumber()
	secret := map[string]any{}
	if err := decoder.Decode(&secret); err != nil {
		return nil, fmt.Errorf("secret must be a JSON object: %w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("secret must be a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("secret must contain exactly one JSON object")
	}
	return secret, nil
}

func encodeKeyStoreSecretJSON(value map[string]any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode key-store secret: %w", err)
	}
	return string(encoded), nil
}

func keyStoreTokenExpiry(creationTime string, ttlSeconds int, now func() time.Time) string {
	createdAt, err := time.Parse(time.RFC3339Nano, creationTime)
	if err != nil {
		createdAt = now().UTC()
	}
	return createdAt.UTC().Add(time.Duration(ttlSeconds) * time.Second).Format(time.RFC3339)
}

func keyStoreOpenBaoStatus(err error, notFoundMessage string) error {
	var statusErr *openbao.StatusError
	if errors.As(err, &statusErr) {
		switch statusErr.StatusCode {
		case http.StatusNotFound:
			return status.Error(codes.NotFound, notFoundMessage)
		case http.StatusBadRequest, http.StatusForbidden:
			if strings.HasPrefix(notFoundMessage, "wrap token ") {
				return status.Error(codes.PermissionDenied, notFoundMessage)
			}
			return status.Error(codes.PermissionDenied, "key-store request denied by OpenBao")
		default:
			return status.Error(codes.Internal, err.Error())
		}
	}
	return status.Error(codes.Internal, err.Error())
}
