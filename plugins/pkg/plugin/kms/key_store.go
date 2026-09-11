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

	"github.com/spacecomputer-io/orbitport/plugins/internal/openbao"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxKeyStoreNameLen   = 256
	keyStoreActionPut    = "kms_keystore.Put"
	keyStoreActionGet    = "kms_keystore.Get"
	keyStoreActionList   = "kms_keystore.List"
	keyStoreActionDelete = "kms_keystore.Delete"
)

var (
	keyStoreSegmentRe           = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	errKeyStoreMaxDepthExceeded = errors.New("key-store maximum depth exceeded")
)

func (p *Plugin) Put(ctx context.Context, req *proto.KeyStorePutRequest) (*proto.KeyStorePutResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	name, err := normalizeKeyStoreName(req.Name, p.keyStoreMaxDepth)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	secret, err := decodeKeyStoreSecretJSON(req.SecretJson)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.keyStoreAuthorizer.authorize(req.ClientId, keyStoreActionPut, keyStoreKeyType, name, ""); err != nil {
		return nil, err
	}

	version, err := p.client.putKeyStoreSecret(ctx, req.ClientId, name, secret, p.now().UTC())
	if err != nil {
		return nil, keyStoreOpenBaoStatus(err, "key-store entry not found")
	}
	logger.Debugf("key-store put completed name=%s owner=%s version=%d", name, tenantNamespace(req.ClientId), version)
	return &proto.KeyStorePutResponse{Name: name, Version: version}, nil
}

func (p *Plugin) Get(ctx context.Context, req *proto.KeyStoreGetRequest) (*proto.KeyStoreGetResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	name, err := normalizeKeyStoreName(req.Name, p.keyStoreMaxDepth)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.keyStoreAuthorizer.authorize(req.ClientId, keyStoreActionGet, keyStoreKeyType, name, ""); err != nil {
		return nil, err
	}

	record, err := p.client.getKeyStoreSecret(ctx, req.ClientId, name)
	if err != nil {
		return nil, keyStoreOpenBaoStatus(err, "key-store entry not found")
	}
	if record == nil || record.Owner != tenantNamespace(req.ClientId) || record.Name != name || record.Secret == nil {
		logger.Warnf("key-store get rejected invalid stored payload owner=%s name=%s", tenantNamespace(req.ClientId), name)
		return nil, status.Error(codes.PermissionDenied, "key-store entry does not belong to the requested key")
	}
	secretJSON, err := encodeKeyStoreSecretJSON(record.Secret)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	logger.Debugf("key-store get completed name=%s owner=%s", name, tenantNamespace(req.ClientId))
	return &proto.KeyStoreGetResponse{Name: name, SecretJson: secretJSON}, nil
}

func (p *Plugin) List(ctx context.Context, req *proto.KeyStoreListRequest) (*proto.KeyStoreListResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	prefix, err := normalizeKeyStorePrefix(optionalString(req.Prefix), p.keyStoreMaxDepth)
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
	name, err := normalizeKeyStoreName(req.Name, p.keyStoreMaxDepth)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.keyStoreAuthorizer.authorize(req.ClientId, keyStoreActionDelete, keyStoreKeyType, name, ""); err != nil {
		return nil, err
	}

	if err := p.client.ensureKeyStoreSecretExists(ctx, req.ClientId, name); err != nil {
		return nil, keyStoreOpenBaoStatus(err, "key-store entry not found")
	}
	if err := p.client.deleteKeyStoreSecret(ctx, req.ClientId, name); err != nil {
		return nil, keyStoreOpenBaoStatus(err, "key-store entry not found")
	}
	logger.Debugf("key-store delete completed name=%s owner=%s", name, tenantNamespace(req.ClientId))
	return &proto.KeyStoreDeleteResponse{Name: name, Deleted: true}, nil
}

func normalizeKeyStoreName(value string, maxDepth int) (string, error) {
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
	segments := strings.Split(name, "/")
	if err := validateKeyStoreDepth("name", len(segments), maxDepth); err != nil {
		return "", err
	}
	for _, segment := range segments {
		if err := validateKeyStoreSegment("name", segment); err != nil {
			return "", err
		}
	}
	return name, nil
}

func normalizeKeyStorePrefix(value string, maxDepth int) (string, error) {
	prefix := strings.Trim(strings.TrimSpace(value), "/")
	if prefix == "" {
		return "", nil
	}
	if len(prefix) > maxKeyStoreNameLen {
		return "", fmt.Errorf("prefix must be at most %d characters", maxKeyStoreNameLen)
	}
	segments := strings.Split(prefix, "/")
	if err := validateKeyStoreDepth("prefix", len(segments), maxDepth); err != nil {
		return "", err
	}
	for _, segment := range segments {
		if err := validateKeyStoreSegment("prefix", segment); err != nil {
			return "", err
		}
	}
	return prefix, nil
}

func validateKeyStoreDepth(fieldName string, depth, maxDepth int) error {
	maxDepth = effectiveKeyStoreMaxDepth(maxDepth)
	if depth > maxDepth {
		return fmt.Errorf("%w: %s must contain at most %d path segments", errKeyStoreMaxDepthExceeded, fieldName, maxDepth)
	}
	return nil
}

func effectiveKeyStoreMaxDepth(maxDepth int) int {
	if maxDepth <= 0 {
		return defaultKMSKeyStoreMaxDepth
	}
	return maxDepth
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

func keyStoreOpenBaoStatus(err error, notFoundMessage string) error {
	if errors.Is(err, errKeyStoreMaxDepthExceeded) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	var statusErr *openbao.StatusError
	if errors.As(err, &statusErr) {
		switch statusErr.StatusCode {
		case http.StatusNotFound:
			return status.Error(codes.NotFound, notFoundMessage)
		case http.StatusBadRequest, http.StatusForbidden:
			return status.Error(codes.PermissionDenied, "key-store request denied by OpenBao")
		default:
			return status.Error(codes.Internal, err.Error())
		}
	}
	return status.Error(codes.Internal, err.Error())
}
