package kms

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/internal/openbao"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	keyStateEnabled         = "ENABLED"
	keyStateDisabled        = "DISABLED"
	keyStatePendingDeletion = "PENDING_DELETION"
	defaultListKeysLimit    = 100
	maxListKeysLimit        = 1000
	defaultDeletionWindow   = 30
)

func isMetadataCASConflict(err error) bool {
	var backend *openbao.StatusError
	return errors.As(err, &backend) && backend.StatusCode == http.StatusBadRequest &&
		strings.Contains(backend.Body, "check-and-set")
}

func kmsBackendStatus(operation string, err error) error {
	var backend *openbao.StatusError
	if errors.As(err, &backend) {
		logger.Warnf("KMS %s backend status=%d body=%s", operation, backend.StatusCode, backend.Body)
		if isMetadataCASConflict(err) {
			return status.Error(codes.Aborted, "key changed concurrently; check its state before retrying")
		}
	} else {
		logger.Warnf("KMS %s backend failure: %v", operation, err)
	}
	return status.Error(codes.Internal, "KMS backend error")
}

func validLifecycleState(record *keyMetadataRecord) bool {
	switch record.KeyState {
	case keyStateEnabled:
		return record.Enabled && record.DeletionDate == "" && record.DeletionIndex == "" && record.DeletionStartedAt == ""
	case keyStateDisabled:
		return !record.Enabled && record.DeletionDate == "" && record.DeletionIndex == "" && record.DeletionStartedAt == ""
	case keyStatePendingDeletion:
		date, err := time.Parse(time.RFC3339, record.DeletionDate)
		keyID, deadline, indexErr := parseDeletionEntry(record.DeletionIndex)
		if record.DeletionStartedAt != "" {
			if _, claimErr := time.Parse(time.RFC3339, record.DeletionStartedAt); claimErr != nil {
				return false
			}
		}
		return !record.Enabled && err == nil && indexErr == nil &&
			keyID == record.KeyID && deadline.Equal(date)
	default:
		return false
	}
}

func requireUsableKey(record *keyMetadataRecord) error {
	if record.Scheme != schemeTransit {
		return nil
	}
	if !validLifecycleState(record) {
		return status.Error(codes.FailedPrecondition, "key lifecycle metadata is invalid")
	}
	switch record.KeyState {
	case keyStateDisabled:
		return status.Error(codes.FailedPrecondition, "key is disabled")
	case keyStatePendingDeletion:
		return status.Error(codes.FailedPrecondition, "key is pending deletion")
	default:
		return nil
	}
}

func (p *Plugin) lifecycleMetadata(ctx context.Context, clientID, keyID string) (*keyMetadataRecord, error) {
	if err := requireClientID(clientID); err != nil {
		return nil, err
	}
	resolved, err := p.resolveKeyID(keyID)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	record, err := p.client.getMetadata(ctx, clientID, resolved)
	if err != nil {
		var backend *openbao.StatusError
		if errors.As(err, &backend) && backend.StatusCode == http.StatusNotFound {
			return nil, status.Error(codes.PermissionDenied, "key does not belong to the authenticated client")
		}
		return nil, kmsBackendStatus("read lifecycle metadata", err)
	}
	if record.KeyID != resolved || record.kvVersion == 0 || !validLifecycleState(record) {
		return nil, status.Error(codes.FailedPrecondition, "key lifecycle metadata is invalid")
	}
	if record.Scheme != schemeTransit {
		return nil, status.Error(codes.Unimplemented, "key lifecycle operations support TRANSIT only")
	}
	expectedBackend, err := scopedBackendKey(clientID, strings.TrimPrefix(resolved, "kms:"))
	if err != nil || record.backendKey() != expectedBackend {
		return nil, status.Error(codes.FailedPrecondition, "key lifecycle metadata is invalid")
	}
	// Legacy records may omit the owner; the tenant-scoped lookup established it.
	record.ClientID = clientID
	return record, nil
}

func (p *Plugin) setKeyEnabled(ctx context.Context, clientID, keyID string, enabled bool) (*proto.KeyMetadata, error) {
	record, err := p.lifecycleMetadata(ctx, clientID, keyID)
	if err != nil {
		return nil, err
	}
	if record.KeyState == keyStatePendingDeletion {
		return nil, status.Error(codes.FailedPrecondition, "key is pending deletion; call kms.CancelKeyDeletion first")
	}
	if record.Enabled == enabled {
		return toProtoMetadata(record), nil
	}
	record.Enabled = enabled
	record.KeyState = keyStateDisabled
	if enabled {
		record.KeyState = keyStateEnabled
	}
	if err := p.client.putMetadata(ctx, clientID, record.KeyID, record); err != nil {
		return nil, kmsBackendStatus("set key state", err)
	}
	return toProtoMetadata(record), nil
}

func (p *Plugin) DisableKey(ctx context.Context, req *proto.DisableKeyRequest) (*proto.DisableKeyResponse, error) {
	record, err := p.setKeyEnabled(ctx, req.ClientId, req.KeyId, false)
	if err != nil {
		return nil, err
	}
	return &proto.DisableKeyResponse{KeyMetadata: record}, nil
}

func (p *Plugin) EnableKey(ctx context.Context, req *proto.EnableKeyRequest) (*proto.EnableKeyResponse, error) {
	record, err := p.setKeyEnabled(ctx, req.ClientId, req.KeyId, true)
	if err != nil {
		return nil, err
	}
	return &proto.EnableKeyResponse{KeyMetadata: record}, nil
}

func (p *Plugin) ScheduleKeyDeletion(ctx context.Context, req *proto.ScheduleKeyDeletionRequest) (*proto.ScheduleKeyDeletionResponse, error) {
	window := uint32(defaultDeletionWindow)
	if req.PendingWindowInDays != nil {
		window = *req.PendingWindowInDays
	}
	if window < 7 || window > 30 {
		return nil, status.Error(codes.InvalidArgument, "PendingWindowInDays must be between 7 and 30")
	}
	record, err := p.lifecycleMetadata(ctx, req.ClientId, req.KeyId)
	if err != nil {
		return nil, err
	}
	if record.KeyState == keyStatePendingDeletion {
		return nil, status.Error(codes.FailedPrecondition, "key is already pending deletion")
	}
	deadline := p.now().UTC().Truncate(time.Second).Add(time.Duration(window) * 24 * time.Hour)
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, status.Error(codes.Internal, "could not schedule key deletion")
	}
	entry := record.KeyID + "_" + deadline.Format("20060102T150405Z") + "_" + hex.EncodeToString(nonce[:])
	record.DeletionDate = deadline.Format(time.RFC3339)
	record.DeletionIndex = entry
	record.Enabled = false
	record.KeyState = keyStatePendingDeletion
	if err := p.client.putDeletionEntry(ctx, tenantNamespace(req.ClientId), entry, record); err != nil {
		return nil, kmsBackendStatus("schedule deletion index", err)
	}
	// Keep the index on any error: an interrupted write may have committed.
	if err := p.client.putMetadata(ctx, req.ClientId, record.KeyID, record); err != nil {
		return nil, kmsBackendStatus("schedule key deletion", err)
	}
	return &proto.ScheduleKeyDeletionResponse{KeyMetadata: toProtoMetadata(record), PendingWindowInDays: window}, nil
}

func (p *Plugin) CancelKeyDeletion(ctx context.Context, req *proto.CancelKeyDeletionRequest) (*proto.CancelKeyDeletionResponse, error) {
	record, err := p.lifecycleMetadata(ctx, req.ClientId, req.KeyId)
	if err != nil {
		return nil, err
	}
	if record.KeyState != keyStatePendingDeletion {
		return nil, status.Error(codes.FailedPrecondition, "key is not pending deletion")
	}
	deadline, _ := time.Parse(time.RFC3339, record.DeletionDate)
	if !p.now().UTC().Before(deadline) {
		return nil, status.Error(codes.FailedPrecondition, "deletion date has passed")
	}
	if record.DeletionStartedAt != "" {
		return nil, status.Error(codes.FailedPrecondition, "deletion in progress")
	}
	entry := record.DeletionIndex
	record.KeyState, record.Enabled = keyStateDisabled, false
	record.DeletionDate, record.DeletionIndex = "", ""
	if err := p.client.putMetadata(ctx, req.ClientId, record.KeyID, record); err != nil {
		return nil, kmsBackendStatus("cancel key deletion", err)
	}
	if err := p.client.deleteDeletionEntry(ctx, tenantNamespace(req.ClientId), entry); err != nil {
		logger.Warnf("could not clean cancelled deletion entry tenant=%s key_id=%s: %v", tenantNamespace(req.ClientId), record.KeyID, err)
	}
	return &proto.CancelKeyDeletionResponse{KeyMetadata: toProtoMetadata(record)}, nil
}

type listKeysCursor struct {
	Version int    `json:"v"`
	After   string `json:"after"`
}

func (p *Plugin) ListKeys(ctx context.Context, req *proto.ListKeysRequest) (*proto.ListKeysResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	limit := uint32(defaultListKeysLimit)
	if req.Limit != nil {
		limit = *req.Limit
	}
	if limit < 1 || limit > maxListKeysLimit {
		return nil, status.Error(codes.InvalidArgument, "Limit must be between 1 and 1000")
	}
	after := ""
	if req.NextToken != nil {
		token := strings.TrimSpace(*req.NextToken)
		if len(token) == 0 || len(token) > 512 {
			return nil, status.Error(codes.InvalidArgument, "invalid NextToken")
		}
		var cursor listKeysCursor
		decoded, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || json.Unmarshal(decoded, &cursor) != nil || cursor.Version != 1 || !isCanonicalKeyID(cursor.After) {
			return nil, status.Error(codes.InvalidArgument, "invalid NextToken")
		}
		after = cursor.After
	}
	keys, err := p.client.listKMSMetadata(ctx, tenantNamespace(req.ClientId), "metadata")
	if err != nil {
		return nil, kmsBackendStatus("list keys", err)
	}
	valid := make([]string, 0, len(keys))
	seen := make(map[string]bool, len(keys))
	for _, key := range keys {
		if !isCanonicalKeyID(key) {
			logger.Warnf("skipping unsafe KMS key name tenant=%s key=%q", tenantNamespace(req.ClientId), key)
			continue
		}
		if !seen[key] && key > after {
			valid = append(valid, key)
			seen[key] = true
		}
	}
	sort.Strings(valid)
	response := &proto.ListKeysResponse{KeyIds: valid}
	if len(valid) > int(limit) {
		response.KeyIds = valid[:limit]
		raw, _ := json.Marshal(listKeysCursor{Version: 1, After: response.KeyIds[limit-1]})
		token := base64.RawURLEncoding.EncodeToString(raw)
		response.NextToken = &token
	}
	return response, nil
}

func isCanonicalKeyID(value string) bool {
	keyID, _, err := resolveKeyRef(value)
	return err == nil && keyID == value
}
