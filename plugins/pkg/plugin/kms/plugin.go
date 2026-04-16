package kms

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Plugin struct {
	proto.UnimplementedKmsPluginServer

	client    *openBaoClient
	now       func() time.Time
	providers map[string]kmsProvider
}

var uuidNewString = uuid.NewString
var logger = utils.GetLogger("orbitport:kms")

func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()
	if cfg.OpenBaoProxyURL == "" {
		return nil, fmt.Errorf("ORBITPORT_KMS_OPENBAO_PROXY_URL is required")
	}
	logger.Infof(
		"creating KMS plugin with proxy url=%s, transit mount=%s, kv mount=%s, ethereum mount=%s",
		cfg.OpenBaoProxyURL,
		cfg.TransitMount,
		cfg.KVMount,
		cfg.EthereumMount,
	)
	return newPlugin(cfg, newOpenBaoClient(cfg)), nil
}

func newPlugin(cfg *kmsConfig, client *openBaoClient) *Plugin {
	_ = cfg
	return &Plugin{
		client: client,
		now:    time.Now,
		providers: map[string]kmsProvider{
			schemeTransit:  newTransitProvider(client),
			schemeEthereum: newEthereumProvider(client),
		},
	}
}

func (p *Plugin) Encrypt(ctx context.Context, req *proto.EncryptRequest) (*proto.EncryptResponse, error) {
	logger.Debugf("Encrypt request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.KeyId)
	if err != nil {
		logger.Warnf("Encrypt failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	resp, err := provider.Encrypt(ctx, metadata, req)
	if err != nil {
		logger.Warnf("Encrypt failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	logger.Debugf("Encrypt completed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
	return resp, nil
}

func (p *Plugin) Decrypt(ctx context.Context, req *proto.DecryptRequest) (*proto.DecryptResponse, error) {
	blob, err := decodeCiphertextBlob(req.CiphertextBlob)
	if err != nil {
		logger.Warn("Decrypt rejected invalid ciphertext blob")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	logger.Debugf("Decrypt request received for key_id=%s scheme=%s", blob.KeyID, blob.Scheme)
	if req.KeyId != nil && *req.KeyId != blob.KeyID {
		logger.Warnf("Decrypt rejected mismatched key id: request=%s blob=%s", *req.KeyId, blob.KeyID)
		return nil, status.Error(codes.InvalidArgument, "KeyId does not match CiphertextBlob")
	}

	provider, err := p.providerForScheme(blob.Scheme)
	if err != nil {
		logger.Warnf("Decrypt failed to resolve provider for scheme=%s key_id=%s", blob.Scheme, blob.KeyID)
		return nil, err
	}
	resp, err := provider.Decrypt(ctx, blob, req)
	if err != nil {
		logger.Warnf("Decrypt failed for key_id=%s scheme=%s", blob.KeyID, blob.Scheme)
		return nil, err
	}
	logger.Debugf("Decrypt completed for key_id=%s scheme=%s", blob.KeyID, blob.Scheme)
	return resp, nil
}

func (p *Plugin) Sign(ctx context.Context, req *proto.SignRequest) (*proto.SignResponse, error) {
	logger.Debugf(
		"Sign request received for key_id=%s signing_algorithm=%s message_type=%q",
		req.KeyId,
		req.SigningAlgorithm,
		optionalString(req.MessageType),
	)
	metadata, provider, err := p.metadataProvider(ctx, req.KeyId)
	if err != nil {
		logger.Warnf("Sign failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	resp, err := provider.Sign(ctx, metadata, req)
	if err != nil {
		logger.Warnf("Sign failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	logger.Debugf("Sign completed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
	return resp, nil
}

func (p *Plugin) CreateKey(ctx context.Context, req *proto.CreateKeyRequest) (*proto.CreateKeyResponse, error) {
	scheme, err := normalizeScheme(optionalString(req.Scheme))
	if err != nil {
		logger.Warnf("CreateKey rejected unsupported scheme=%q", optionalString(req.Scheme))
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	logger.Infof(
		"CreateKey request received scheme=%s key_spec=%s key_usage=%s tags=%d",
		scheme,
		req.KeySpec,
		req.KeyUsage,
		len(req.Tags),
	)

	provider, err := p.providerForScheme(scheme)
	if err != nil {
		logger.Warnf("CreateKey failed to resolve provider for scheme=%s", scheme)
		return nil, err
	}

	keyID := fmt.Sprintf("kms:%s", uuidNewString())
	record, err := provider.CreateKey(ctx, req, keyID, p.now().UTC())
	if err != nil {
		logger.Warnf("CreateKey failed for key_id=%s scheme=%s", keyID, scheme)
		return nil, err
	}

	record.normalize()
	if err := p.client.putMetadata(ctx, keyID, record); err != nil {
		logger.Warnf("CreateKey failed to persist metadata for key_id=%s scheme=%s", keyID, scheme)
		return nil, status.Error(codes.Internal, err.Error())
	}
	logger.Infof("CreateKey completed key_id=%s scheme=%s", keyID, scheme)

	return &proto.CreateKeyResponse{
		KeyMetadata: toProtoMetadata(record),
	}, nil
}

func (p *Plugin) GenerateDataKey(ctx context.Context, req *proto.GenerateDataKeyRequest) (*proto.GenerateDataKeyResponse, error) {
	logger.Debugf("GenerateDataKey request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.KeyId)
	if err != nil {
		logger.Warnf("GenerateDataKey failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	resp, err := provider.GenerateDataKey(ctx, metadata, req)
	if err != nil {
		logger.Warnf("GenerateDataKey failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	logger.Debugf("GenerateDataKey completed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
	return resp, nil
}

func (p *Plugin) RotateKey(ctx context.Context, req *proto.RotateKeyRequest) (*proto.RotateKeyResponse, error) {
	logger.Infof("RotateKey request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.KeyId)
	if err != nil {
		logger.Warnf("RotateKey failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}

	updated, err := provider.RotateKey(ctx, metadata)
	if err != nil {
		logger.Warnf("RotateKey failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	updated.normalize()
	if err := p.client.putMetadata(ctx, updated.KeyID, updated); err != nil {
		logger.Warnf("RotateKey failed to persist metadata for key_id=%s", updated.KeyID)
		return nil, status.Error(codes.Internal, err.Error())
	}
	logger.Infof(
		"RotateKey completed for key_id=%s scheme=%s primary_version=%d",
		updated.KeyID,
		updated.Scheme,
		updated.PrimaryVersion,
	)

	return &proto.RotateKeyResponse{
		KeyMetadata: toProtoMetadata(updated),
	}, nil
}

func (p *Plugin) metadataProvider(ctx context.Context, keyID string) (*keyMetadataRecord, kmsProvider, error) {
	metadata, err := p.client.getMetadata(ctx, keyID)
	if err != nil {
		logger.Warnf("failed to fetch KMS metadata for key_id=%s", keyID)
		return nil, nil, status.Error(codes.Internal, err.Error())
	}

	provider, err := p.providerForScheme(metadata.Scheme)
	if err != nil {
		logger.Warnf("failed to resolve provider for key_id=%s scheme=%s", keyID, metadata.Scheme)
		return nil, nil, err
	}
	return metadata, provider, nil
}

func (p *Plugin) providerForScheme(scheme string) (kmsProvider, error) {
	normalized, err := normalizeScheme(scheme)
	if err != nil {
		logger.Warnf("unsupported KMS scheme=%q", scheme)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	provider, ok := p.providers[normalized]
	if !ok {
		logger.Warnf("no provider registered for KMS scheme=%q", normalized)
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("unsupported Scheme %q", normalized))
	}
	return provider, nil
}

func toRecordTags(tags []*proto.Tag) []*pluginTag {
	result := make([]*pluginTag, 0, len(tags))
	for _, tag := range tags {
		result = append(result, &pluginTag{
			TagKey:   tag.TagKey,
			TagValue: tag.TagValue,
		})
	}
	return result
}

func toProtoTags(tags []*pluginTag) []*proto.Tag {
	result := make([]*proto.Tag, 0, len(tags))
	for _, tag := range tags {
		result = append(result, &proto.Tag{
			TagKey:   tag.TagKey,
			TagValue: tag.TagValue,
		})
	}
	return result
}

func toProtoMetadata(record *keyMetadataRecord) *proto.KeyMetadata {
	record.normalize()

	metadata := &proto.KeyMetadata{
		KeyId:          record.KeyID,
		Description:    record.Description,
		KeySpec:        record.KeySpec,
		KeyUsage:       record.KeyUsage,
		Enabled:        record.Enabled,
		PrimaryVersion: record.PrimaryVersion,
		CreationDate:   record.CreatedAt,
		Scheme:         record.Scheme,
		Tags:           toProtoTags(record.Tags),
	}
	if record.PublicKey != "" {
		metadata.PublicKey = &record.PublicKey
	}
	if record.Address != "" {
		metadata.Address = &record.Address
	}
	return metadata
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func optionalUint32(value *uint32) uint32 {
	if value == nil {
		return 0
	}
	return *value
}
