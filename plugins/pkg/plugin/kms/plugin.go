package kms

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
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

func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()
	if cfg.OpenBaoProxyURL == "" {
		return nil, fmt.Errorf("ORBITPORT_KMS_OPENBAO_PROXY_URL is required")
	}
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
	metadata, provider, err := p.metadataProvider(ctx, req.KeyId)
	if err != nil {
		return nil, err
	}
	return provider.Encrypt(ctx, metadata, req)
}

func (p *Plugin) Decrypt(ctx context.Context, req *proto.DecryptRequest) (*proto.DecryptResponse, error) {
	blob, err := decodeCiphertextBlob(req.CiphertextBlob)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if req.KeyId != nil && *req.KeyId != blob.KeyID {
		return nil, status.Error(codes.InvalidArgument, "KeyId does not match CiphertextBlob")
	}

	provider, err := p.providerForScheme(blob.Scheme)
	if err != nil {
		return nil, err
	}
	return provider.Decrypt(ctx, blob, req)
}

func (p *Plugin) Sign(ctx context.Context, req *proto.SignRequest) (*proto.SignResponse, error) {
	metadata, provider, err := p.metadataProvider(ctx, req.KeyId)
	if err != nil {
		return nil, err
	}
	return provider.Sign(ctx, metadata, req)
}

func (p *Plugin) CreateKey(ctx context.Context, req *proto.CreateKeyRequest) (*proto.CreateKeyResponse, error) {
	scheme, err := normalizeScheme(optionalString(req.Scheme))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	provider, err := p.providerForScheme(scheme)
	if err != nil {
		return nil, err
	}

	keyID := fmt.Sprintf("kms:%s", uuidNewString())
	record, err := provider.CreateKey(ctx, req, keyID, p.now().UTC())
	if err != nil {
		return nil, err
	}

	record.normalize()
	if err := p.client.putMetadata(ctx, keyID, record); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.CreateKeyResponse{
		KeyMetadata: toProtoMetadata(record),
	}, nil
}

func (p *Plugin) GenerateDataKey(ctx context.Context, req *proto.GenerateDataKeyRequest) (*proto.GenerateDataKeyResponse, error) {
	metadata, provider, err := p.metadataProvider(ctx, req.KeyId)
	if err != nil {
		return nil, err
	}
	return provider.GenerateDataKey(ctx, metadata, req)
}

func (p *Plugin) RotateKey(ctx context.Context, req *proto.RotateKeyRequest) (*proto.RotateKeyResponse, error) {
	metadata, provider, err := p.metadataProvider(ctx, req.KeyId)
	if err != nil {
		return nil, err
	}

	updated, err := provider.RotateKey(ctx, metadata)
	if err != nil {
		return nil, err
	}
	updated.normalize()
	if err := p.client.putMetadata(ctx, updated.KeyID, updated); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.RotateKeyResponse{
		KeyMetadata: toProtoMetadata(updated),
	}, nil
}

func (p *Plugin) metadataProvider(ctx context.Context, keyID string) (*keyMetadataRecord, kmsProvider, error) {
	metadata, err := p.client.getMetadata(ctx, keyID)
	if err != nil {
		return nil, nil, status.Error(codes.Internal, err.Error())
	}

	provider, err := p.providerForScheme(metadata.Scheme)
	if err != nil {
		return nil, nil, err
	}
	return metadata, provider, nil
}

func (p *Plugin) providerForScheme(scheme string) (kmsProvider, error) {
	normalized, err := normalizeScheme(scheme)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	provider, ok := p.providers[normalized]
	if !ok {
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
