package kms

import (
	"context"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ethereumProvider struct {
	client *openBaoClient
}

func newEthereumProvider(client *openBaoClient) kmsProvider {
	return &ethereumProvider{client: client}
}

func (p *ethereumProvider) CreateKey(ctx context.Context, req *proto.CreateKeyRequest, keyID string, now time.Time) (*keyMetadataRecord, error) {
	if err := validateEthereumKeyUsage(req.KeySpec, req.KeyUsage); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	providerKey, err := scopedBackendKey(req.ClientId, req.Alias)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	keyInfo, err := p.client.createEthereumKey(ctx, providerKey)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	createdAt := keyInfo.CreatedAt
	if createdAt == "" {
		createdAt = now.UTC().Format(time.RFC3339)
	}

	return &keyMetadataRecord{
		KeyID:          keyID,
		ClientID:       req.ClientId,
		Alias:          req.Alias,
		Scheme:         schemeEthereum,
		ProviderKey:    providerKey,
		Description:    req.Description,
		KeySpec:        req.KeySpec,
		KeyUsage:       req.KeyUsage,
		Enabled:        true,
		PrimaryVersion: 1,
		CreatedAt:      createdAt,
		PublicKey:      keyInfo.PublicKey,
		Address:        keyInfo.Address,
		Tags:           toRecordTags(req.Tags),
	}, nil
}

func (p *ethereumProvider) Sign(ctx context.Context, metadata *keyMetadataRecord, req *proto.SignRequest) (*proto.SignResponse, error) {
	if metadata.KeySpec != keySpecECCSecgP256K1 || metadata.KeyUsage != signVerifyUsage {
		return nil, status.Error(codes.FailedPrecondition, "key does not support ethereum signing")
	}
	if req.SigningAlgorithm != signingAlgorithmEthereumSecp256k1 {
		return nil, status.Error(codes.InvalidArgument, "ETHEREUM keys require SigningAlgorithm ETHEREUM_SECP256K1")
	}

	messageType := optionalString(req.MessageType)
	var (
		signResp *ethereumSignInfo
		err      error
	)
	switch messageType {
	case "", messageTypeEIP191, messageTypeRaw:
		signResp, err = p.client.signEthereumMessage(ctx, metadata.backendKey(), req.Message)
	case messageTypeDigest:
		signResp, err = p.client.signEthereumHash(ctx, metadata.backendKey(), req.Message)
	default:
		return nil, status.Error(codes.InvalidArgument, "ETHEREUM keys support MessageType EIP191, RAW, or DIGEST")
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.SignResponse{
		KeyId:            metadata.KeyID,
		Signature:        signResp.Signature,
		SigningAlgorithm: req.SigningAlgorithm,
	}, nil
}
