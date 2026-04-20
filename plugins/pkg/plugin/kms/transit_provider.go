package kms

import (
	"context"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type transitProvider struct {
	client *openBaoClient
}

func newTransitProvider(client *openBaoClient) kmsProvider {
	return &transitProvider{client: client}
}

func (p *transitProvider) CreateKey(ctx context.Context, req *proto.CreateKeyRequest, keyID string, now time.Time) (*keyMetadataRecord, error) {
	if err := validateTransitKeyUsage(req.KeySpec, req.KeyUsage); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	keyType, err := transitKeyType(req.KeySpec)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	providerKey, err := scopedBackendKey(req.ClientId, keyID)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	transitInfo, err := p.client.createTransitKey(ctx, providerKey, keyType)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &keyMetadataRecord{
		KeyID:          keyID,
		ClientID:       req.ClientId,
		Alias:          req.Alias,
		Scheme:         schemeTransit,
		ProviderKey:    providerKey,
		Description:    req.Description,
		KeySpec:        req.KeySpec,
		KeyUsage:       req.KeyUsage,
		Enabled:        true,
		PrimaryVersion: transitInfo.LatestVersion,
		CreatedAt:      now.UTC().Format(time.RFC3339),
		Tags:           toRecordTags(req.Tags),
	}, nil
}

func (p *transitProvider) Encrypt(ctx context.Context, metadata *keyMetadataRecord, req *proto.EncryptRequest) (*proto.EncryptResponse, error) {
	algorithm, err := normalizeEncryptionAlgorithm(optionalString(req.EncryptionAlgorithm))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if !supportsEncryption(metadata.KeySpec) || metadata.KeyUsage != encryptDecryptUsage {
		return nil, status.Error(codes.FailedPrecondition, "key does not support encryption")
	}

	ciphertext, err := p.client.encrypt(ctx, metadata.backendKey(), req.Plaintext)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	blob, err := encodeCiphertextBlob(metadata.Scheme, metadata.KeyID, metadata.backendKey(), ciphertext, algorithm)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.EncryptResponse{
		CiphertextBlob:      blob,
		KeyId:               metadata.KeyID,
		EncryptionAlgorithm: algorithm,
	}, nil
}

func (p *transitProvider) Decrypt(ctx context.Context, blob *ciphertextBlob, _ *proto.DecryptRequest) (*proto.DecryptResponse, error) {
	plaintext, err := p.client.decrypt(ctx, blob.backendKey(), blob.Ciphertext)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.DecryptResponse{
		Plaintext:           plaintext,
		KeyId:               blob.KeyID,
		EncryptionAlgorithm: blob.Algorithm,
	}, nil
}

func (p *transitProvider) Sign(ctx context.Context, metadata *keyMetadataRecord, req *proto.SignRequest) (*proto.SignResponse, error) {
	mapping, err := signingConfig(req.SigningAlgorithm, optionalString(req.MessageType))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if !supportsSigning(metadata.KeySpec) || metadata.KeyUsage != signVerifyUsage {
		return nil, status.Error(codes.FailedPrecondition, "key does not support signing")
	}

	signature, err := p.client.sign(ctx, metadata.backendKey(), req.Message, mapping)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.SignResponse{
		KeyId:            metadata.KeyID,
		Signature:        signature,
		SigningAlgorithm: req.SigningAlgorithm,
	}, nil
}

func (p *transitProvider) GenerateDataKey(ctx context.Context, metadata *keyMetadataRecord, req *proto.GenerateDataKeyRequest) (*proto.GenerateDataKeyResponse, error) {
	if !supportsEncryption(metadata.KeySpec) || metadata.KeyUsage != encryptDecryptUsage {
		return nil, status.Error(codes.FailedPrecondition, "key does not support data key generation")
	}

	bits, err := dataKeyBits(optionalString(req.DataKeySpec), optionalUint32(req.NumberOfBytes))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	plaintext, ciphertext, err := p.client.generateDataKey(ctx, metadata.backendKey(), bits)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	blob, err := encodeCiphertextBlob(metadata.Scheme, metadata.KeyID, metadata.backendKey(), ciphertext, keySpecSymmetric)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.GenerateDataKeyResponse{
		KeyId:          metadata.KeyID,
		Plaintext:      plaintext,
		CiphertextBlob: blob,
	}, nil
}

func (p *transitProvider) RotateKey(ctx context.Context, metadata *keyMetadataRecord) (*keyMetadataRecord, error) {
	transitInfo, err := p.client.rotateTransitKey(ctx, metadata.backendKey())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	metadata.PrimaryVersion = transitInfo.LatestVersion
	return metadata, nil
}
