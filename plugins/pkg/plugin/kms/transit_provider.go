package kms

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/internal/openbao"
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

	if err := validateTransitKeySpec(req.KeySpec); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	keyType, err := transitKeyType(req.KeySpec)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	providerKey, err := scopedBackendKey(req.ClientId, req.Alias)
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
		PublicKey:      transitInfo.PublicKey,
		Tags:           toRecordTags(req.Tags),
	}, nil
}

func (p *transitProvider) GetImportParameters(ctx context.Context, req *proto.GetImportParametersRequest) (*proto.GetImportParametersResponse, error) {
	if err := validateTransitImportKeyUsage(req.KeySpec, req.KeyUsage); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	hashFunction, err := normalizeHashFunction(optionalString(req.HashFunction))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	materialFormat, err := keyMaterialFormat(req.KeySpec)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	wrappingKey, err := p.client.getTransitWrappingKey(ctx)
	if err != nil {
		return nil, kmsBackendStatus("GetImportParameters wrapping key read", err)
	}

	return &proto.GetImportParametersResponse{
		WrappingKey:       wrappingKey,
		WrappingAlgorithm: transitImportWrappingAlgorithm,
		HashFunction:      hashFunction,
		KeyMaterialFormat: materialFormat,
	}, nil
}

func (p *transitProvider) PrepareImportKeyMaterial(req *proto.ImportKeyMaterialRequest, keyID string, now time.Time) (*keyMetadataRecord, error) {
	if err := validateTransitImportKeyUsage(req.KeySpec, req.KeyUsage); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if _, err := transitKeyType(req.KeySpec); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if _, err := normalizeHashFunction(optionalString(req.HashFunction)); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	providerKey, err := scopedBackendKey(req.ClientId, req.Alias)
	if err != nil {
		return nil, status.Error(codes.Internal, kmsBackendErrorMessage)
	}

	return &keyMetadataRecord{
		KeyID:       keyID,
		ClientID:    req.ClientId,
		Alias:       req.Alias,
		Scheme:      schemeTransit,
		ProviderKey: providerKey,
		Description: req.Description,
		KeySpec:     req.KeySpec,
		KeyUsage:    req.KeyUsage,
		Enabled:     false,
		CreatedAt:   now.UTC().Format(time.RFC3339),
		Origin:      metadataOriginImported,
		Exportable:  importKeyMaterialExportable(req),
		Status:      metadataStatusImportPending,
		Tags:        toRecordTags(req.Tags),
	}, nil
}

func (p *transitProvider) ImportKeyMaterial(ctx context.Context, metadata *keyMetadataRecord, req *proto.ImportKeyMaterialRequest) (*keyMetadataRecord, error) {
	keyType, err := transitKeyType(req.KeySpec)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	hashFunction, err := normalizeHashFunction(optionalString(req.HashFunction))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	transitInfo, err := p.client.importTransitKey(ctx, metadata.backendKey(), keyType, req.Ciphertext, hashFunction, metadata.Exportable)
	if err != nil {
		return nil, statusFromOpenBaoBYOKError("ImportKeyMaterial Transit import", err)
	}

	metadata.Enabled = true
	metadata.Status = metadataStatusEnabled
	metadata.PrimaryVersion = transitInfo.LatestVersion
	metadata.PublicKey = transitInfo.PublicKey
	return metadata, nil
}

func (p *transitProvider) ImportKeyMaterialVersion(ctx context.Context, metadata *keyMetadataRecord, req *proto.ImportKeyMaterialVersionRequest) (*keyMetadataRecord, error) {
	if metadata.Origin != metadataOriginImported || metadata.PublicOnly {
		return nil, status.Error(codes.FailedPrecondition, "key was not imported with BYOK")
	}
	hashFunction, err := normalizeHashFunction(optionalString(req.HashFunction))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	transitInfo, err := p.client.importTransitKeyVersion(ctx, metadata.backendKey(), req.Ciphertext, hashFunction, req.GetVersion())
	if err != nil {
		return nil, statusFromOpenBaoBYOKError("ImportKeyMaterialVersion Transit import", err)
	}
	metadata.PrimaryVersion = transitInfo.LatestVersion
	metadata.PublicKey = transitInfo.PublicKey
	return metadata, nil
}

func (p *transitProvider) RegisterExportWrappingKey(ctx context.Context, req *proto.RegisterExportWrappingKeyRequest, keyID string, now time.Time) (*keyMetadataRecord, error) {
	providerKey, err := scopedBackendKey(req.ClientId, req.Alias)
	if err != nil {
		return nil, status.Error(codes.Internal, kmsBackendErrorMessage)
	}
	transitInfo, err := p.client.importTransitPublicKey(ctx, providerKey, "rsa-4096", req.PublicKey)
	if err != nil {
		return nil, statusFromOpenBaoBYOKError("RegisterExportWrappingKey Transit import", err)
	}

	return &keyMetadataRecord{
		KeyID:          keyID,
		ClientID:       req.ClientId,
		Alias:          req.Alias,
		Scheme:         schemeTransit,
		ProviderKey:    providerKey,
		Description:    req.Description,
		KeySpec:        keySpecRSA4096,
		KeyUsage:       keyUsageKeyWrap,
		Enabled:        true,
		PrimaryVersion: transitInfo.LatestVersion,
		CreatedAt:      now.UTC().Format(time.RFC3339),
		Origin:         metadataOriginPublicOnly,
		PublicOnly:     true,
		PublicKey:      req.PublicKey,
		Tags:           toRecordTags(req.Tags),
	}, nil
}

func (p *transitProvider) ExportKeyMaterial(ctx context.Context, source, destination *keyMetadataRecord, req *proto.ExportKeyMaterialRequest) (*proto.ExportKeyMaterialResponse, error) {
	if source.Origin != metadataOriginImported || source.PublicOnly {
		return nil, status.Error(codes.FailedPrecondition, "source key is not an imported Transit key")
	}
	if !source.Exportable {
		return nil, status.Error(codes.FailedPrecondition, "source key was imported as non-exportable")
	}
	if destination.Origin != metadataOriginPublicOnly || !destination.PublicOnly || destination.KeyUsage != keyUsageKeyWrap {
		return nil, status.Error(codes.FailedPrecondition, "destination key is not a registered export wrapping key")
	}
	hashFunction, err := normalizeHashFunction(optionalString(req.HashFunction))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	exported, err := p.client.byokExportTransitKey(ctx, destination.backendKey(), source.backendKey(), req.GetVersion(), hashFunction)
	if err != nil {
		return nil, kmsBackendStatus("ExportKeyMaterial Transit byok-export", err)
	}

	return &proto.ExportKeyMaterialResponse{
		KeyId:                       source.KeyID,
		DestinationKeyId:            destination.KeyID,
		HashFunction:                hashFunction,
		WrappedKeyMaterialByVersion: exported.Keys,
	}, nil
}

func (p *transitProvider) DeleteKey(ctx context.Context, metadata *keyMetadataRecord) error {
	if err := p.client.deleteTransitKey(ctx, metadata.backendKey()); err != nil {
		return kmsBackendStatus("DeleteKey Transit hard-delete", err)
	}
	return nil
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
	blob, err := encodeCiphertextBlob(
		metadata.Scheme,
		metadata.KeyID,
		metadata.backendKey(),
		ciphertext,
		encryptionAlgorithmAES256GCM96,
	)
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
	if metadata.Origin == metadataOriginImported {
		return nil, status.Error(codes.FailedPrecondition, "imported keys must be rotated with ImportKeyMaterialVersion")
	}
	if metadata.PublicOnly {
		return nil, status.Error(codes.FailedPrecondition, "public-only export wrapping keys do not support rotation")
	}
	transitInfo, err := p.client.rotateTransitKey(ctx, metadata.backendKey())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	metadata.PrimaryVersion = transitInfo.LatestVersion
	metadata.PublicKey = transitInfo.PublicKey
	return metadata, nil
}

func statusFromOpenBaoBYOKError(operation string, err error) error {
	var statusErr *openbao.StatusError
	if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusBadRequest {
		logger.Warnf(
			"KMS BYOK request rejected operation=%s status_code=%d status=%q body=%q",
			operation,
			statusErr.StatusCode,
			statusErr.Status,
			statusErr.Body,
		)
		return status.Error(codes.InvalidArgument, "invalid BYOK key material")
	}
	return kmsBackendStatus(operation, err)
}
