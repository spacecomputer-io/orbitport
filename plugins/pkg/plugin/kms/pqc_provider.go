package kms

import (
	"context"
	stdmlkem "crypto/mlkem"
	"encoding/base64"
	"fmt"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type pqcProvider struct {
	client *openBaoClient
}

func newPQCProvider(client *openBaoClient) kmsProvider {
	return &pqcProvider{client: client}
}

func (p *pqcProvider) CreateKey(ctx context.Context, req *proto.CreateKeyRequest, keyID string, now time.Time) (*keyMetadataRecord, error) {
	if err := validatePQCKeyUsage(req.KeySpec, req.KeyUsage); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	providerKey, err := scopedBackendKey(req.ClientId, req.Alias)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	keyInfo, variant, err := p.createPQCKey(ctx, providerKey, req.KeySpec)
	if err != nil {
		return nil, err
	}
	if keyInfo.Variant != "" && keyInfo.Variant != variant {
		return nil, status.Error(codes.Internal, "PQC key response variant mismatch")
	}

	createdAt := keyInfo.CreatedAt
	if createdAt == "" {
		createdAt = now.UTC().Format(time.RFC3339)
	}
	version := keyInfo.Version
	if version == 0 {
		version = 1
	}

	return &keyMetadataRecord{
		KeyID:          keyID,
		ClientID:       req.ClientId,
		Alias:          req.Alias,
		Scheme:         schemePQC,
		ProviderKey:    providerKey,
		Description:    req.Description,
		KeySpec:        req.KeySpec,
		KeyUsage:       req.KeyUsage,
		Enabled:        true,
		PrimaryVersion: version,
		CreatedAt:      createdAt,
		PublicKey:      keyInfo.PublicKey,
		Tags:           toRecordTags(req.Tags),
	}, nil
}

func (p *pqcProvider) createPQCKey(ctx context.Context, providerKey, keySpec string) (*pqcKeyInfo, string, error) {
	if isPQCSigningKey(keySpec) {
		variant, err := pqcMLDSAVariant(keySpec)
		if err != nil {
			return nil, "", status.Error(codes.InvalidArgument, err.Error())
		}
		keyInfo, err := p.client.createPQCKey(ctx, providerKey, variant)
		if err != nil {
			return nil, "", status.Error(codes.Internal, err.Error())
		}
		return keyInfo, variant, nil
	}

	if isPQCKEMKey(keySpec) {
		variant, err := pqcMLKEMVariant(keySpec)
		if err != nil {
			return nil, "", status.Error(codes.InvalidArgument, err.Error())
		}
		keyInfo, err := p.client.createPQCKEMKey(ctx, providerKey, variant)
		if err != nil {
			return nil, "", status.Error(codes.Internal, err.Error())
		}
		return keyInfo, variant, nil
	}

	return nil, "", status.Error(codes.InvalidArgument, fmt.Sprintf("unsupported PQC KeySpec %q", keySpec))
}

func (p *pqcProvider) Sign(ctx context.Context, metadata *keyMetadataRecord, req *proto.SignRequest) (*proto.SignResponse, error) {
	if err := validatePQCKeyUsage(metadata.KeySpec, metadata.KeyUsage); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "key does not support PQC signing")
	}
	if !isPQCSigningKey(metadata.KeySpec) {
		return nil, status.Error(codes.FailedPrecondition, "key does not support PQC signing")
	}
	if req.SigningAlgorithm != signingAlgorithmMLDSA {
		return nil, status.Error(codes.InvalidArgument, "PQC keys require SigningAlgorithm ML_DSA")
	}
	if messageType := optionalString(req.MessageType); messageType != "" && messageType != messageTypeRaw {
		return nil, status.Error(codes.InvalidArgument, "PQC keys support MessageType RAW only")
	}
	if _, err := base64.StdEncoding.DecodeString(req.Message); err != nil {
		return nil, status.Error(codes.InvalidArgument, "PQC RAW messages must be base64-encoded bytes")
	}

	signResp, err := p.client.signPQC(ctx, metadata.backendKey(), req.Message)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	variant, err := pqcMLDSAVariant(metadata.KeySpec)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if signResp == nil {
		return nil, status.Error(codes.Internal, "PQC signing response missing data")
	}
	if signResp.Signature == "" {
		return nil, status.Error(codes.Internal, "PQC signing response missing signature")
	}
	if signResp.Variant != "" && signResp.Variant != variant {
		return nil, status.Error(codes.Internal, "PQC signing response variant mismatch")
	}
	if _, err := base64.StdEncoding.DecodeString(signResp.Signature); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("PQC signing response signature is not base64: %s", err.Error()))
	}

	return &proto.SignResponse{
		KeyId:            metadata.KeyID,
		Signature:        signResp.Signature,
		SigningAlgorithm: req.SigningAlgorithm,
	}, nil
}

func (p *pqcProvider) Encapsulate(_ context.Context, metadata *keyMetadataRecord, _ *proto.EncapsulateRequest) (*proto.EncapsulateResponse, error) {
	if err := validatePQCKeyUsage(metadata.KeySpec, metadata.KeyUsage); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "key does not support PQC key agreement")
	}
	if !isPQCKEMKey(metadata.KeySpec) {
		return nil, status.Error(codes.FailedPrecondition, "key does not support PQC key agreement")
	}

	sharedKey, ciphertext, err := encapsulateMLKEMPublicKey(metadata.KeySpec, metadata.PublicKey)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	return &proto.EncapsulateResponse{
		KeyId:                 metadata.KeyID,
		Ciphertext:            ciphertext,
		SharedKey:             sharedKey,
		KeyAgreementAlgorithm: keyAgreementAlgorithmMLKEM,
	}, nil
}

func (p *pqcProvider) Decapsulate(ctx context.Context, metadata *keyMetadataRecord, req *proto.DecapsulateRequest) (*proto.DecapsulateResponse, error) {
	if err := validatePQCKeyUsage(metadata.KeySpec, metadata.KeyUsage); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "key does not support PQC key agreement")
	}
	if !isPQCKEMKey(metadata.KeySpec) {
		return nil, status.Error(codes.FailedPrecondition, "key does not support PQC key agreement")
	}
	if _, err := base64.StdEncoding.DecodeString(req.Ciphertext); err != nil {
		return nil, status.Error(codes.InvalidArgument, "PQC ciphertext must be base64-encoded bytes")
	}

	decapResp, err := p.client.decapsulatePQC(ctx, metadata.backendKey(), req.Ciphertext)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	variant, err := pqcMLKEMVariant(metadata.KeySpec)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if decapResp == nil {
		return nil, status.Error(codes.Internal, "PQC decapsulate response missing data")
	}
	if decapResp.Variant != "" && decapResp.Variant != variant {
		return nil, status.Error(codes.Internal, "PQC decapsulate response variant mismatch")
	}
	if decapResp.SharedKey == "" {
		return nil, status.Error(codes.Internal, "PQC decapsulate response missing shared key")
	}
	if _, err := base64.StdEncoding.DecodeString(decapResp.SharedKey); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("PQC decapsulate response shared key is not base64: %s", err.Error()))
	}

	return &proto.DecapsulateResponse{
		KeyId:                 metadata.KeyID,
		KeyAgreementAlgorithm: keyAgreementAlgorithmMLKEM,
	}, nil
}

func encapsulateMLKEMPublicKey(keySpec, publicKeyB64 string) (string, string, error) {
	if publicKeyB64 == "" {
		return "", "", fmt.Errorf("PQC key metadata missing public key")
	}
	publicKey, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return "", "", fmt.Errorf("PQC public key is not base64: %s", err.Error())
	}

	var sharedKey, ciphertext []byte
	switch keySpec {
	case keySpecMLKEM768:
		if len(publicKey) != stdmlkem.EncapsulationKeySize768 {
			return "", "", fmt.Errorf("PQC ML-KEM-768 public key has %d bytes, want %d", len(publicKey), stdmlkem.EncapsulationKeySize768)
		}
		encapsulationKey, err := stdmlkem.NewEncapsulationKey768(publicKey)
		if err != nil {
			return "", "", fmt.Errorf("parse PQC ML-KEM-768 public key: %s", err.Error())
		}
		sharedKey, ciphertext = encapsulationKey.Encapsulate()
	case keySpecMLKEM1024:
		if len(publicKey) != stdmlkem.EncapsulationKeySize1024 {
			return "", "", fmt.Errorf("PQC ML-KEM-1024 public key has %d bytes, want %d", len(publicKey), stdmlkem.EncapsulationKeySize1024)
		}
		encapsulationKey, err := stdmlkem.NewEncapsulationKey1024(publicKey)
		if err != nil {
			return "", "", fmt.Errorf("parse PQC ML-KEM-1024 public key: %s", err.Error())
		}
		sharedKey, ciphertext = encapsulationKey.Encapsulate()
	default:
		return "", "", fmt.Errorf("unsupported PQC ML-KEM KeySpec %q", keySpec)
	}

	return base64.StdEncoding.EncodeToString(sharedKey), base64.StdEncoding.EncodeToString(ciphertext), nil
}
