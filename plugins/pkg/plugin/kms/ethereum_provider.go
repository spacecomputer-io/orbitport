package kms

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"golang.org/x/crypto/sha3"
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
		expectedHash   string
		expectedMethod string
		hashHex        string
		signResp       *ethereumSignInfo
		err            error
	)
	switch messageType {
	case "", messageTypeRaw:
		hashHex, err = rawEthereumHash(req.Message)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		expectedHash = hashHex
		expectedMethod = ethereumSignMethodRawHash
		signResp, err = p.client.signEthereumHash(ctx, metadata.backendKey(), hashHex)
	case messageTypeEIP191:
		signResp, err = p.client.signEthereumMessage(ctx, metadata.backendKey(), req.Message)
	case messageTypeDigest:
		hashHex, err = normalizeEthereumDigest(req.Message)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		expectedHash = hashHex
		expectedMethod = ethereumSignMethodRawHash
		signResp, err = p.client.signEthereumHash(ctx, metadata.backendKey(), hashHex)
	default:
		return nil, status.Error(codes.InvalidArgument, "ETHEREUM keys support MessageType EIP191, RAW, or DIGEST")
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if expectedMethod != "" {
		if err := validateEthereumHashSignResponse(signResp, expectedHash, expectedMethod); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	return &proto.SignResponse{
		KeyId:            metadata.KeyID,
		Signature:        signResp.Signature,
		SigningAlgorithm: req.SigningAlgorithm,
	}, nil
}

func rawEthereumHash(message string) (string, error) {
	rawBytes, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("ETHEREUM RAW messages must be base64-encoded bytes")
	}

	hasher := sha3.NewLegacyKeccak256()
	if _, err := hasher.Write(rawBytes); err != nil {
		return "", fmt.Errorf("keccak hash write: %w", err)
	}

	return "0x" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func normalizeEthereumDigest(message string) (string, error) {
	var (
		rawBytes []byte
		err      error
	)

	switch {
	case strings.HasPrefix(message, "0x"), strings.HasPrefix(message, "0X"):
		rawBytes, err = hex.DecodeString(message[2:])
	default:
		rawBytes, err = base64.StdEncoding.DecodeString(message)
	}

	if err != nil {
		return "", fmt.Errorf("ETHEREUM DIGEST messages must be base64-encoded bytes or 0x-prefixed hex")
	}
	if len(rawBytes) != 32 {
		return "", fmt.Errorf("ETHEREUM DIGEST messages must be exactly 32 bytes")
	}

	return "0x" + hex.EncodeToString(rawBytes), nil
}

func validateEthereumHashSignResponse(signResp *ethereumSignInfo, expectedHash, expectedMethod string) error {
	if signResp == nil {
		return fmt.Errorf("ethereum signing response missing data")
	}
	if signResp.Hash != expectedHash {
		return fmt.Errorf("ethereum signing response hash mismatch")
	}
	if signResp.Method != expectedMethod {
		return fmt.Errorf("ethereum signing response method mismatch")
	}
	return nil
}
