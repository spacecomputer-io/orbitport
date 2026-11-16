package kms

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func publicKeyFromMetadata(_ context.Context, metadata *keyMetadataRecord, version uint32) (*publicKeyRecord, error) {
	if metadata.PublicKey == "" {
		return nil, status.Error(codes.FailedPrecondition, "key does not have a public key")
	}
	if version == 0 {
		version = metadata.PrimaryVersion
	}
	if version != metadata.PrimaryVersion {
		return nil, status.Error(codes.NotFound, "public key version not found")
	}
	return &publicKeyRecord{
		PublicKey: metadata.PublicKey,
		Version:   version,
	}, nil
}
