package kms

import (
	"context"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

type kmsProvider interface {
	CreateKey(context.Context, *proto.CreateKeyRequest, string, time.Time) (*keyMetadataRecord, error)
	Encrypt(context.Context, *keyMetadataRecord, *proto.EncryptRequest) (*proto.EncryptResponse, error)
	Decrypt(context.Context, *ciphertextBlob, *proto.DecryptRequest) (*proto.DecryptResponse, error)
	Sign(context.Context, *keyMetadataRecord, *proto.SignRequest) (*proto.SignResponse, error)
	GenerateDataKey(context.Context, *keyMetadataRecord, *proto.GenerateDataKeyRequest) (*proto.GenerateDataKeyResponse, error)
	RotateKey(context.Context, *keyMetadataRecord) (*keyMetadataRecord, error)
}
