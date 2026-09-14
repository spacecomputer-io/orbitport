package kms

import (
	"context"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

type kmsProvider interface {
	CreateKey(context.Context, *proto.CreateKeyRequest, string, time.Time) (*keyMetadataRecord, error)
}

type cipherProvider interface {
	Encrypt(context.Context, *keyMetadataRecord, *proto.EncryptRequest) (*proto.EncryptResponse, error)
	Decrypt(context.Context, *ciphertextBlob, *proto.DecryptRequest) (*proto.DecryptResponse, error)
}

type signProvider interface {
	Sign(context.Context, *keyMetadataRecord, *proto.SignRequest) (*proto.SignResponse, error)
}

type keyAgreementProvider interface {
	Encapsulate(context.Context, *keyMetadataRecord, *proto.EncapsulateRequest) (*proto.EncapsulateResponse, error)
	Decapsulate(context.Context, *keyMetadataRecord, *proto.DecapsulateRequest) (*proto.DecapsulateResponse, error)
}

type dataKeyProvider interface {
	GenerateDataKey(context.Context, *keyMetadataRecord, *proto.GenerateDataKeyRequest) (*proto.GenerateDataKeyResponse, error)
}

type rotateKeyProvider interface {
	RotateKey(context.Context, *keyMetadataRecord) (*keyMetadataRecord, error)
}

type importParametersProvider interface {
	GetImportParameters(context.Context, *proto.GetImportParametersRequest) (*proto.GetImportParametersResponse, error)
}

type keyMaterialImporter interface {
	PrepareImportKeyMaterial(*proto.ImportKeyMaterialRequest, string, time.Time) (*keyMetadataRecord, error)
	ImportKeyMaterial(context.Context, *keyMetadataRecord, *proto.ImportKeyMaterialRequest) (*keyMetadataRecord, error)
}

type keyMaterialVersionImporter interface {
	ImportKeyMaterialVersion(context.Context, *keyMetadataRecord, *proto.ImportKeyMaterialVersionRequest) (*keyMetadataRecord, error)
}

type exportWrappingKeyRegistrar interface {
	RegisterExportWrappingKey(context.Context, *proto.RegisterExportWrappingKeyRequest, string, time.Time) (*keyMetadataRecord, error)
}

type keyMaterialExporter interface {
	ExportKeyMaterial(context.Context, *keyMetadataRecord, *keyMetadataRecord, *proto.ExportKeyMaterialRequest) (*proto.ExportKeyMaterialResponse, error)
}

type deleteKeyProvider interface {
	DeleteKey(context.Context, *keyMetadataRecord) error
}
