package kms

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type cipherOperation string

const (
	cipherOperationEncryption cipherOperation = "encryption"
	cipherOperationDecryption cipherOperation = "decryption"
)

func requireCipherProvider(provider kmsProvider, keyID, scheme string, operation cipherOperation) (cipherProvider, error) {
	typed, ok := provider.(cipherProvider)
	if !ok {
		logger.Warnf("%s rejected: unsupported operation for key_id=%s scheme=%s", operation, keyID, scheme)
		return nil, status.Error(codes.FailedPrecondition, fmt.Sprintf("%s keys do not support %s", scheme, operation))
	}
	return typed, nil
}

func requireSignProvider(provider kmsProvider, scheme string) (signProvider, error) {
	typed, ok := provider.(signProvider)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, fmt.Sprintf("%s keys do not support signing", scheme))
	}
	return typed, nil
}

func requireKeyAgreementProvider(provider kmsProvider, scheme string) (keyAgreementProvider, error) {
	typed, ok := provider.(keyAgreementProvider)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, fmt.Sprintf("%s keys do not support key agreement", scheme))
	}
	return typed, nil
}

func requireDataKeyProvider(provider kmsProvider, scheme string) (dataKeyProvider, error) {
	typed, ok := provider.(dataKeyProvider)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, fmt.Sprintf("%s keys do not support data key generation", scheme))
	}
	return typed, nil
}

func requireRotateKeyProvider(provider kmsProvider, scheme string) (rotateKeyProvider, error) {
	typed, ok := provider.(rotateKeyProvider)
	if !ok {
		return nil, status.Error(codes.Unimplemented, fmt.Sprintf("%s key rotation is not implemented", scheme))
	}
	return typed, nil
}

func requireImportParametersProvider(provider kmsProvider, scheme string) (importParametersProvider, error) {
	typed, ok := provider.(importParametersProvider)
	if !ok {
		return nil, status.Error(codes.Unimplemented, fmt.Sprintf("%s BYOK import parameters are not implemented", scheme))
	}
	return typed, nil
}

func requireKeyMaterialImporter(provider kmsProvider, scheme string) (keyMaterialImporter, error) {
	typed, ok := provider.(keyMaterialImporter)
	if !ok {
		return nil, status.Error(codes.Unimplemented, fmt.Sprintf("%s BYOK import is not implemented", scheme))
	}
	return typed, nil
}

func requireKeyMaterialVersionImporter(provider kmsProvider, scheme string) (keyMaterialVersionImporter, error) {
	typed, ok := provider.(keyMaterialVersionImporter)
	if !ok {
		return nil, status.Error(codes.Unimplemented, fmt.Sprintf("%s BYOK import-version is not implemented", scheme))
	}
	return typed, nil
}

func requireExportWrappingKeyRegistrar(provider kmsProvider, scheme string) (exportWrappingKeyRegistrar, error) {
	typed, ok := provider.(exportWrappingKeyRegistrar)
	if !ok {
		return nil, status.Error(codes.Unimplemented, fmt.Sprintf("%s export wrapping-key registration is not implemented", scheme))
	}
	return typed, nil
}

func requireKeyMaterialExporter(provider kmsProvider, scheme string) (keyMaterialExporter, error) {
	typed, ok := provider.(keyMaterialExporter)
	if !ok {
		return nil, status.Error(codes.Unimplemented, fmt.Sprintf("%s BYOK export is not implemented", scheme))
	}
	return typed, nil
}

func requireDeleteKeyProvider(provider kmsProvider, scheme string) (deleteKeyProvider, error) {
	typed, ok := provider.(deleteKeyProvider)
	if !ok {
		return nil, status.Error(codes.Unimplemented, fmt.Sprintf("%s key deletion is not implemented", scheme))
	}
	return typed, nil
}
