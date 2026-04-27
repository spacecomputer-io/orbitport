package kms

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func requireCipherProvider(provider kmsProvider, scheme string) (cipherProvider, error) {
	typed, ok := provider.(cipherProvider)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, fmt.Sprintf("%s keys do not support encryption or decryption", scheme))
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
