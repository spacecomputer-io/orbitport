package kms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/internal/openbao"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Plugin struct {
	proto.UnimplementedKmsPluginServer

	client     *openBaoClient
	now        func() time.Time
	providers  map[string]kmsProvider
	authorizer *kmsAuthorizer
}

var logger = utils.GetLogger("orbitport:kms")
var aliasCharsRe = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
var reservedKmsRe = regexp.MustCompile(`^kms:`)

const kmsBackendErrorMessage = "KMS backend error"

func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()
	if cfg.OpenBaoProxyURL == "" {
		return nil, fmt.Errorf("ORBITPORT_KMS_OPENBAO_PROXY_URL is required")
	}
	logger.Infof(
		"creating KMS plugin with proxy url=%s, transit mount=%s, kv mount=%s, ethereum mount=%s, pqc mount=%s",
		cfg.OpenBaoProxyURL,
		cfg.TransitMount,
		cfg.KVMount,
		cfg.EthereumMount,
		cfg.PQCMount,
	)
	authorizer, err := newKMSAuthorizer(cfg)
	if err != nil {
		return nil, err
	}
	return newPluginWithAuthorizer(cfg, newOpenBaoClient(cfg), authorizer), nil
}

func newPlugin(cfg *kmsConfig, client *openBaoClient) *Plugin {
	authorizer, err := newKMSAuthorizer(cfg)
	if err != nil {
		panic(err)
	}
	return newPluginWithAuthorizer(cfg, client, authorizer)
}

func newPluginWithAuthorizer(cfg *kmsConfig, client *openBaoClient, authorizer *kmsAuthorizer) *Plugin {
	cfg = withKMSConfigDefaults(cfg)
	return &Plugin{
		client: client,
		now:    time.Now,
		providers: map[string]kmsProvider{
			schemeTransit:  newTransitProvider(client),
			schemeEthereum: newEthereumProvider(client),
			schemePQC:      newPQCProvider(client),
		},
		authorizer: authorizer,
	}
}

func (p *Plugin) Encrypt(ctx context.Context, req *proto.EncryptRequest) (*proto.EncryptResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	logger.Debugf("Encrypt request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("Encrypt failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	if err := ensureKeyEnabled(metadata); err != nil {
		return nil, err
	}
	if err := p.authorizer.authorize(req.ClientId, req.AuthzContext, kmsActionEncrypt, policyResourceFromMetadata(metadata)); err != nil {
		return nil, err
	}
	encryptor, err := requireCipherProvider(provider, req.KeyId, metadata.Scheme, cipherOperationEncryption)
	if err != nil {
		return nil, err
	}
	resp, err := encryptor.Encrypt(ctx, metadata, req)
	if err != nil {
		logger.Warnf("Encrypt failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	logger.Debugf("Encrypt completed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
	return resp, nil
}

func (p *Plugin) Decrypt(ctx context.Context, req *proto.DecryptRequest) (*proto.DecryptResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	blob, err := decodeCiphertextBlob(req.CiphertextBlob)
	if err != nil {
		logger.Warn("Decrypt rejected invalid ciphertext blob")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	logger.Debugf("Decrypt request received for key_id=%s scheme=%s", blob.KeyID, blob.Scheme)
	if req.KeyId != nil {
		resolvedKeyID, err := p.resolveKeyID(*req.KeyId)
		if err != nil {
			logger.Warnf("Decrypt failed to resolve key reference for request key_id=%s", *req.KeyId)
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		if resolvedKeyID != blob.KeyID {
			logger.Warnf("Decrypt rejected mismatched key id: request=%s resolved=%s blob=%s", *req.KeyId, resolvedKeyID, blob.KeyID)
			return nil, status.Error(codes.InvalidArgument, "KeyId does not match CiphertextBlob")
		}
	}

	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, blob.KeyID)
	if err != nil {
		logger.Warnf("Decrypt failed to resolve metadata for key_id=%s", blob.KeyID)
		return nil, err
	}
	if err := ensureKeyEnabled(metadata); err != nil {
		return nil, err
	}
	if metadata.KeyID != blob.KeyID || metadata.backendKey() != blob.backendKey() {
		logger.Warnf("Decrypt rejected mismatched ciphertext blob for key_id=%s", blob.KeyID)
		return nil, status.Error(codes.PermissionDenied, "CiphertextBlob does not belong to the authenticated client")
	}
	if err := p.authorizer.authorize(req.ClientId, req.AuthzContext, kmsActionDecrypt, policyResourceFromMetadata(metadata)); err != nil {
		return nil, err
	}
	decryptor, err := requireCipherProvider(provider, blob.KeyID, metadata.Scheme, cipherOperationDecryption)
	if err != nil {
		return nil, err
	}
	if !supportsEncryption(metadata.KeySpec) || metadata.KeyUsage != encryptDecryptUsage {
		return nil, status.Error(codes.FailedPrecondition, "key does not support encryption")
	}
	resp, err := decryptor.Decrypt(ctx, blob, req)
	if err != nil {
		logger.Warnf("Decrypt failed for key_id=%s scheme=%s", blob.KeyID, blob.Scheme)
		return nil, err
	}
	logger.Debugf("Decrypt completed for key_id=%s scheme=%s", blob.KeyID, blob.Scheme)
	return resp, nil
}

func (p *Plugin) Sign(ctx context.Context, req *proto.SignRequest) (*proto.SignResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	logger.Debugf(
		"Sign request received for key_id=%s signing_algorithm=%s message_type=%q",
		req.KeyId,
		req.SigningAlgorithm,
		optionalString(req.MessageType),
	)
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("Sign failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	if err := ensureKeyEnabled(metadata); err != nil {
		return nil, err
	}
	if err := p.authorizer.authorize(req.ClientId, req.AuthzContext, kmsActionSign, policyResourceFromMetadata(metadata)); err != nil {
		return nil, err
	}
	signer, err := requireSignProvider(provider, metadata.Scheme)
	if err != nil {
		logger.Warnf("Sign rejected: unsupported operation for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	resp, err := signer.Sign(ctx, metadata, req)
	if err != nil {
		logger.Warnf("Sign failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	logger.Debugf("Sign completed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
	return resp, nil
}

func (p *Plugin) Encapsulate(ctx context.Context, req *proto.EncapsulateRequest) (*proto.EncapsulateResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	logger.Debugf("Encapsulate request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("Encapsulate failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	if err := ensureKeyEnabled(metadata); err != nil {
		return nil, err
	}
	if err := p.authorizer.authorize(req.ClientId, req.AuthzContext, kmsActionEncapsulate, policyResourceFromMetadata(metadata)); err != nil {
		return nil, err
	}
	keyAgreement, err := requireKeyAgreementProvider(provider, metadata.Scheme)
	if err != nil {
		logger.Warnf("Encapsulate rejected: unsupported operation for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	resp, err := keyAgreement.Encapsulate(ctx, metadata, req)
	if err != nil {
		logger.Warnf("Encapsulate failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	logger.Debugf("Encapsulate completed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
	return resp, nil
}

func (p *Plugin) Decapsulate(ctx context.Context, req *proto.DecapsulateRequest) (*proto.DecapsulateResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	logger.Debugf("Decapsulate request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("Decapsulate failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	if err := ensureKeyEnabled(metadata); err != nil {
		return nil, err
	}
	if err := p.authorizer.authorize(req.ClientId, req.AuthzContext, kmsActionDecapsulate, policyResourceFromMetadata(metadata)); err != nil {
		return nil, err
	}
	keyAgreement, err := requireKeyAgreementProvider(provider, metadata.Scheme)
	if err != nil {
		logger.Warnf("Decapsulate rejected: unsupported operation for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	resp, err := keyAgreement.Decapsulate(ctx, metadata, req)
	if err != nil {
		logger.Warnf("Decapsulate failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	logger.Debugf("Decapsulate completed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
	return resp, nil
}

func (p *Plugin) CreateKey(ctx context.Context, req *proto.CreateKeyRequest) (*proto.CreateKeyResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	scheme, err := normalizeScheme(optionalString(req.Scheme))
	if err != nil {
		logger.Warnf("CreateKey rejected unsupported scheme=%q", optionalString(req.Scheme))
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	logger.Infof(
		"CreateKey request received scheme=%s key_spec=%s key_usage=%s alias=%q tags=%d",
		scheme,
		req.KeySpec,
		req.KeyUsage,
		req.Alias,
		len(req.Tags),
	)

	alias := strings.TrimSpace(req.Alias)
	if err := validateAlias(alias); err != nil {
		logger.Warnf("CreateKey rejected invalid alias=%q", alias)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	keyID, err := canonicalKeyID(alias)
	if err != nil {
		logger.Warnf("CreateKey rejected alias=%q", alias)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.authorizer.authorize(req.ClientId, req.AuthzContext, kmsActionCreateKey, kmsPolicyResource{
		KeyID:    keyID,
		Alias:    alias,
		Scheme:   scheme,
		KeySpec:  req.KeySpec,
		KeyUsage: req.KeyUsage,
		Origin:   metadataOriginGenerated,
	}); err != nil {
		return nil, err
	}
	if err := p.client.metadataExists(ctx, req.ClientId, keyID); err == nil {
		logger.Warnf("CreateKey rejected duplicate alias=%q", alias)
		return nil, status.Error(codes.AlreadyExists, "Alias already exists for this tenant")
	} else {
		var statusErr *openbao.StatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusNotFound {
			logger.Warnf("CreateKey failed to verify key availability alias=%q", alias)
			return nil, kmsBackendStatus("CreateKey availability check", err)
		}
	}

	provider, err := p.providerForScheme(scheme)
	if err != nil {
		logger.Warnf("CreateKey failed to resolve provider for scheme=%s", scheme)
		return nil, err
	}

	req.Alias = alias
	record, err := provider.CreateKey(ctx, req, keyID, p.now().UTC())
	if err != nil {
		logger.Warnf("CreateKey failed for key_id=%s scheme=%s", keyID, scheme)
		return nil, err
	}

	record.normalize()
	if err := p.client.putMetadata(ctx, req.ClientId, keyID, record); err != nil {
		logger.Warnf("CreateKey failed to persist metadata for key_id=%s scheme=%s", keyID, scheme)
		return nil, kmsBackendStatus("CreateKey metadata write", err)
	}
	logger.Infof("CreateKey completed key_id=%s scheme=%s", keyID, scheme)

	return &proto.CreateKeyResponse{
		KeyMetadata: toProtoMetadata(record),
	}, nil
}

func (p *Plugin) GenerateDataKey(ctx context.Context, req *proto.GenerateDataKeyRequest) (*proto.GenerateDataKeyResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	logger.Debugf("GenerateDataKey request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("GenerateDataKey failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	if err := ensureKeyEnabled(metadata); err != nil {
		return nil, err
	}
	if err := p.authorizer.authorize(req.ClientId, req.AuthzContext, kmsActionGenerateDataKey, policyResourceFromMetadata(metadata)); err != nil {
		return nil, err
	}
	generator, err := requireDataKeyProvider(provider, metadata.Scheme)
	if err != nil {
		logger.Warnf("GenerateDataKey rejected: unsupported operation for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	resp, err := generator.GenerateDataKey(ctx, metadata, req)
	if err != nil {
		logger.Warnf("GenerateDataKey failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	logger.Debugf("GenerateDataKey completed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
	return resp, nil
}

func (p *Plugin) RotateKey(ctx context.Context, req *proto.RotateKeyRequest) (*proto.RotateKeyResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	logger.Infof("RotateKey request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("RotateKey failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	if err := ensureKeyEnabled(metadata); err != nil {
		return nil, err
	}
	if err := p.authorizer.authorize(req.ClientId, req.AuthzContext, kmsActionRotateKey, policyResourceFromMetadata(metadata)); err != nil {
		return nil, err
	}

	rotator, err := requireRotateKeyProvider(provider, metadata.Scheme)
	if err != nil {
		logger.Warnf("RotateKey rejected: unsupported operation for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	updated, err := rotator.RotateKey(ctx, metadata)
	if err != nil {
		logger.Warnf("RotateKey failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	updated.normalize()
	if err := p.client.putMetadata(ctx, req.ClientId, updated.KeyID, updated); err != nil {
		logger.Warnf("RotateKey failed to persist metadata for key_id=%s", updated.KeyID)
		return nil, status.Error(codes.Internal, err.Error())
	}
	logger.Infof(
		"RotateKey completed for key_id=%s scheme=%s primary_version=%d",
		updated.KeyID,
		updated.Scheme,
		updated.PrimaryVersion,
	)

	return &proto.RotateKeyResponse{
		KeyMetadata: toProtoMetadata(updated),
	}, nil
}

func (p *Plugin) GetImportParameters(ctx context.Context, req *proto.GetImportParametersRequest) (*proto.GetImportParametersResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	scheme, err := normalizeScheme(optionalString(req.Scheme))
	if err != nil {
		logger.Warnf("GetImportParameters rejected unsupported scheme=%q", optionalString(req.Scheme))
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.authorizer.authorize(req.ClientId, req.AuthzContext, kmsActionGetImportParameters, kmsPolicyResource{
		Scheme:   scheme,
		KeySpec:  req.KeySpec,
		KeyUsage: req.KeyUsage,
	}); err != nil {
		return nil, err
	}
	provider, err := p.providerForScheme(scheme)
	if err != nil {
		return nil, err
	}
	importer, err := requireImportParametersProvider(provider, scheme)
	if err != nil {
		return nil, err
	}
	return importer.GetImportParameters(ctx, req)
}

func (p *Plugin) ImportKeyMaterial(ctx context.Context, req *proto.ImportKeyMaterialRequest) (*proto.ImportKeyMaterialResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	scheme, err := normalizeScheme(optionalString(req.Scheme))
	if err != nil {
		logger.Warnf("ImportKeyMaterial rejected unsupported scheme=%q", optionalString(req.Scheme))
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	alias := strings.TrimSpace(req.Alias)
	if err := validateAlias(alias); err != nil {
		logger.Warnf("ImportKeyMaterial rejected invalid alias=%q", alias)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	keyID, err := canonicalKeyID(alias)
	if err != nil {
		logger.Warnf("ImportKeyMaterial rejected alias=%q", alias)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.authorizer.authorize(req.ClientId, req.AuthzContext, kmsActionImportKeyMaterial, kmsPolicyResource{
		KeyID:    keyID,
		Alias:    alias,
		Scheme:   scheme,
		KeySpec:  req.KeySpec,
		KeyUsage: req.KeyUsage,
		Origin:   metadataOriginImported,
	}); err != nil {
		return nil, err
	}
	if err := p.client.metadataExists(ctx, req.ClientId, keyID); err == nil {
		logger.Warnf("ImportKeyMaterial rejected duplicate alias=%q", alias)
		return nil, status.Error(codes.AlreadyExists, "Alias already exists for this tenant")
	} else {
		var statusErr *openbao.StatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusNotFound {
			logger.Warnf("ImportKeyMaterial failed to verify key availability alias=%q", alias)
			return nil, kmsBackendStatus("ImportKeyMaterial availability check", err)
		}
	}

	provider, err := p.providerForScheme(scheme)
	if err != nil {
		logger.Warnf("ImportKeyMaterial failed to resolve provider for scheme=%s", scheme)
		return nil, err
	}
	importer, err := requireKeyMaterialImporter(provider, scheme)
	if err != nil {
		return nil, err
	}

	now := p.now().UTC()
	req.Alias = alias
	record, err := importer.PrepareImportKeyMaterial(req, keyID, now)
	if err != nil {
		logger.Warnf("ImportKeyMaterial failed to prepare metadata for key_id=%s scheme=%s", keyID, scheme)
		return nil, err
	}
	record.normalize()
	if err := p.client.putMetadata(ctx, req.ClientId, keyID, record); err != nil {
		logger.Warnf("ImportKeyMaterial failed to persist pending metadata for key_id=%s scheme=%s", keyID, scheme)
		return nil, kmsBackendStatus("ImportKeyMaterial pending metadata write", err)
	}

	record, err = importer.ImportKeyMaterial(ctx, record, req)
	if err != nil {
		logger.Warnf("ImportKeyMaterial failed for key_id=%s scheme=%s", keyID, scheme)
		if status.Code(err) == codes.Internal {
			p.cleanupImportedKeyAfterMetadataFailure(ctx, req.ClientId, provider, record)
		} else {
			p.cleanupPendingMetadata(ctx, req.ClientId, keyID, "ImportKeyMaterial import failure")
		}
		return nil, err
	}
	record.normalize()
	if err := p.client.putMetadata(ctx, req.ClientId, keyID, record); err != nil {
		logger.Warnf("ImportKeyMaterial failed to persist metadata for key_id=%s scheme=%s", keyID, scheme)
		p.cleanupImportedKeyAfterMetadataFailure(ctx, req.ClientId, provider, record)
		return nil, kmsBackendStatus("ImportKeyMaterial metadata write", err)
	}
	logger.Infof("ImportKeyMaterial completed key_id=%s scheme=%s", keyID, scheme)

	return &proto.ImportKeyMaterialResponse{
		KeyMetadata: toProtoMetadata(record),
	}, nil
}

func (p *Plugin) ImportKeyMaterialVersion(ctx context.Context, req *proto.ImportKeyMaterialVersionRequest) (*proto.ImportKeyMaterialVersionResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	logger.Infof("ImportKeyMaterialVersion request received for key_id=%s", req.KeyId)
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("ImportKeyMaterialVersion failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	if err := ensureKeyEnabled(metadata); err != nil {
		return nil, err
	}
	if err := p.authorizer.authorize(req.ClientId, req.AuthzContext, kmsActionImportKeyMaterialVersion, policyResourceFromMetadata(metadata)); err != nil {
		return nil, err
	}
	importer, err := requireKeyMaterialVersionImporter(provider, metadata.Scheme)
	if err != nil {
		return nil, err
	}
	updated, err := importer.ImportKeyMaterialVersion(ctx, metadata, req)
	if err != nil {
		logger.Warnf("ImportKeyMaterialVersion failed for key_id=%s scheme=%s", req.KeyId, metadata.Scheme)
		return nil, err
	}
	updated.normalize()
	if err := p.client.putMetadata(ctx, req.ClientId, updated.KeyID, updated); err != nil {
		logger.Warnf("ImportKeyMaterialVersion failed to persist metadata for key_id=%s", updated.KeyID)
		return nil, kmsBackendStatus("ImportKeyMaterialVersion metadata write", err)
	}

	return &proto.ImportKeyMaterialVersionResponse{
		KeyMetadata: toProtoMetadata(updated),
	}, nil
}

func (p *Plugin) RegisterExportWrappingKey(ctx context.Context, req *proto.RegisterExportWrappingKeyRequest) (*proto.RegisterExportWrappingKeyResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	alias := strings.TrimSpace(req.Alias)
	if err := validateAlias(alias); err != nil {
		logger.Warnf("RegisterExportWrappingKey rejected invalid alias=%q", alias)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	keyID, err := canonicalKeyID(alias)
	if err != nil {
		logger.Warnf("RegisterExportWrappingKey rejected alias=%q", alias)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.authorizer.authorize(req.ClientId, req.AuthzContext, kmsActionRegisterExportWrappingKey, kmsPolicyResource{
		KeyID:      keyID,
		Alias:      alias,
		Scheme:     schemeTransit,
		KeySpec:    keySpecRSA4096,
		KeyUsage:   keyUsageKeyWrap,
		Origin:     metadataOriginPublicOnly,
		PublicOnly: true,
	}); err != nil {
		return nil, err
	}
	if err := p.client.metadataExists(ctx, req.ClientId, keyID); err == nil {
		logger.Warnf("RegisterExportWrappingKey rejected duplicate alias=%q", alias)
		return nil, status.Error(codes.AlreadyExists, "Alias already exists for this tenant")
	} else {
		var statusErr *openbao.StatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusNotFound {
			logger.Warnf("RegisterExportWrappingKey failed to verify key availability alias=%q", alias)
			return nil, kmsBackendStatus("RegisterExportWrappingKey availability check", err)
		}
	}

	provider, err := p.providerForScheme(schemeTransit)
	if err != nil {
		return nil, err
	}
	registrar, err := requireExportWrappingKeyRegistrar(provider, schemeTransit)
	if err != nil {
		return nil, err
	}
	req.Alias = alias
	record, err := registrar.RegisterExportWrappingKey(ctx, req, keyID, p.now().UTC())
	if err != nil {
		logger.Warnf("RegisterExportWrappingKey failed for key_id=%s", keyID)
		return nil, err
	}
	record.normalize()
	if err := p.client.putMetadata(ctx, req.ClientId, keyID, record); err != nil {
		logger.Warnf("RegisterExportWrappingKey failed to persist metadata for key_id=%s", keyID)
		return nil, kmsBackendStatus("RegisterExportWrappingKey metadata write", err)
	}

	return &proto.RegisterExportWrappingKeyResponse{
		KeyMetadata: toProtoMetadata(record),
	}, nil
}

func (p *Plugin) ExportKeyMaterial(ctx context.Context, req *proto.ExportKeyMaterialRequest) (*proto.ExportKeyMaterialResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	source, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("ExportKeyMaterial failed to resolve source metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	if err := ensureKeyEnabled(source); err != nil {
		return nil, err
	}
	destination, _, err := p.metadataProvider(ctx, req.ClientId, req.DestinationKeyId)
	if err != nil {
		logger.Warnf("ExportKeyMaterial failed to resolve destination metadata for key_id=%s", req.DestinationKeyId)
		return nil, err
	}
	if err := ensureKeyEnabled(destination); err != nil {
		return nil, err
	}
	if err := p.authorizer.authorize(req.ClientId, req.AuthzContext, kmsActionExportKeyMaterial, policyResourceFromMetadata(source)); err != nil {
		return nil, err
	}
	exporter, err := requireKeyMaterialExporter(provider, source.Scheme)
	if err != nil {
		return nil, err
	}
	return exporter.ExportKeyMaterial(ctx, source, destination, req)
}

func (p *Plugin) DeleteKey(ctx context.Context, req *proto.DeleteKeyRequest) (*proto.DeleteKeyResponse, error) {
	if err := requireClientID(req.ClientId); err != nil {
		return nil, err
	}
	metadata, provider, err := p.metadataProvider(ctx, req.ClientId, req.KeyId)
	if err != nil {
		logger.Warnf("DeleteKey failed to resolve metadata for key_id=%s", req.KeyId)
		return nil, err
	}
	if err := p.authorizer.authorize(req.ClientId, req.AuthzContext, kmsActionDeleteKey, policyResourceFromMetadata(metadata)); err != nil {
		return nil, err
	}
	if metadata.DeletedAt == "" {
		if metadata.Status != metadataStatusDeletePending {
			metadata.Enabled = false
			metadata.Status = metadataStatusDeletePending
			metadata.normalize()
			if err := p.client.putMetadata(ctx, req.ClientId, metadata.KeyID, metadata); err != nil {
				logger.Warnf("DeleteKey failed to mark metadata pending-delete for key_id=%s", metadata.KeyID)
				return nil, kmsBackendStatus("DeleteKey pending metadata write", err)
			}
		}
		deleter, err := requireDeleteKeyProvider(provider, metadata.Scheme)
		if err != nil {
			return nil, err
		}
		if err := deleter.DeleteKey(ctx, metadata); err != nil {
			logger.Warnf("DeleteKey failed for key_id=%s scheme=%s", metadata.KeyID, metadata.Scheme)
			return nil, err
		}
		metadata.Enabled = false
		metadata.Status = metadataStatusDeleted
		metadata.DeletedAt = p.now().UTC().Format(time.RFC3339)
		metadata.normalize()
		if err := p.client.putMetadata(ctx, req.ClientId, metadata.KeyID, metadata); err != nil {
			logger.Warnf("DeleteKey failed to persist metadata for key_id=%s", metadata.KeyID)
			return nil, kmsBackendStatus("DeleteKey metadata write", err)
		}
	}
	return &proto.DeleteKeyResponse{
		KeyId: metadata.KeyID,
	}, nil
}

func (p *Plugin) metadataProvider(ctx context.Context, clientID, keyID string) (*keyMetadataRecord, kmsProvider, error) {
	resolvedKeyID, err := p.resolveKeyID(keyID)
	if err != nil {
		return nil, nil, status.Error(codes.InvalidArgument, err.Error())
	}

	metadata, err := p.client.getMetadata(ctx, clientID, resolvedKeyID)
	if err != nil {
		var statusErr *openbao.StatusError
		if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
			logger.Warnf("denied access to key_id=%s for requesting client", resolvedKeyID)
			return nil, nil, status.Error(codes.PermissionDenied, "key does not belong to the authenticated client")
		}
		logger.Warnf("failed to fetch KMS metadata for key_id=%s", resolvedKeyID)
		return nil, nil, kmsBackendStatus("metadata read", err)
	}

	provider, err := p.providerForScheme(metadata.Scheme)
	if err != nil {
		logger.Warnf("failed to resolve provider for key_id=%s scheme=%s", resolvedKeyID, metadata.Scheme)
		return nil, nil, err
	}
	return metadata, provider, nil
}

func (p *Plugin) resolveKeyID(keyRef string) (string, error) {
	resolvedKeyID, _, err := resolveKeyRef(keyRef)
	return resolvedKeyID, err
}

func requireClientID(clientID string) error {
	if strings.TrimSpace(clientID) == "" {
		return status.Error(codes.InvalidArgument, "client_id is required")
	}
	return nil
}

func importKeyMaterialExportable(req *proto.ImportKeyMaterialRequest) bool {
	if req.Exportable == nil {
		return true
	}
	return req.GetExportable()
}

func (p *Plugin) cleanupPendingMetadata(ctx context.Context, clientID, keyID, operation string) {
	if err := p.client.deleteMetadata(ctx, clientID, keyID); err != nil {
		logger.Warnf("%s failed to remove pending metadata for key_id=%s: %v", operation, keyID, err)
	}
}

func (p *Plugin) cleanupImportedKeyAfterMetadataFailure(ctx context.Context, clientID string, provider kmsProvider, record *keyMetadataRecord) {
	deleter, err := requireDeleteKeyProvider(provider, record.Scheme)
	if err != nil {
		logger.Warnf("ImportKeyMaterial cleanup could not resolve deleter for key_id=%s scheme=%s: %v", record.KeyID, record.Scheme, err)
		return
	}
	if err := deleter.DeleteKey(ctx, record); err != nil {
		logger.Warnf("ImportKeyMaterial cleanup failed to delete imported key_id=%s scheme=%s: %v", record.KeyID, record.Scheme, err)
		return
	}
	p.cleanupPendingMetadata(ctx, clientID, record.KeyID, "ImportKeyMaterial cleanup")
}

func kmsBackendStatus(operation string, err error) error {
	var statusErr *openbao.StatusError
	if errors.As(err, &statusErr) {
		logger.Warnf(
			"KMS backend error operation=%s status_code=%d status=%q body=%q",
			operation,
			statusErr.StatusCode,
			statusErr.Status,
			statusErr.Body,
		)
	} else {
		logger.Warnf("KMS backend error operation=%s error=%v", operation, err)
	}
	return status.Error(codes.Internal, kmsBackendErrorMessage)
}

func ensureKeyEnabled(metadata *keyMetadataRecord) error {
	if metadata == nil {
		return status.Error(codes.NotFound, "key metadata not found")
	}
	if metadata.DeletedAt != "" || !metadata.Enabled {
		return status.Error(codes.FailedPrecondition, "key is disabled or deleted")
	}
	return nil
}

func (p *Plugin) providerForScheme(scheme string) (kmsProvider, error) {
	normalized, err := normalizeScheme(scheme)
	if err != nil {
		logger.Warnf("unsupported KMS scheme=%q", scheme)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	provider, ok := p.providers[normalized]
	if !ok {
		logger.Warnf("no provider registered for KMS scheme=%q", normalized)
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("unsupported Scheme %q", normalized))
	}
	return provider, nil
}

func toRecordTags(tags []*proto.Tag) []*pluginTag {
	result := make([]*pluginTag, 0, len(tags))
	for _, tag := range tags {
		result = append(result, &pluginTag{
			TagKey:   tag.TagKey,
			TagValue: tag.TagValue,
		})
	}
	return result
}

func toProtoTags(tags []*pluginTag) []*proto.Tag {
	result := make([]*proto.Tag, 0, len(tags))
	for _, tag := range tags {
		result = append(result, &proto.Tag{
			TagKey:   tag.TagKey,
			TagValue: tag.TagValue,
		})
	}
	return result
}

func toProtoMetadata(record *keyMetadataRecord) *proto.KeyMetadata {
	record.normalize()

	metadata := &proto.KeyMetadata{
		KeyId:          record.KeyID,
		Description:    record.Description,
		KeySpec:        record.KeySpec,
		KeyUsage:       record.KeyUsage,
		Enabled:        record.Enabled,
		PrimaryVersion: record.PrimaryVersion,
		CreationDate:   record.CreatedAt,
		Scheme:         record.Scheme,
		Tags:           toProtoTags(record.Tags),
		Origin:         record.Origin,
		PublicOnly:     record.PublicOnly,
		Exportable:     record.Exportable,
	}
	if record.DeletedAt != "" {
		metadata.DeletedAt = &record.DeletedAt
	}
	if record.PublicKey != "" {
		metadata.PublicKey = &record.PublicKey
	}
	if record.Address != "" {
		metadata.Address = &record.Address
	}
	metadata.Alias = record.Alias
	return metadata
}

func policyResourceFromMetadata(record *keyMetadataRecord) kmsPolicyResource {
	record.normalize()
	return kmsPolicyResource{
		KeyID:      record.KeyID,
		Alias:      record.Alias,
		Scheme:     record.Scheme,
		KeySpec:    record.KeySpec,
		KeyUsage:   record.KeyUsage,
		Origin:     record.Origin,
		PublicOnly: record.PublicOnly,
	}
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func optionalUint32(value *uint32) uint32 {
	if value == nil {
		return 0
	}
	return *value
}

func validateAlias(alias string) error {
	const maxAliasLen = 128

	if alias == "" {
		return fmt.Errorf("alias is required")
	}
	if len(alias) > maxAliasLen {
		return fmt.Errorf("alias must be at most %d characters", maxAliasLen)
	}
	if reservedKmsRe.MatchString(alias) {
		return fmt.Errorf("alias must not use the reserved kms:<alias> format")
	}
	if !aliasCharsRe.MatchString(alias) {
		return fmt.Errorf("alias contains unsupported characters")
	}
	return nil
}
