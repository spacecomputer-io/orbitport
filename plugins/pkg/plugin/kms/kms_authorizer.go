package kms

import (
	"fmt"
	"os"
	"strings"

	cedar "github.com/cedar-policy/cedar-go"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	kmsPrincipalType = "KmsClient"
	kmsKeyType       = "KmsKey"
	kmsActionType    = "Action"

	kmsActionCreateKey                 = "kms.CreateKey"
	kmsActionEncrypt                   = "kms.Encrypt"
	kmsActionDecrypt                   = "kms.Decrypt"
	kmsActionSign                      = "kms.Sign"
	kmsActionEncapsulate               = "kms.Encapsulate"
	kmsActionDecapsulate               = "kms.Decapsulate"
	kmsActionGenerateDataKey           = "kms.GenerateDataKey"
	kmsActionRotateKey                 = "kms.RotateKey"
	kmsActionGetImportParameters       = "kms.GetImportParameters"
	kmsActionImportKeyMaterial         = "kms.ImportKeyMaterial"
	kmsActionImportKeyMaterialVersion  = "kms.ImportKeyMaterialVersion"
	kmsActionRegisterExportWrappingKey = "kms.RegisterExportWrappingKey"
	kmsActionExportKeyMaterial         = "kms.ExportKeyMaterial"
	kmsActionDeleteKey                 = "kms.DeleteKey"
)

type kmsAuthorizer struct {
	policies *cedar.PolicySet
}

type kmsPolicyResource struct {
	KeyID      string
	Alias      string
	Scheme     string
	KeySpec    string
	KeyUsage   string
	Origin     string
	PublicOnly bool
}

func newKMSAuthorizer(cfg *kmsConfig) (*kmsAuthorizer, error) {
	cfg = withKMSConfigDefaults(cfg)
	if cfg.CedarPolicyPath == "" {
		return &kmsAuthorizer{}, nil
	}

	document, err := os.ReadFile(cfg.CedarPolicyPath)
	if err != nil {
		return nil, fmt.Errorf("read KMS Cedar policy: %w", err)
	}
	policies := cedar.NewPolicySet()
	if err := addCedarPolicyDocument(policies, cfg.CedarPolicyPath, document); err != nil {
		return nil, err
	}
	return &kmsAuthorizer{policies: policies}, nil
}

func addCedarPolicyDocument(target *cedar.PolicySet, fileName string, document []byte) error {
	policies, err := cedar.NewPolicySetFromBytes(fileName, document)
	if err != nil {
		return fmt.Errorf("parse Cedar policy %s: %w", fileName, err)
	}
	for policyID, policy := range policies.All() {
		target.Add(cedar.PolicyID(fileName+":"+string(policyID)), policy)
	}
	return nil
}

func (a *kmsAuthorizer) authorize(clientID string, authz *proto.AuthzContext, action string, resource kmsPolicyResource) error {
	if err := authorizeKMSPATScope(authz, action); err != nil {
		return err
	}
	if a == nil || a.policies == nil {
		return nil
	}

	owner := tenantNamespace(clientID)
	principalUID := cedar.NewEntityUID(kmsPrincipalType, cedar.String(kmsPrincipalID(clientID, authz)))
	resourceUID := cedar.NewEntityUID(kmsKeyType, cedar.String(kmsResourceID(owner, resource)))

	principalAttrs := cedar.NewRecord(kmsPrincipalAttrs(owner, clientID, authz))
	resourceAttrs := cedar.NewRecord(kmsResourceAttrs(owner, resource))
	entities := cedar.EntityMap{
		principalUID: {
			UID:        principalUID,
			Parents:    cedar.NewEntityUIDSet(),
			Attributes: principalAttrs,
			Tags:       cedar.NewRecord(nil),
		},
		resourceUID: {
			UID:        resourceUID,
			Parents:    cedar.NewEntityUIDSet(),
			Attributes: resourceAttrs,
			Tags:       cedar.NewRecord(nil),
		},
	}

	context := kmsResourceAttrs(owner, resource)
	context["client_id"] = cedar.String(clientID)
	context["owner"] = cedar.String(owner)

	decision, diagnostic := cedar.Authorize(a.policies, entities, cedar.Request{
		Principal: principalUID,
		Action:    cedar.NewEntityUID(kmsActionType, cedar.String(action)),
		Resource:  resourceUID,
		Context:   cedar.NewRecord(context),
	})
	if len(diagnostic.Errors) > 0 {
		logger.Warnf("KMS Cedar evaluation errors action=%s owner=%s errors=%v", action, owner, diagnostic.Errors)
		return status.Error(codes.PermissionDenied, "KMS request denied by policy")
	}
	if decision != cedar.Allow {
		logger.Warnf("KMS Cedar denied action=%s owner=%s resource=%s", action, owner, resourceUID.String())
		return status.Error(codes.PermissionDenied, "KMS request denied by policy")
	}
	return nil
}

func authorizeKMSPATScope(authz *proto.AuthzContext, action string) error {
	if authz == nil || !authz.GetIsPat() {
		return nil
	}
	if hasScope(authz.GetScopes(), "kms:*") {
		return nil
	}
	for _, scope := range requiredKMSScopes(action) {
		if hasScope(authz.GetScopes(), scope) {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "KMS request denied by scope")
}

func requiredKMSScopes(action string) []string {
	switch action {
	case kmsActionCreateKey:
		return []string{"kms:create"}
	case kmsActionEncrypt:
		return []string{"kms:encrypt"}
	case kmsActionDecrypt:
		return []string{"kms:decrypt"}
	case kmsActionSign:
		return []string{"kms:sign"}
	case kmsActionEncapsulate:
		return []string{"kms:encapsulate"}
	case kmsActionDecapsulate:
		return []string{"kms:decapsulate"}
	case kmsActionGenerateDataKey:
		return []string{"kms:generate-data-key"}
	case kmsActionRotateKey:
		return []string{"kms:rotate"}
	case kmsActionGetImportParameters, kmsActionImportKeyMaterial, kmsActionImportKeyMaterialVersion:
		return []string{"kms:import"}
	case kmsActionRegisterExportWrappingKey, kmsActionExportKeyMaterial:
		return []string{"kms:export"}
	case kmsActionDeleteKey:
		return []string{"kms:delete"}
	default:
		return nil
	}
}

func hasScope(scopes []string, want string) bool {
	for _, scope := range scopes {
		if strings.EqualFold(strings.TrimSpace(scope), want) {
			return true
		}
	}
	return false
}

func kmsPrincipalID(clientID string, authz *proto.AuthzContext) string {
	if authz != nil && authz.GetCredentialId() != "" {
		return "credential/" + authz.GetCredentialId()
	}
	return "client/" + tenantNamespace(clientID)
}

func kmsPrincipalAttrs(owner, clientID string, authz *proto.AuthzContext) cedar.RecordMap {
	isPAT := authz != nil && authz.GetIsPat()
	attrs := cedar.RecordMap{
		"owner":                 cedar.String(owner),
		"client_id":             cedar.String(clientID),
		"is_pat":                cedar.Boolean(isPAT),
		"legacy":                cedar.Boolean(!isPAT),
		"can_create":            cedar.Boolean(!isPAT || kmsActionAllowedByScope(authz, kmsActionCreateKey)),
		"can_encrypt":           cedar.Boolean(!isPAT || kmsActionAllowedByScope(authz, kmsActionEncrypt)),
		"can_decrypt":           cedar.Boolean(!isPAT || kmsActionAllowedByScope(authz, kmsActionDecrypt)),
		"can_sign":              cedar.Boolean(!isPAT || kmsActionAllowedByScope(authz, kmsActionSign)),
		"can_encapsulate":       cedar.Boolean(!isPAT || kmsActionAllowedByScope(authz, kmsActionEncapsulate)),
		"can_decapsulate":       cedar.Boolean(!isPAT || kmsActionAllowedByScope(authz, kmsActionDecapsulate)),
		"can_generate_data_key": cedar.Boolean(!isPAT || kmsActionAllowedByScope(authz, kmsActionGenerateDataKey)),
		"can_rotate":            cedar.Boolean(!isPAT || kmsActionAllowedByScope(authz, kmsActionRotateKey)),
		"can_import":            cedar.Boolean(!isPAT || kmsActionAllowedByScope(authz, kmsActionImportKeyMaterial)),
		"can_export":            cedar.Boolean(!isPAT || kmsActionAllowedByScope(authz, kmsActionExportKeyMaterial)),
		"can_delete":            cedar.Boolean(!isPAT || kmsActionAllowedByScope(authz, kmsActionDeleteKey)),
	}
	if authz != nil && authz.GetCredentialId() != "" {
		attrs["credential_id"] = cedar.String(authz.GetCredentialId())
	}
	return attrs
}

func kmsActionAllowedByScope(authz *proto.AuthzContext, action string) bool {
	return authorizeKMSPATScope(&proto.AuthzContext{
		IsPat:        true,
		CredentialId: authz.GetCredentialId(),
		Scopes:       authz.GetScopes(),
	}, action) == nil
}

func kmsResourceAttrs(owner string, resource kmsPolicyResource) cedar.RecordMap {
	attrs := cedar.RecordMap{
		"owner":       cedar.String(owner),
		"public_only": cedar.Boolean(resource.PublicOnly),
	}
	if resource.KeyID != "" {
		attrs["key_id"] = cedar.String(resource.KeyID)
	}
	if resource.Alias != "" {
		attrs["alias"] = cedar.String(resource.Alias)
	}
	if resource.Scheme != "" {
		attrs["scheme"] = cedar.String(resource.Scheme)
	}
	if resource.KeySpec != "" {
		attrs["key_spec"] = cedar.String(resource.KeySpec)
	}
	if resource.KeyUsage != "" {
		attrs["key_usage"] = cedar.String(resource.KeyUsage)
	}
	if resource.Origin != "" {
		attrs["origin"] = cedar.String(resource.Origin)
	}
	return attrs
}

func kmsResourceID(owner string, resource kmsPolicyResource) string {
	if resource.KeyID != "" {
		return "owners/" + owner + "/" + resource.KeyID
	}
	if resource.Alias != "" {
		return "owners/" + owner + "/" + resource.Alias
	}
	return "owners/" + owner
}
