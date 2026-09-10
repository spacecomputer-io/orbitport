package kms

import (
	_ "embed"
	"fmt"
	"os"

	cedar "github.com/cedar-policy/cedar-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultKeyStorePolicyName = "key-store-default.cedar"
	keyStorePrincipalType     = "KmsClient"
	keyStoreKeyType           = "KeyStoreKey"
	keyStoreNamespaceType     = "KeyStoreNamespace"
	keyStoreActionType        = "Action"
)

//go:embed cedar/key_store_default.cedar
var defaultKeyStorePolicy []byte

type keyStoreAuthorizer struct {
	policies *cedar.PolicySet
}

func newKeyStoreAuthorizer(cfg *kmsConfig) (*keyStoreAuthorizer, error) {
	policies := cedar.NewPolicySet()
	if cfg.KeyStoreCedarDefaultOwnerPolicy {
		if err := addPolicyDocument(policies, defaultKeyStorePolicyName, defaultKeyStorePolicy); err != nil {
			return nil, err
		}
	}
	if cfg.KeyStoreCedarPolicyPath != "" {
		document, err := os.ReadFile(cfg.KeyStoreCedarPolicyPath)
		if err != nil {
			return nil, fmt.Errorf("read key-store Cedar policy: %w", err)
		}
		if err := addPolicyDocument(policies, cfg.KeyStoreCedarPolicyPath, document); err != nil {
			return nil, err
		}
	}
	return &keyStoreAuthorizer{policies: policies}, nil
}

func addPolicyDocument(target *cedar.PolicySet, fileName string, document []byte) error {
	policies, err := cedar.NewPolicySetFromBytes(fileName, document)
	if err != nil {
		return fmt.Errorf("parse Cedar policy %s: %w", fileName, err)
	}
	for policyID, policy := range policies.All() {
		target.Add(cedar.PolicyID(fileName+":"+string(policyID)), policy)
	}
	return nil
}

func (a *keyStoreAuthorizer) authorize(clientID, action, resourceType, name, prefix string) error {
	if a == nil || a.policies == nil {
		return status.Error(codes.PermissionDenied, "key-store request denied by policy")
	}

	owner := tenantNamespace(clientID)
	principalUID := cedar.NewEntityUID(keyStorePrincipalType, cedar.String(owner))
	resourceUID := cedar.NewEntityUID(cedar.EntityType(resourceType), cedar.String(keyStoreResourceID(owner, name, prefix)))

	principalAttrs := cedar.NewRecord(cedar.RecordMap{
		"owner":     cedar.String(owner),
		"client_id": cedar.String(clientID),
	})
	resourceAttrs := cedar.RecordMap{
		"owner": cedar.String(owner),
	}
	if name != "" {
		resourceAttrs["name"] = cedar.String(name)
	}
	if prefix != "" {
		resourceAttrs["prefix"] = cedar.String(prefix)
	}

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
			Attributes: cedar.NewRecord(resourceAttrs),
			Tags:       cedar.NewRecord(nil),
		},
	}

	context := cedar.RecordMap{
		"client_id": cedar.String(clientID),
		"owner":     cedar.String(owner),
	}
	if name != "" {
		context["name"] = cedar.String(name)
	}
	if prefix != "" {
		context["prefix"] = cedar.String(prefix)
	}

	decision, diagnostic := cedar.Authorize(a.policies, entities, cedar.Request{
		Principal: principalUID,
		Action:    cedar.NewEntityUID(keyStoreActionType, cedar.String(action)),
		Resource:  resourceUID,
		Context:   cedar.NewRecord(context),
	})
	if len(diagnostic.Errors) > 0 {
		logger.Warnf("key-store Cedar evaluation errors action=%s owner=%s errors=%v", action, owner, diagnostic.Errors)
		return status.Error(codes.PermissionDenied, "key-store request denied by policy")
	}
	if decision != cedar.Allow {
		logger.Warnf("key-store Cedar denied action=%s owner=%s resource=%s", action, owner, resourceUID.String())
		return status.Error(codes.PermissionDenied, "key-store request denied by policy")
	}
	return nil
}

func keyStoreResourceID(owner, name, prefix string) string {
	if name != "" {
		return "owners/" + owner + "/" + name
	}
	if prefix != "" {
		return "owners/" + owner + "/" + prefix
	}
	return "owners/" + owner
}
