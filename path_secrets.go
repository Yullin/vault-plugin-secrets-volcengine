package volcengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const secretType = "volcengine"

func (b *backend) pathSecrets() *framework.Secret {
	return &framework.Secret{
		Type: secretType,
		Fields: map[string]*framework.FieldSchema{
			"access_key": {
				Type:        framework.TypeString,
				Description: "Access Key",
			},
			"secret_key": {
				Type:        framework.TypeString,
				Description: "Secret Key",
			},
		},
		Renew:  b.operationRenew,
		Revoke: b.operationRevoke,
	}
}

func (b *backend) operationRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleTypeRaw, ok := req.Secret.InternalData["role_type"]
	if !ok {
		return nil, errors.New("role_type missing from secret")
	}
	nameOfRoleType, ok := roleTypeRaw.(string)
	if !ok {
		return nil, fmt.Errorf("unable to read role_type: %+v", roleTypeRaw)
	}
	rType, err := parseRoleType(nameOfRoleType)
	if err != nil {
		return nil, err
	}

	switch rType {
	case roleTypeSTS:
		return nil, nil

	case roleTypeIAM:
		// Phase 2: will read role TTL and extend lease
		return nil, nil

	default:
		return nil, fmt.Errorf("unrecognized role_type: %s", nameOfRoleType)
	}
}

func (b *backend) operationRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roleTypeRaw, ok := req.Secret.InternalData["role_type"]
	if !ok {
		return nil, errors.New("role_type missing from secret")
	}
	nameOfRoleType, ok := roleTypeRaw.(string)
	if !ok {
		return nil, fmt.Errorf("unable to read role_type: %+v", roleTypeRaw)
	}
	rType, err := parseRoleType(nameOfRoleType)
	if err != nil {
		return nil, err
	}

	switch rType {
	case roleTypeSTS:
		return nil, nil

	case roleTypeIAM:
		// Phase 2: will clean up IAM user, policies, and access keys
		return nil, nil

	default:
		return nil, fmt.Errorf("unrecognized role_type: %s", nameOfRoleType)
	}
}
