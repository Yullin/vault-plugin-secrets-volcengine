package volcengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Yullin/vault-plugin-secrets-volcengine/clients"
	"github.com/hashicorp/go-multierror"
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
		roleName, err := getStringValue(req.Secret.InternalData, "role_name")
		if err != nil {
			return nil, err
		}

		role, err := readRole(ctx, req.Storage, roleName)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return nil, fmt.Errorf("role %s has been deleted so no further renewals are allowed", roleName)
		}

		resp := &logical.Response{Secret: req.Secret}
		if role.TTL != 0 {
			resp.Secret.TTL = role.TTL
		}
		if role.MaxTTL != 0 {
			resp.Secret.MaxTTL = role.MaxTTL
		}
		return resp, nil

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
		creds, err := readCredentials(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		if creds == nil {
			return nil, errors.New("unable to delete access key because no credentials are configured")
		}
		client, err := clients.NewIAMClient(creds.AccessKey, creds.SecretKey, creds.Region)
		if err != nil {
			return nil, err
		}

		userName, err := getStringValue(req.Secret.InternalData, "username")
		if err != nil {
			return nil, err
		}

		accessKeyID, err := getStringValue(req.Secret.InternalData, "access_key_id")
		if err != nil {
			return nil, err
		}

		apiErrs := &multierror.Error{}

		if err := client.DeleteAccessKey(accessKeyID, userName); err != nil {
			apiErrs = multierror.Append(apiErrs, err)
		}

		inlinePolicies, err := getRemotePolicies(req.Secret.InternalData, "inline_policies")
		if err != nil {
			return nil, err
		}
		for _, inlinePolicy := range inlinePolicies {
			if err := client.DetachUserPolicy(userName, inlinePolicy.Name, inlinePolicy.Type); err != nil {
				apiErrs = multierror.Append(apiErrs, err)
			}
			if err := client.DeletePolicy(inlinePolicy.Name); err != nil {
				apiErrs = multierror.Append(apiErrs, err)
			}
		}

		remotePolicies, err := getRemotePolicies(req.Secret.InternalData, "remote_policies")
		if err != nil {
			return nil, err
		}
		for _, rp := range remotePolicies {
			if err := client.DetachUserPolicy(userName, rp.Name, rp.Type); err != nil {
				apiErrs = multierror.Append(apiErrs, err)
			}
		}

		if err := client.DeleteUser(userName); err != nil {
			apiErrs = multierror.Append(apiErrs, err)
		}

		return nil, apiErrs.ErrorOrNil()

	default:
		return nil, fmt.Errorf("unrecognized role_type: %s", nameOfRoleType)
	}
}

func getStringValue(internalData map[string]interface{}, key string) (string, error) {
	valueRaw, ok := internalData[key]
	if !ok {
		return "", fmt.Errorf("secret is missing %s internal data", key)
	}
	value, ok := valueRaw.(string)
	if !ok {
		return "", fmt.Errorf("secret is missing %s internal data", key)
	}
	return value, nil
}

func getRemotePolicies(internalData map[string]interface{}, key string) ([]*remotePolicy, error) {
	valuesRaw, ok := internalData[key]
	if !ok {
		return nil, nil
	}

	valuesJSON, err := json.Marshal(valuesRaw)
	if err != nil {
		return nil, fmt.Errorf("malformed %s internal data", key)
	}

	var policies []*remotePolicy
	if err := json.Unmarshal(valuesJSON, &policies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s internal data as remotePolicy", key)
	}
	return policies, nil
}
