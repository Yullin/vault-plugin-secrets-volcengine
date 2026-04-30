package volcengine

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/Yullin/vault-plugin-secrets-volcengine/clients"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathCreds() *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixVolcengine,
			OperationVerb:   "generate",
			OperationSuffix: "credentials",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "The name of the role.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.operationCredsRead,
		},
		HelpSynopsis:    pathCredsHelpSyn,
		HelpDescription: pathCredsHelpDesc,
	}
}

func (b *backend) operationCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return nil, errors.New("name is required")
	}

	role, err := readRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	creds, err := readCredentials(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if creds == nil {
		return nil, errors.New("unable to create secret because no credentials are configured")
	}

	switch role.Type() {
	case roleTypeSTS:
		client, err := clients.NewSTSClient(creds.AccessKey, creds.SecretKey, creds.Region)
		if err != nil {
			return nil, err
		}
		assumeRoleResp, err := client.AssumeRole(generateRoleSessionName(req.DisplayName, roleName), role.RoleTRN)
		if err != nil {
			return nil, err
		}

		expiration, err := time.Parse("2006-01-02T15:04:05+08:00", *assumeRoleResp.Credentials.ExpiredTime)
		if err != nil {
			expiration, err = time.Parse(time.RFC3339, *assumeRoleResp.Credentials.ExpiredTime)
			if err != nil {
				return nil, fmt.Errorf("unable to parse expiration time: %s", *assumeRoleResp.Credentials.ExpiredTime)
			}
		}

		resp := b.Secret(secretType).Response(map[string]interface{}{
			"access_key":     *assumeRoleResp.Credentials.AccessKeyId,
			"secret_key":     *assumeRoleResp.Credentials.SecretAccessKey,
			"security_token": *assumeRoleResp.Credentials.SessionToken,
			"expiration":     expiration,
		}, map[string]interface{}{
			"role_type": roleTypeSTS.String(),
		})

		ttl := time.Until(expiration)
		resp.Secret.TTL = ttl
		resp.Secret.MaxTTL = ttl
		resp.Secret.Renewable = false
		return resp, nil

	case roleTypeIAM:
		return nil, errors.New("IAM role type is not yet supported, coming in Phase 2")

	default:
		return nil, fmt.Errorf("unsupported role type: %s", role.Type())
	}
}

func generateRoleSessionName(displayName, roleName string) string {
	return generateName(displayName, roleName, 32)
}

func generateName(displayName, roleName string, maxLength int) string {
	name := fmt.Sprintf("%s-%s-", displayName, roleName)
	if len(name) > maxLength-15 {
		name = name[:maxLength-15]
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return fmt.Sprintf("%s%d-%d", name, time.Now().Unix(), r.Intn(10000))
}

const pathCredsHelpSyn = `
Generate an API key or STS credential using the given role's configuration.
`

const pathCredsHelpDesc = `
This path will generate a new API key or STS credential for
accessing Volcengine. The IAM policies used to back this key pair will be
configured on the role. For example, if this backend is mounted at "volcengine",
then "volcengine/creds/deploy" would generate access keys for the "deploy" role.

The API key or STS credential will have a ttl associated with it. API keys can
be renewed or revoked as described here:
https://www.vaultproject.io/docs/concepts/lease.html,
but STS credentials do not support renewal or revocation.
`
