package volcengine

import (
	"context"
	"encoding/json"
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
		client, err := clients.NewIAMClient(creds.AccessKey, creds.SecretKey, creds.Region)
		if err != nil {
			return nil, err
		}

		success := false
		userName := generateUsername(req.DisplayName, roleName)

		createUserResp, err := client.CreateUser(userName)
		if err != nil {
			return nil, err
		}
		defer func() {
			if success {
				return
			}
			if err := client.DeleteUser(userName); err != nil {
				b.Logger().Error(fmt.Sprintf("unable to delete user %s", userName), "error", err)
			}
		}()

		inlinePolicies := make([]*remotePolicy, len(role.InlinePolicies))

		for i, inlinePol := range role.InlinePolicies {
			policyName := generateName("vault", inlinePol.UUID, 64)

			policyDoc, err := json.Marshal(inlinePol.PolicyDocument)
			if err != nil {
				return nil, err
			}

			createPolicyResp, err := client.CreatePolicy(policyName, string(policyDoc))
			if err != nil {
				return nil, err
			}

			inlinePolicies[i] = &remotePolicy{
				Name: *createPolicyResp.Policy.PolicyName,
				Type: *createPolicyResp.Policy.PolicyType,
			}

			polName := *createPolicyResp.Policy.PolicyName
			polType := *createPolicyResp.Policy.PolicyType
			defer func() {
				if success {
					return
				}
				_ = client.DetachUserPolicy(userName, polName, polType)
				if err := client.DeletePolicy(polName); err != nil {
					b.Logger().Error(fmt.Sprintf("unable to delete policy %s", polName), "error", err)
				}
			}()

			if err := client.AttachUserPolicy(userName, polName, polType); err != nil {
				return nil, err
			}
		}

		for _, remotePol := range role.RemotePolicies {
			if err := client.AttachUserPolicy(userName, remotePol.Name, remotePol.Type); err != nil {
				return nil, err
			}
			rPolName := remotePol.Name
			rPolType := remotePol.Type
			defer func() {
				if success {
					return
				}
				if err := client.DetachUserPolicy(userName, rPolName, rPolType); err != nil {
					b.Logger().Error(fmt.Sprintf("unable to detach policy %s from user %s", rPolName, userName), "error", err)
				}
			}()
		}

		accessKeyResp, err := client.CreateAccessKey(*createUserResp.User.UserName)
		if err != nil {
			return nil, err
		}
		defer func() {
			if success {
				return
			}
			if err := client.DeleteAccessKey(*accessKeyResp.AccessKey.AccessKeyId, userName); err != nil {
				b.Logger().Error(fmt.Sprintf("unable to delete access key for user %s", userName), "error", err)
			}
		}()

		resp := b.Secret(secretType).Response(map[string]interface{}{
			"access_key": *accessKeyResp.AccessKey.AccessKeyId,
			"secret_key": *accessKeyResp.AccessKey.SecretAccessKey,
		}, map[string]interface{}{
			"role_type":       roleTypeIAM.String(),
			"role_name":       roleName,
			"username":        userName,
			"access_key_id":   *accessKeyResp.AccessKey.AccessKeyId,
			"inline_policies": inlinePolicies,
			"remote_policies": role.RemotePolicies,
		})
		if role.TTL != 0 {
			resp.Secret.TTL = role.TTL
		}
		if role.MaxTTL != 0 {
			resp.Secret.MaxTTL = role.MaxTTL
		}

		success = true
		return resp, nil

	default:
		return nil, fmt.Errorf("unsupported role type: %s", role.Type())
	}
}

func generateRoleSessionName(displayName, roleName string) string {
	return generateName(displayName, roleName, 32)
}

func generateUsername(displayName, roleName string) string {
	return generateName(displayName, roleName, 64)
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
