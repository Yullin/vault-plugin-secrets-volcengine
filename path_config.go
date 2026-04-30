package volcengine

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const operationPrefixVolcengine = "volcengine"

func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixVolcengine,
		},
		Fields: map[string]*framework.FieldSchema{
			"access_key": {
				Type:        framework.TypeString,
				Description: "Access key with appropriate permissions.",
			},
			"secret_key": {
				Type:        framework.TypeString,
				Description: "Secret key with appropriate permissions.",
			},
			"region": {
				Type:        framework.TypeString,
				Description: "The region for API calls, e.g. cn-beijing.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.operationConfigCreate,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "create",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.operationConfigUpdate,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "configure",
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.operationConfigRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "configuration",
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.operationConfigDelete,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "configuration",
				},
			},
		},
		ExistenceCheck:  b.operationConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

func (b *backend) operationConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *backend) operationConfigCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.configCreateOrUpdate(ctx, req, data)
}

func (b *backend) operationConfigUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.configCreateOrUpdate(ctx, req, data)
}

func (b *backend) configCreateOrUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	accessKey := ""
	if v, ok := data.GetOk("access_key"); ok {
		accessKey = v.(string)
	} else {
		return nil, errors.New("access_key is required")
	}

	secretKey := ""
	if v, ok := data.GetOk("secret_key"); ok {
		secretKey = v.(string)
	} else {
		return nil, errors.New("secret_key is required")
	}

	region := ""
	if v, ok := data.GetOk("region"); ok {
		region = v.(string)
	} else {
		return nil, errors.New("region is required")
	}

	entry, err := logical.StorageEntryJSON("config", credConfig{
		AccessKey: accessKey,
		SecretKey: secretKey,
		Region:    region,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) operationConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	creds, err := readCredentials(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if creds == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"access_key": creds.AccessKey,
			"region":     creds.Region,
		},
	}, nil
}

func (b *backend) operationConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "config"); err != nil {
		return nil, err
	}
	return nil, nil
}

func readCredentials(ctx context.Context, storage logical.Storage) (*credConfig, error) {
	entry, err := storage.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	creds := &credConfig{}
	if err := entry.DecodeJSON(creds); err != nil {
		return nil, err
	}
	return creds, nil
}

type credConfig struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	Region    string `json:"region"`
}

const pathConfigHelpSyn = `
Configure the access key, secret key, and region for Volcengine API calls.
`

const pathConfigHelpDesc = `
Before doing anything, the Volcengine backend needs credentials that are able
to manage IAM users, policies, and access keys, and that can call STS AssumeRole.
This endpoint is used to configure those credentials and the target region.
`
