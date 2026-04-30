package volcengine

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func newBackend() logical.Backend {
	var b backend
	b.Backend = &framework.Backend{
		Help:        backendHelp,
		BackendType: logical.TypeLogical,
	}
	return &b
}

type backend struct {
	*framework.Backend
}

const backendHelp = `
The Volcengine backend dynamically generates Volcengine access keys for a set of
IAM policies. The Volcengine access keys have a configurable ttl set and
are automatically revoked at the end of the ttl.

After mounting this backend, credentials to generate IAM keys must
be configured and roles must be written using
the "role/" endpoints before any access keys can be generated.
`
