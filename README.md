# Vault Plugin: Volcengine Secrets Backend

This is a backend plugin to be used with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin generates unique, ephemeral API keys and STS credentials for [Volcengine](https://www.volcengine.com/).

## Quick Links
- [Vault Website](https://www.vaultproject.io)
- [Vault Github](https://www.github.com/hashicorp/vault)
- [Volcengine IAM Documentation](https://www.volcengine.com/docs/6257)

## Usage

This is a [Vault plugin](https://developer.hashicorp.com/vault/docs/plugins)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works. Otherwise, first read this guide on
how to [get started with Vault](https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-install).

### Setup

1. Register and enable the plugin:

```sh
$ vault plugin register \
    -sha256="$(shasum -a 256 path/to/vault-plugin-secrets-volcengine | cut -d " " -f1)" \
    -command="vault-plugin-secrets-volcengine" \
    secret \
    volcengine

$ vault secrets enable -path=volcengine volcengine
Success! Enabled the volcengine secrets engine at: volcengine/
```

2. Configure the credentials and region that will be used to communicate with Volcengine:

```sh
$ vault write volcengine/config \
    access_key="AKXXXXXXXXXXXXXXXXXX" \
    secret_key="SKXXXXXXXXXXXXXXXXXX" \
    region="cn-beijing"
```

3. Configure a role that maps a name in Vault to a Volcengine role TRN (for STS credentials):

```sh
$ vault write volcengine/role/my-role \
    role_trn="trn:iam::200000000:role/my-volcengine-role"
```

### Generate Credentials

To generate STS temporary credentials, read from the `creds` endpoint with the name of the role:

```sh
$ vault read volcengine/creds/my-role
Key                Value
---                -----
lease_id           volcengine/creds/my-role/f3e92392-7d9c-09c8-c921-575d62fe80d8
lease_duration     59m59s
lease_renewable    false
access_key         STS.XXXXXXXXXXXXXXXXXX
expiration         2026-06-01T12:00:00+08:00
secret_key         XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
security_token     XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

## Role Types

This plugin supports two role types:

### STS AssumeRole

When a `role_trn` is provided, the credentials endpoint will call Volcengine STS AssumeRole
and return temporary credentials. These credentials are short-lived and cannot be renewed or revoked.

```sh
$ vault write volcengine/role/sts-role \
    role_trn="trn:iam::200000000:role/my-role"
```

### IAM User (Dynamic)

When `inline_policies` or `remote_policies` are provided instead of a `role_trn`,
the plugin dynamically creates an IAM user, attaches the specified policies, and generates
an access key. These credentials are renewable and are fully revoked (access key deleted,
policies detached, user removed) when the lease expires or is manually revoked.

```sh
$ vault write volcengine/role/iam-role \
    remote_policies="name:ReadOnlyAccess,type:System" \
    ttl="1h" \
    max_ttl="24h"

$ vault read volcengine/creds/iam-role
Key                Value
---                -----
lease_id           volcengine/creds/iam-role/abcd1234-5678-90ab-cdef-1234567890ab
lease_duration     1h
lease_renewable    true
access_key         AKXXXXXXXXXXXXXXXXXX
secret_key         SKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

You can also use inline policies for fine-grained access:

```sh
$ vault write volcengine/role/inline-role \
    inline_policies='[{"Statement":[{"Effect":"Allow","Action":["ecs:Describe*"],"Resource":["*"]}]}]' \
    ttl="2h"
```

## API

### `/config`

#### POST

Configure the Volcengine credentials and region.

**Parameters:**
- `access_key` (string, required) — Volcengine access key ID.
- `secret_key` (string, required) — Volcengine secret access key.
- `region` (string, required) — Volcengine region, e.g. `cn-beijing`.

#### GET

Return the current configuration (excluding `secret_key`).

#### DELETE

Delete the current configuration.

### `/role/:name`

#### POST

Create or update a role.

**Parameters:**
- `role_trn` (string) — TRN of the role to assume via STS. Mutually exclusive with policy fields.
- `inline_policies` (string) — JSON array of policy documents for dynamic IAM user creation.
- `remote_policies` (list) — List of existing policies in `name:PolicyName,type:Type` format.
- `ttl` (duration) — Default TTL for credentials.
- `max_ttl` (duration) — Maximum TTL for credentials.

#### GET

Return the role configuration.

#### DELETE

Delete the role.

#### LIST `/role`

List all configured roles.

### `/creds/:name`

#### GET

Generate credentials based on the named role's configuration.

**Returns (STS type):**
- `access_key` — Temporary access key ID.
- `secret_key` — Temporary secret access key.
- `security_token` — STS session token.
- `expiration` — Credential expiration time.

**Returns (IAM type):**
- `access_key` — IAM user access key ID.
- `secret_key` — IAM user secret access key.

## Developing

If you wish to work on this plugin, you'll first need [Go](https://www.golang.org)
installed on your machine.

### Build

```sh
$ make build
```

This will put the plugin binary in the `vault/plugins/` folder.

### Tests

```sh
$ make test
```

### Install Plugin in Vault

Put the plugin binary into a location of your choice. This directory
will be specified as the [`plugin_directory`](https://developer.hashicorp.com/vault/docs/configuration#plugin_directory)
in the Vault config used to start the server.

```hcl
plugin_directory = "path/to/plugin/directory"
```

Start a Vault server with this config file:
```sh
$ vault server -config=path/to/config.json
```

Once the server is started, register the plugin in the Vault server's [plugin catalog](https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture#plugin-catalog):

```sh
$ vault plugin register \
    -sha256="$(shasum -a 256 path/to/plugin/directory/vault-plugin-secrets-volcengine | cut -d " " -f1)" \
    -command="vault-plugin-secrets-volcengine" \
    secret \
    volcengine
```

Enable the secrets engine:

```sh
$ vault secrets enable -path=volcengine volcengine
```
