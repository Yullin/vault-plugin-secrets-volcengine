package volcengine

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	b := newBackend()
	storage := &logical.InmemStorage{}
	config := &logical.BackendConfig{
		StorageView: storage,
		Logger:      hclog.NewNullLogger(),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: 24 * time.Hour,
			MaxLeaseTTLVal:     48 * time.Hour,
		},
	}
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	return b, storage
}

func TestConfigCRUD(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create config
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"access_key": "test-access-key",
			"secret_key": "test-secret-key",
			"region":     "cn-beijing",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatalf("expected nil response, got %v", resp)
	}

	// Read config
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Data["access_key"] != "test-access-key" {
		t.Fatalf("expected access_key 'test-access-key', got %s", resp.Data["access_key"])
	}
	if resp.Data["region"] != "cn-beijing" {
		t.Fatalf("expected region 'cn-beijing', got %s", resp.Data["region"])
	}
	if _, ok := resp.Data["secret_key"]; ok {
		t.Fatal("secret_key should not be returned in read")
	}

	// Delete config
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	// Verify deleted
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatalf("expected nil response after delete, got %v", resp)
	}
}

func TestRoleCRUD_STS(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create STS role
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-sts-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"role_trn": "trn:iam::1234567890:role/test-role",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	// Read role
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-sts-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Data["role_trn"] != "trn:iam::1234567890:role/test-role" {
		t.Fatalf("unexpected role_trn: %v", resp.Data["role_trn"])
	}

	// List roles
	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role/",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected response for list, got nil")
	}
	keys := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "test-sts-role" {
		t.Fatalf("unexpected list result: %v", keys)
	}

	// Delete role
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/test-sts-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	// Verify deleted
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-sts-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatalf("expected nil response after delete, got %v", resp)
	}
}

func TestRoleValidation_STSWithPolicies(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// STS role with remote_policies should fail
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"role_trn":        "trn:iam::1234567890:role/test-role",
			"remote_policies": []string{"name:SomePolicy,type:System"},
		},
	}
	_, err := b.HandleRequest(ctx, req)
	if err == nil {
		t.Fatal("expected error when STS role has remote_policies")
	}
}

func TestRoleValidation_NoPoliciesOrTRN(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Role with neither role_trn nor policies should fail
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/empty-role",
		Storage:   storage,
		Data:      map[string]interface{}{},
	}
	_, err := b.HandleRequest(ctx, req)
	if err == nil {
		t.Fatal("expected error when role has neither role_trn nor policies")
	}
}

func TestCredsRead_NoConfig(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create a role first
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"role_trn": "trn:iam::1234567890:role/test-role",
		},
	}
	_, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	// Try to read creds without config
	req = &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "creds/test-role",
		Storage:     storage,
		DisplayName: "test",
	}
	_, err = b.HandleRequest(ctx, req)
	if err == nil {
		t.Fatal("expected error when no config is set")
	}
	if err.Error() != "unable to create secret because no credentials are configured" {
		t.Fatalf("unexpected error: %v", err)
	}
}
