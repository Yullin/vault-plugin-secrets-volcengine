package clients

import (
	"github.com/volcengine/volcengine-go-sdk/service/iam"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
)

type IAMClient struct {
	client *iam.IAM
}

func NewIAMClient(accessKey, secretKey, region string) (*IAMClient, error) {
	sess, err := newSession(accessKey, secretKey, region)
	if err != nil {
		return nil, err
	}
	client := iam.New(sess)
	return &IAMClient{client: client}, nil
}

func (c *IAMClient) CreateUser(userName string) (*iam.CreateUserOutput, error) {
	input := &iam.CreateUserInput{
		UserName:    volcengine.String(userName),
		DisplayName: volcengine.String(userName),
	}
	return c.client.CreateUser(input)
}

func (c *IAMClient) DeleteUser(userName string) error {
	input := &iam.DeleteUserInput{
		UserName: volcengine.String(userName),
	}
	_, err := c.client.DeleteUser(input)
	return err
}

func (c *IAMClient) CreateAccessKey(userName string) (*iam.CreateAccessKeyOutput, error) {
	input := &iam.CreateAccessKeyInput{
		UserName: volcengine.String(userName),
	}
	return c.client.CreateAccessKey(input)
}

func (c *IAMClient) DeleteAccessKey(accessKeyID, userName string) error {
	input := &iam.DeleteAccessKeyInput{
		AccessKeyId: volcengine.String(accessKeyID),
		UserName:    volcengine.String(userName),
	}
	_, err := c.client.DeleteAccessKey(input)
	return err
}

func (c *IAMClient) CreatePolicy(policyName, policyDocument string) (*iam.CreatePolicyOutput, error) {
	input := &iam.CreatePolicyInput{
		PolicyName:     volcengine.String(policyName),
		PolicyDocument: volcengine.String(policyDocument),
		Description:    volcengine.String("Created by Vault."),
	}
	return c.client.CreatePolicy(input)
}

func (c *IAMClient) DeletePolicy(policyName string) error {
	input := &iam.DeletePolicyInput{
		PolicyName: volcengine.String(policyName),
	}
	_, err := c.client.DeletePolicy(input)
	return err
}

func (c *IAMClient) AttachUserPolicy(userName, policyName, policyType string) error {
	input := &iam.AttachUserPolicyInput{
		UserName:   volcengine.String(userName),
		PolicyName: volcengine.String(policyName),
		PolicyType: volcengine.String(policyType),
	}
	_, err := c.client.AttachUserPolicy(input)
	return err
}

func (c *IAMClient) DetachUserPolicy(userName, policyName, policyType string) error {
	input := &iam.DetachUserPolicyInput{
		UserName:   volcengine.String(userName),
		PolicyName: volcengine.String(policyName),
		PolicyType: volcengine.String(policyType),
	}
	_, err := c.client.DetachUserPolicy(input)
	return err
}
