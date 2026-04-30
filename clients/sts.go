package clients

import (
	"github.com/volcengine/volcengine-go-sdk/service/sts"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
)

type STSClient struct {
	client *sts.STS
}

func NewSTSClient(accessKey, secretKey, region string) (*STSClient, error) {
	sess, err := newSession(accessKey, secretKey, region)
	if err != nil {
		return nil, err
	}
	client := sts.New(sess)
	return &STSClient{client: client}, nil
}

func (c *STSClient) AssumeRole(roleSessionName, roleTrn string) (*sts.AssumeRoleOutput, error) {
	input := &sts.AssumeRoleInput{
		RoleSessionName: volcengine.String(roleSessionName),
		RoleTrn:         volcengine.String(roleTrn),
	}
	return c.client.AssumeRole(input)
}
