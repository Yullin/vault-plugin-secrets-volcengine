package clients

import (
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

func newSession(accessKey, secretKey, region string) (*session.Session, error) {
	creds := credentials.NewChainCredentials([]credentials.Provider{
		&credentials.EnvProvider{},
		&credentials.StaticProvider{Value: credentials.Value{
			AccessKeyID:     accessKey,
			SecretAccessKey: secretKey,
		}},
	})

	sess, err := session.NewSession(&volcengine.Config{
		Region:      volcengine.String(region),
		Credentials: creds,
	})
	if err != nil {
		return nil, err
	}
	return sess, nil
}
