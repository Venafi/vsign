package getcred

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/vsign"
)

func TestGetCred(t *testing.T) {
	testCases := []struct {
		description  string
		url          string
		username     string
		password     string
		trust_bundle string
		expected     []string
	}{
		{
			description:  "Valid vh.venafilab.com credential",
			url:          "https://vh.venafilab.com",
			username:     "sample-cs-user",
			password:     "Passw0rd123!",
			trust_bundle: "",
			expected:     nil,
		},
		{
			description:  "Invalid vh.venafilab.com credential password",
			url:          "https://vh.venafilab.com",
			username:     "sample-cs-user",
			password:     "Passw0rd123",
			trust_bundle: "",
			expected:     []string{"unexpected status code on TPP Authorize. Status: 400 Bad Request, Details: Authentication error. Error ID: invalid_grant Description: Username/password combination not valid"},
		},
		{
			description:  "Invalid vh.venafilab.com credential username",
			url:          "https://vh.venafilab.com",
			username:     "invalid-cs-user",
			password:     "Passw0rd123!",
			trust_bundle: "",
			expected:     []string{"unexpected status code on TPP Authorize. Status: 400 Bad Request, Details: Authentication error. Error ID: invalid_grant Description: Username/password combination not valid"},
		},
		{
			description:  "Invalid vsign-sdk API access",
			url:          "https://vh.venafilab.com",
			username:     "sample-gpg-user",
			password:     "Passw0rd123!",
			trust_bundle: "",
			expected:     []string{"unexpected status code on TPP Authorize. Status: 400 Bad Request, Details: Authentication error. Error ID: unauthorized_client Description: No rule/permission for identity local:sample-gpg-user exists"},
		},
	}

	err := setTLSConfig()
	if err != nil {
		t.Error("setTLSConfig error")
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cfg, err := vsign.BuildConfigWithAuth(context.TODO(), tc.url, &endpoint.Authentication{User: tc.username, Password: tc.password, JWT: ""}, tc.trust_bundle)
			if err != nil {
				t.Error("error building config")
			}

			connector, err := vsign.NewClient(&cfg)
			if err != nil {
				t.Error("error")
			}

			auth := &endpoint.Authentication{
				User:     tc.username,
				Password: tc.password,
				Scope:    endpoint.DefaultScope,
				ClientId: endpoint.DefaultClientID}

			_, err = connector.GetCredential(auth)
			var errs []string
			if err != nil {
				errs = append(errs, err.Error())
				require.Equal(t, tc.expected, errs)

			}

		})
	}
}
