package jwt

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/venafi/vsign/pkg/vsign"
)

const defaultPayload = "{'sub': '1234567890','name': 'John Doe','iat': 1516239022}"

func TestJWT(t *testing.T) {
	testCases := []struct {
		description string
		header      string
		payload     string
		project     string
		expected    []string
	}{
		{
			description: "Invalid JWT signature using RS224",
			header:      "{'alg':'RS224','typ':'JWT'}",
			payload:     defaultPayload,
			project:     "vsign\\rsa2048-cert",
			expected:    []string{"unexpected error from API/Sign: Algorithm chosen is not supported."},
		},
		{
			description: "Valid JWT signature using RS256",
			header:      "{'alg':'RS256','typ':'JWT'}",
			payload:     defaultPayload,
			project:     "vsign\\rsa2048-cert",
			expected:    nil,
		},
		{
			description: "Valid JWT signature using RS384",
			header:      "{'alg':'RS384','typ':'JWT'}",
			payload:     defaultPayload,
			project:     "vsign\\rsa2048-cert",
			expected:    nil,
		},
		{
			description: "Valid JWT signature using RS512",
			header:      "{'alg':'RS512','typ':'JWT'}",
			payload:     defaultPayload,
			project:     "vsign\\rsa2048-cert",
			expected:    nil,
		},
		{
			description: "Invalid JWT signature using ES224",
			header:      "{'alg':'ES224','typ':'JWT'}",
			payload:     defaultPayload,
			project:     "vsign\\p256-cert",
			expected:    []string{"unexpected error from API/Sign: Algorithm chosen is not supported."},
		},
		{
			description: "Valid JWT signature using ES256",
			header:      "{'alg':'ES256','typ':'JWT'}",
			payload:     defaultPayload,
			project:     "vsign\\p256-cert",
			expected:    nil,
		},
		{
			description: "Valid JWT signature using ES384",
			header:      "{'alg':'ES384','typ':'JWT'}",
			payload:     defaultPayload,
			project:     "vsign\\p256-cert",
			expected:    nil,
		},
		{
			description: "Valid JWT signature using ES512",
			header:      "{'alg':'ES512','typ':'JWT'}",
			payload:     defaultPayload,
			project:     "vsign\\p256-cert",
			expected:    nil,
		},
		{
			description: "Invalid JWT signature using EdDSA",
			header:      "{'alg':'EdDSA','typ':'JWT'}",
			payload:     defaultPayload,
			project:     "vsign\\ed25519",
			expected:    []string{"unexpected error from API/Sign: Algorithm chosen is not supported."},
		},
	}

	err := setTLSConfig()
	if err != nil {
		t.Error("setTLSConfig error")
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cfg, err := vsign.BuildConfig(context.TODO(), "../../../../test/config.ini")

			if err != nil {
				t.Error("error building config")
			}
			cfg.Project = tc.project
			connector, err := vsign.NewClient(&cfg)
			if err != nil {
				t.Error("error")
			}

			env, err := connector.GetEnvironment()
			if err != nil {
				t.Error("error")
			}

			_, err = connector.SignJWT(env.KeyID, base64.RawURLEncoding.EncodeToString([]byte(tc.header)), base64.RawURLEncoding.EncodeToString([]byte(tc.payload)))
			var errs []string
			if err != nil {
				errs = append(errs, err.Error())
				require.Equal(t, tc.expected, errs)
			}
		})
	}
}
