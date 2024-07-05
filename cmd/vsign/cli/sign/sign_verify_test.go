package sign

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/vsign"
)

const sample_payload = "this is a test"

func TestSign(t *testing.T) {
	testCases := []struct {
		description   string
		project       string
		payload       string
		mechanism     int
		digest        string
		publicKeyPath string
		expected      []string
	}{
		{
			description:   "RsaPkcs Sha1 valid test",
			project:       "vsign\\rsa2048-cert",
			payload:       sample_payload,
			mechanism:     c.RsaPkcs,
			digest:        "sha1",
			publicKeyPath: "../../../../test/rsa2048-cert.pub",
			expected:      nil,
		},
		{
			description:   "RsaPkcs Sha224 failure test",
			project:       "vsign\\rsa2048-cert",
			payload:       sample_payload,
			mechanism:     c.RsaPkcs,
			digest:        "sha224",
			publicKeyPath: "../../../../test/rsa2048-cert.pub",
			expected:      []string{"unexpected error from API/Sign: Private Key Access: 'sign' operation failed. More info: Error signing data (Failed to sign data using engine: 'Software', error: Call to C_Sign failed [MechanismInvalid])", "failed verification: crypto/rsa: verification error"},
		},
		{
			description:   "RsaPkcs Sha256 valid test",
			project:       "vsign\\rsa2048-cert",
			payload:       sample_payload,
			mechanism:     c.RsaPkcs,
			digest:        "sha256",
			publicKeyPath: "../../../../test/rsa2048-cert.pub",
			expected:      nil,
		},
		{
			description:   "RsaPkcs Sha384 valid test",
			project:       "vsign\\rsa2048-cert",
			payload:       sample_payload,
			mechanism:     c.RsaPkcs,
			digest:        "sha384",
			publicKeyPath: "../../../../test/rsa2048-cert.pub",
			expected:      nil,
		},
		{
			description:   "RsaPkcs Sha512 valid test",
			project:       "vsign\\rsa2048-cert",
			payload:       sample_payload,
			mechanism:     c.RsaPkcs,
			digest:        "sha512",
			publicKeyPath: "../../../../test/rsa2048-cert.pub",
			expected:      nil,
		},
		{
			description:   "RsaSha256 valid test",
			project:       "vsign\\rsa2048-cert",
			payload:       sample_payload,
			mechanism:     c.RsaSha256,
			digest:        "sha256",
			publicKeyPath: "../../../../test/rsa2048-cert.pub",
			expected:      nil,
		},
		{
			description:   "RsaSha384 valid test",
			project:       "vsign\\rsa2048-cert",
			payload:       sample_payload,
			mechanism:     c.RsaSha384,
			digest:        "sha384",
			publicKeyPath: "../../../../test/rsa2048-cert.pub",
			expected:      nil,
		},
		{
			description:   "RsaSha512 valid test",
			project:       "vsign\\rsa2048-cert",
			payload:       sample_payload,
			mechanism:     c.RsaSha512,
			digest:        "sha512",
			publicKeyPath: "../../../../test/rsa2048-cert.pub",
			expected:      nil,
		},
		{
			description:   "RsaPssSha1 valid test",
			project:       "vsign\\rsa2048-cert",
			payload:       sample_payload,
			mechanism:     c.RsaPssSha1,
			digest:        "sha1",
			publicKeyPath: "../../../../test/rsa2048-cert.pub",
			expected:      nil,
		},
		{
			description:   "RsaPssSha256 valid test",
			project:       "vsign\\rsa2048-cert",
			payload:       sample_payload,
			mechanism:     c.RsaPssSha256,
			digest:        "sha256",
			publicKeyPath: "../../../../test/rsa2048-cert.pub",
			expected:      nil,
		},
		{
			description:   "RsaPssSha384 valid test",
			project:       "vsign\\rsa2048-cert",
			payload:       sample_payload,
			mechanism:     c.RsaPssSha384,
			digest:        "sha384",
			publicKeyPath: "../../../../test/rsa2048-cert.pub",
			expected:      nil,
		},
		{
			description:   "RsaPssSha512 valid test",
			project:       "vsign\\rsa2048-cert",
			payload:       sample_payload,
			mechanism:     c.RsaPssSha512,
			digest:        "sha512",
			publicKeyPath: "../../../../test/rsa2048-cert.pub",
			expected:      nil,
		},
		{
			description:   "EcDsa Sha1 valid test",
			project:       "vsign\\p256-cert",
			payload:       sample_payload,
			mechanism:     c.EcDsa,
			digest:        "sha1",
			publicKeyPath: "../../../../test/p256-cert.pub",
			expected:      nil,
		},
		{
			description:   "EcDsa Sha256 valid test",
			project:       "vsign\\p256-cert",
			payload:       sample_payload,
			mechanism:     c.EcDsa,
			digest:        "sha256",
			publicKeyPath: "../../../../test/p256-cert.pub",
			expected:      nil,
		},
		{
			description:   "EcDsa Sha384 valid test",
			project:       "vsign\\p256-cert",
			payload:       sample_payload,
			mechanism:     c.EcDsa,
			digest:        "sha384",
			publicKeyPath: "../../../../test/p256-cert.pub",
			expected:      nil,
		},
		{
			description:   "EcDsa Sha512 valid test",
			project:       "vsign\\p256-cert",
			payload:       sample_payload,
			mechanism:     c.EcDsa,
			digest:        "sha512",
			publicKeyPath: "../../../../test/p256-cert.pub",
			expected:      nil,
		},
		{
			description:   "EcDsaSha1 valid test",
			project:       "vsign\\p256-cert",
			payload:       sample_payload,
			mechanism:     c.EcDsaSha1,
			digest:        "sha1",
			publicKeyPath: "../../../../test/p256-cert.pub",
			expected:      nil,
		},
		{
			description:   "EcDsaSha256 valid test",
			project:       "vsign\\p256-cert",
			payload:       sample_payload,
			mechanism:     c.EcDsaSha256,
			digest:        "sha256",
			publicKeyPath: "../../../../test/p256-cert.pub",
			expected:      nil,
		},
		{
			description:   "EcDsaSha384 valid test",
			project:       "vsign\\p256-cert",
			payload:       sample_payload,
			mechanism:     c.EcDsaSha384,
			digest:        "sha384",
			publicKeyPath: "../../../../test/p256-cert.pub",
			expected:      nil,
		},
		{
			description:   "EcDsaSha512 valid test",
			project:       "vsign\\p256-cert",
			payload:       sample_payload,
			mechanism:     c.EcDsaSha512,
			digest:        "sha512",
			publicKeyPath: "../../../../test/p256-cert.pub",
			expected:      nil,
		},
		{
			description:   "EdDsa Sha1 valid test",
			project:       "vsign\\ed25519",
			payload:       sample_payload,
			mechanism:     c.EdDsa,
			digest:        "sha1",
			publicKeyPath: "../../../../test/ed25519.pub",
			expected:      nil,
		},
		{
			description:   "EdDsa Sha256 valid test",
			project:       "vsign\\ed25519",
			payload:       sample_payload,
			mechanism:     c.EdDsa,
			digest:        "sha256",
			publicKeyPath: "../../../../test/ed25519.pub",
			expected:      nil,
		},
		{
			description:   "EdDsa Sha384 valid test",
			project:       "vsign\\ed25519",
			payload:       sample_payload,
			mechanism:     c.EdDsa,
			digest:        "sha384",
			publicKeyPath: "../../../../test/ed25519.pub",
			expected:      nil,
		},
		{
			description:   "EdDsa Sha512 valid test",
			project:       "vsign\\ed25519",
			payload:       sample_payload,
			mechanism:     c.EdDsa,
			digest:        "sha512",
			publicKeyPath: "../../../../test/ed25519.pub",
			expected:      nil,
		},
		{
			description:   "Ml-Dsa44 Sha256 valid test",
			project:       "vsign\\ml-dsa44",
			payload:       sample_payload,
			mechanism:     c.MlDsa,
			digest:        "sha256",
			publicKeyPath: "../../../../test/tbd.pub",
			expected:      nil,
		},
		{
			description:   "Slh-dsa-sha2-128s Sha256 valid test",
			project:       "vsign\\slh-dsa-sha2-128s",
			payload:       sample_payload,
			mechanism:     c.SlhDsa,
			digest:        "sha256",
			publicKeyPath: "../../../../test/tbd.pub",
			expected:      nil,
		},
		{
			description:   "Slh-dsa-shake-256s Sha256 valid test",
			project:       "vsign\\slh-dsa-shake-256s",
			payload:       sample_payload,
			mechanism:     c.SlhDsa,
			digest:        "shake",
			publicKeyPath: "../../../../test/tbd.pub",
			expected:      nil,
		},
		{
			description:   "Slh-dsa-shake-128f Sha256 valid test",
			project:       "vsign\\slh-dsa-shake-128f",
			payload:       sample_payload,
			mechanism:     c.SlhDsa,
			digest:        "shake",
			publicKeyPath: "../../../../test/tbd.pub",
			expected:      nil,
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
				t.Error(err)
			}
			//sig, err := connector.Sign(env.KeyID, tc.mechanism, tc.digest, base64.StdEncoding.EncodeToString([]byte(tc.payload)), true, false)
			sig, err := connector.Sign(&endpoint.SignOption{
				KeyID:     env.KeyID,
				Mechanism: tc.mechanism,
				DigestAlg: tc.digest,
				Payload:   []byte(base64.StdEncoding.EncodeToString([]byte(tc.payload))),
				B64Flag:   true,
				RawFlag:   false,
			})

			var errs []string
			if err != nil {
				errs = append(errs, err.Error())
				//require.Contains(t, tc.expected, []string{err.Error()})
			}
			if tc.mechanism != c.MlDsa && tc.mechanism != c.SlhDsa { // Need PQC golang crypto verification support
				err = c.Verify([]byte(tc.payload), sig, tc.digest, tc.publicKeyPath)
				if err != nil {
					errs = append(errs, err.Error())
					require.Equal(t, tc.expected, errs)
				}
			}

		})
	}
}
