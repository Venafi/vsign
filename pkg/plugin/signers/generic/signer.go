package generic

// Sign Java archives

import (
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/venafi/vsign/cmd/vsign/cli/options"
	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/plugin/signers"
	"github.com/venafi/vsign/pkg/provider/magic"
)

var GenericSigner = &signers.Signer{
	Name:      "*",
	Magic:     magic.FileTypeGeneric,
	CertTypes: signers.CertTypeX509,
	Sign:      sign,
	Verify:    verify,
}

func init() {
	signers.Register(GenericSigner)
}

// sign a generic blob
func sign(r io.Reader, certs []*x509.Certificate, opts signers.SignOpts) ([]byte, error) {

	var data []byte
	var err error

	if opts.Path != "" {
		data, err = os.ReadFile(opts.Path)
		if err != nil {
			return nil, fmt.Errorf("error with payload path")
		}
	}

	sig, err := opts.TPP.Sign(&endpoint.SignOption{
		KeyID:     opts.KeyID,
		Mechanism: opts.Mechanism,
		DigestAlg: opts.Digest,
		Payload:   []byte(c.EncodeBase64(data)),
		B64Flag:   true,
		RawFlag:   false,
	})
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	return sig, nil
}

func verify(f *os.File, opts options.VerifyOptions, tppOpts signers.VerifyOpts) error {

	data, err := os.ReadFile(opts.PayloadPath)
	if err != nil {
		return fmt.Errorf("error with payload path")
	}
	signed, err := os.ReadFile(opts.SignaturePath)
	if err != nil {
		return fmt.Errorf("error with signature path")
	}

	err = c.Verify(data, signed, opts.Digest, opts.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("verification failure: %v", err.Error())
	}
	return nil
}
