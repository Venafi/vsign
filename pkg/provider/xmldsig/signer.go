package xmldsig

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/beevik/etree"
	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/plugin/signers"
)

var signingAlgorithms map[x509.SignatureAlgorithm]cryptoHash

func init() {
	signingAlgorithms = map[x509.SignatureAlgorithm]cryptoHash{
		x509.SHA1WithRSA:     cryptoHash{algorithm: "rsa", hash: crypto.SHA1, name: "sha1"},
		x509.SHA256WithRSA:   cryptoHash{algorithm: "rsa", hash: crypto.SHA256, name: "sha256"},
		x509.SHA384WithRSA:   cryptoHash{algorithm: "rsa", hash: crypto.SHA384, name: "sha384"},
		x509.SHA512WithRSA:   cryptoHash{algorithm: "rsa", hash: crypto.SHA512, name: "sha512"},
		x509.ECDSAWithSHA1:   cryptoHash{algorithm: "ecdsa", hash: crypto.SHA1, name: "sha1"},
		x509.ECDSAWithSHA256: cryptoHash{algorithm: "ecdsa", hash: crypto.SHA256, name: "sha256"},
		x509.ECDSAWithSHA384: cryptoHash{algorithm: "ecdsa", hash: crypto.SHA384, name: "sha384"},
		x509.ECDSAWithSHA512: cryptoHash{algorithm: "ecdsa", hash: crypto.SHA512, name: "sha512"},
	}
}

type cryptoHash struct {
	algorithm string
	hash      crypto.Hash
	name      string
}

// Signer provides options for signing an XML document
type Signer struct {
	signatureData
	platformOpts signers.SignOpts
}

// NewSigner returns a *Signer for the XML provided
func NewSigner(xml []byte, opts signers.SignOpts) (*Signer, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromBytes(xml)
	if err != nil {
		return nil, err
	}
	// TODO TPP configuration input validation
	s := &Signer{platformOpts: opts, signatureData: signatureData{xml: doc}}
	return s, nil
}

// Sign populates the XML digest and signature based on the parameters present and privateKey given
func (s *Signer) Sign() ([]byte, error) {

	if s.signature == nil {
		if err := s.parseEnvelopedSignature(); err != nil {
			return nil, err
		}
	}
	if err := s.parseSignedInfo(); err != nil {
		return nil, err
	}
	if err := s.parseSigAlgorithm(); err != nil {
		return nil, err
	}
	if err := s.parseCanonAlgorithm(); err != nil {
		return nil, err
	}
	if err := s.setDigest(); err != nil {
		return nil, err
	}
	if err := s.setSignature(); err != nil {
		return nil, err
	}

	//xml, err := s.xml.WriteToString()
	xml, err := s.xml.WriteToBytes()
	if err != nil {
		return nil, err
	}
	return xml, nil
}

// SetReferenceIDAttribute set the referenceIDAttribute
func (s *Signer) SetReferenceIDAttribute(refIDAttribute string) {
	s.signatureData.refIDAttribute = refIDAttribute
}

func (s *Signer) setDigest() (err error) {
	references := s.signedInfo.FindElements("./Reference")
	for _, ref := range references {
		doc := s.xml.Copy()
		transforms := ref.SelectElement("Transforms")
		for _, transform := range transforms.SelectElements("Transform") {
			doc, err = processTransform(transform, doc)
			if err != nil {
				return err
			}
		}

		doc, err := s.getReferencedXML(ref, doc)
		if err != nil {
			return err
		}

		calculatedValue, err := calculateHash(ref, doc)
		if err != nil {
			return err
		}

		digestValueElement := ref.SelectElement("DigestValue")
		if digestValueElement == nil {
			return errors.New("xmlsig: unable to find DigestValue")
		}
		digestValueElement.SetText(calculatedValue)
	}
	return nil
}

func (s *Signer) setSignature() error {
	doc := etree.NewDocument()
	doc.SetRoot(s.signedInfo.Copy())
	signedInfo, err := doc.WriteToString()
	if err != nil {
		return fmt.Errorf("error: %s", err)
	}

	canonSignedInfo, err := s.canonAlgorithm.Process(signedInfo, "")
	if err != nil {
		return fmt.Errorf("error: %s", err)
	}

	var signature []byte
	//var h1, h2 *big.Int
	signingAlgorithm, ok := signingAlgorithms[s.sigAlgorithm]
	if !ok {
		return errors.New("signedxml: unsupported algorithm")
	}

	//env, err := s.tppOpts.TPP.GetEnvironment()
	if err != nil {
		return fmt.Errorf("error: %s", err)
	}
	switch signingAlgorithm.algorithm {
	case "rsa":
		signature, err = s.platformOpts.Platform.Sign(&endpoint.SignOption{
			KeyID:     s.platformOpts.KeyID,
			Mechanism: c.RsaPkcs,
			DigestAlg: s.platformOpts.Digest,
			Payload:   []byte(c.EncodeBase64([]byte(canonSignedInfo))),
			B64Flag:   true,
			RawFlag:   false,
		})
	case "ecdsa":
		signature, err = s.platformOpts.Platform.Sign(&endpoint.SignOption{
			KeyID:     s.platformOpts.KeyID,
			Mechanism: c.EcDsa,
			DigestAlg: s.platformOpts.Digest,
			Payload:   []byte(c.EncodeBase64([]byte(canonSignedInfo))),
			B64Flag:   true,
			RawFlag:   false,
		})
	default:
		return fmt.Errorf("invalid signing algorithm")
	}

	if err != nil {
		return fmt.Errorf("error: %s", err)
	}

	b64 := base64.StdEncoding.EncodeToString(signature)
	sigValueElement := s.signature.SelectElement("SignatureValue")
	sigValueElement.SetText(b64)

	return nil
}
