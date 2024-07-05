package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"os"

	"golang.org/x/crypto/sha3"
)

type alg struct {
	Name      string
	Mechanism int
	Size      int //bytes
}

type PSSMechanism struct {
	Mechanism int
	MGF       int
	SaltLen   int
	HashAlg   int
}

type sig struct {
	R, S *big.Int
}

const RsaPkcs = 1
const RsaPkcsOaep = 9
const RsaPkcsPss = 13
const RsaSha1 = 6
const RsaSha224 = 70
const RsaSha256 = 64
const RsaSha384 = 65
const RsaSha512 = 66
const RsaPssSha1 = 14
const RsaPssSha224 = 71
const RsaPssSha256 = 67
const RsaPssSha384 = 68
const RsaPssSha512 = 69
const EcDsa = 4161
const EcDsaSha1 = 4162
const EcDsaSha224 = 4163
const EcDsaSha256 = 4164
const EcDsaSha384 = 4165
const EcDsaSha512 = 4166
const EdDsa = 4183
const Sha1 = 544
const Sha224 = 597
const Sha256 = 592
const Sha384 = 608
const Sha512 = 624
const Mgf1Sha1 = 1
const Mgf1Sha224 = 5
const Mgf1Sha256 = 2
const Mgf1Sha384 = 3
const Mgf1Sha512 = 4

// Experimental PQC support
const MlDsa = 2147483650
const SlhDsa = 2147483652

func getSupportedMechanisms() []alg {
	return []alg{
		{Name: "RsaPkcs", Mechanism: RsaPkcs, Size: 32},
		{Name: "EcDsaSha256", Mechanism: EcDsaSha256, Size: 64},
		{Name: "EcDsaSha384", Mechanism: EcDsaSha384, Size: 96},
		{Name: "EcDsaSha512", Mechanism: EcDsaSha512, Size: 132},
		{Name: "EdDsa", Mechanism: EdDsa, Size: 64},
	}
}

func getMechanismSize(mechanism int) int {
	for _, m := range getSupportedMechanisms() {
		if m.Mechanism == mechanism {
			return m.Size
		}
	}
	return 0
}

func GetPSSMechanism(digest string) PSSMechanism {
	switch digest {
	case "sha1":
		return PSSMechanism{Mechanism: RsaSha1, MGF: Mgf1Sha1, SaltLen: 20, HashAlg: Sha1}
	case "sha224":
		return PSSMechanism{Mechanism: RsaSha224, MGF: Mgf1Sha224, SaltLen: 28, HashAlg: Sha224}
	case "sha256":
		return PSSMechanism{Mechanism: RsaSha256, MGF: Mgf1Sha256, SaltLen: 32, HashAlg: Sha256}
	case "sha384":
		return PSSMechanism{Mechanism: RsaSha384, MGF: Mgf1Sha384, SaltLen: 48, HashAlg: Sha384}
	case "sha512":
		return PSSMechanism{Mechanism: RsaSha512, MGF: Mgf1Sha512, SaltLen: 64, HashAlg: Sha512}
	default:
		return PSSMechanism{Mechanism: RsaSha256, MGF: Mgf1Sha256, SaltLen: 32, HashAlg: Sha256}
	}
}

func GetHasher(digest string) (hash.Hash, crypto.Hash, []byte) {
	switch digest {
	case "sha1":
		return crypto.Hash.New(crypto.SHA1), crypto.SHA1, []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}
	case "sha224":
		return crypto.Hash.New(crypto.SHA224), crypto.SHA224, []byte{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c}
	case "sha256":
		return crypto.Hash.New(crypto.SHA256), crypto.SHA256, []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	case "sha384":
		return crypto.Hash.New(crypto.SHA384), crypto.SHA384, []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}
	case "sha512":
		return crypto.Hash.New(crypto.SHA512), crypto.SHA512, []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}
	case "shake":
		return sha3.New256(), crypto.SHA256, nil
	default:
		return crypto.Hash.New(crypto.SHA256), crypto.SHA256, []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	}

}

func GetRSAClientMechanism(digest string) int {
	switch digest {
	case "sha1":
		return RsaSha1
	case "sha224":
		return RsaSha224
	case "sha256":
		return RsaSha256
	case "sha384":
		return RsaSha384
	case "sha512":
		return RsaSha512
	default:
		return RsaSha256 //RsaSha256
	}
}

func GetECClientMechanism(digest string) int {
	switch digest {
	case "sha1":
		return EcDsaSha1
	case "sha224":
		return EcDsaSha224
	case "sha256":
		return EcDsaSha256
	case "sha384":
		return EcDsaSha384
	case "sha512":
		return EcDsaSha512
	default:
		return EcDsaSha256 //EcDsaSha256
	}

}

func EncodeASN1(rawBase64sig string, mechanism int) ([]byte, error) {
	sigbytes, err := base64.StdEncoding.DecodeString(rawBase64sig)

	if err != nil {
		return nil, err
	}

	switch mechanism {
	case RsaPkcs, EdDsa, RsaSha1, RsaSha256, RsaSha384, RsaSha512, RsaPkcsPss, RsaPssSha1, RsaPssSha256, RsaPssSha384, RsaPssSha512:
		return sigbytes, nil
	case MlDsa, SlhDsa: // Experimental PQC support
		return sigbytes, nil
	case EcDsa, EcDsaSha1, EcDsaSha224, EcDsaSha256, EcDsaSha384, EcDsaSha512:
		r := new(big.Int).SetBytes(sigbytes[0 : len(sigbytes)/2])
		s := new(big.Int).SetBytes(sigbytes[len(sigbytes)/2:])
		components := sig{r, s}
		encoding, _ := asn1.Marshal(components)
		return encoding, nil
	default:
		return nil, fmt.Errorf("invalid mechanism and/or currently not supported")
	}
}

func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func DecodeBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func EncodeHex(data []byte) string {
	return hex.EncodeToString(data)
}

func Verify(data []byte, signature []byte, digest string, publicKeyPath string) error {

	hasher, hashAlgo, _ := GetHasher(digest)
	hasher.Write([]byte(data))

	pemBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("public key not found: %v", err.Error())
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing the public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key")
	}

	switch publicKey := publicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(publicKey, hasher.Sum(nil), signature) {
			return fmt.Errorf("failed verification")
		}
	case ed25519.PublicKey:
		/*err := ed25519.VerifyWithOptions(publicKey, data, signature, &ed25519.Options{})
		if err != nil {
			return fmt.Errorf("failed verification: %v", err.Error())
		}*/
		if !ed25519.Verify(publicKey, data, signature) {
			return fmt.Errorf("failed verification")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(publicKey, hashAlgo, hasher.Sum(nil), signature); err != nil {
			er1 := rsa.VerifyPSS(publicKey, hashAlgo, hasher.Sum(nil), signature, nil)
			if er1 != nil {
				return fmt.Errorf("failed verification: %v", er1.Error())
			}
		}
	default:
		return fmt.Errorf("invalid mechanism and/or currently not supported")
	}

	//Verification successful
	return nil
}

func ParsePEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	block, rest := pem.Decode(data)
	for block != nil {
		// skip private key
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
			block, rest = pem.Decode(rest)
		}
	}
	return certs, nil
}

func ParseCertificates(data [][]byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, cert := range data {
		// skip private key
		crt, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, err
		}
		certs = append(certs, crt)
	}
	return certs, nil
}
