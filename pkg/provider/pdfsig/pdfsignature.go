package pdfsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/digitorus/timestamp"
	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/endpoint"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

const signatureByteRangePlaceholder = "/ByteRange[0 ********** ********** **********]"

func (context *SignContext) createSignaturePlaceholder() (dssd string, byte_range_start_byte int64, signature_contents_start_byte int64) {
	// Using a buffer because it's way faster than concatenating.
	var signature_buffer bytes.Buffer
	signature_buffer.WriteString(strconv.Itoa(int(context.SignData.ObjectId)) + " 0 obj\n")
	signature_buffer.WriteString("<< /Type /Sig")
	signature_buffer.WriteString(" /Filter /Adobe.PPKLite")
	signature_buffer.WriteString(" /SubFilter /adbe.pkcs7.detached")

	byte_range_start_byte = int64(signature_buffer.Len()) + 1

	// Create a placeholder for the byte range string, we will replace it later.
	signature_buffer.WriteString(" " + signatureByteRangePlaceholder)

	signature_contents_start_byte = int64(signature_buffer.Len()) + 11

	// Create a placeholder for the actual signature content, we wil replace it later.
	signature_buffer.WriteString(" /Contents<")
	signature_buffer.Write(bytes.Repeat([]byte("0"), int(context.SignatureMaxLength)))
	signature_buffer.WriteString(">")

	switch context.SignData.Signature.CertType {
	case CertificationSignature, UsageRightsSignature:
		signature_buffer.WriteString(" /Reference [") // start array of signature reference dictionaries
		signature_buffer.WriteString(" << /Type /SigRef")
	}

	switch context.SignData.Signature.CertType {
	case CertificationSignature:
		signature_buffer.WriteString(" /TransformMethod /DocMDP")
		signature_buffer.WriteString(" /TransformParams <<")
		signature_buffer.WriteString(" /Type /TransformParams")
		signature_buffer.WriteString(" /P " + strconv.Itoa(int(context.SignData.Signature.DocMDPPerm)))
		signature_buffer.WriteString(" /V /1.2")
	case UsageRightsSignature:
		signature_buffer.WriteString(" /TransformMethod /UR3")
		signature_buffer.WriteString(" /TransformParams <<")
		signature_buffer.WriteString(" /Type /TransformParams")
		signature_buffer.WriteString(" /V /2.2")
	}

	switch context.SignData.Signature.CertType {
	case CertificationSignature, UsageRightsSignature:
		signature_buffer.WriteString(" >>") // close TransformParams
		signature_buffer.WriteString(" >>")
		signature_buffer.WriteString(" ]") // end of reference
	}

	if context.SignData.Signature.Info.Name != "" {
		signature_buffer.WriteString(" /Name ")
		signature_buffer.WriteString(pdfString(context.SignData.Signature.Info.Name))
	}
	if context.SignData.Signature.Info.Location != "" {
		signature_buffer.WriteString(" /Location ")
		signature_buffer.WriteString(pdfString(context.SignData.Signature.Info.Location))
	}
	if context.SignData.Signature.Info.Reason != "" {
		signature_buffer.WriteString(" /Reason ")
		signature_buffer.WriteString(pdfString(context.SignData.Signature.Info.Reason))
	}
	if context.SignData.Signature.Info.ContactInfo != "" {
		signature_buffer.WriteString(" /ContactInfo ")
		signature_buffer.WriteString(pdfString(context.SignData.Signature.Info.ContactInfo))
	}
	signature_buffer.WriteString(" /M ")
	signature_buffer.WriteString(pdfDateTime(context.SignData.Signature.Info.Date))
	signature_buffer.WriteString(" >>")
	signature_buffer.WriteString("\nendobj\n")

	return signature_buffer.String(), byte_range_start_byte, signature_contents_start_byte
}

func (context *SignContext) fetchRevocationData() error {
	if context.SignData.RevocationFunction != nil {
		if context.SignData.CertificateChains != nil && (len(context.SignData.CertificateChains) > 0) {
			certificate_chain := context.SignData.CertificateChains[0]
			if certificate_chain != nil && (len(certificate_chain) > 0) {
				for i, certificate := range certificate_chain {
					if i < len(certificate_chain)-1 {
						err := context.SignData.RevocationFunction(certificate, certificate_chain[i+1], &context.SignData.RevocationData)
						if err != nil {
							return err
						}
					} else {
						err := context.SignData.RevocationFunction(certificate, nil, &context.SignData.RevocationData)
						if err != nil {
							return err
						}
					}
				}
			}
		}
	}

	// Calculate space needed for signature.
	for _, crl := range context.SignData.RevocationData.CRL {
		context.SignatureMaxLength += uint32(hex.EncodedLen(len(crl.FullBytes)))
	}
	for _, ocsp := range context.SignData.RevocationData.OCSP {
		context.SignatureMaxLength += uint32(hex.EncodedLen(len(ocsp.FullBytes)))
	}

	return nil
}

func (context *SignContext) createSigningCertificateAttribute() (*Attribute, error) {
	hash := context.SignData.DigestAlgorithm.New()
	hash.Write(context.SignData.Certificate.Raw)

	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // SigningCertificate
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // []ESSCertID, []ESSCertIDv2
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // ESSCertID, ESSCertIDv2
				if context.SignData.DigestAlgorithm.HashFunc() != crypto.SHA1 &&
					context.SignData.DigestAlgorithm.HashFunc() != crypto.SHA256 { // default SHA-256
					b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { // AlgorithmIdentifier
						b.AddASN1ObjectIdentifier(getOIDFromHashAlgorithm(context.SignData.DigestAlgorithm))
					})
				}
				b.AddASN1OctetString(hash.Sum(nil)) // certHash
			})
		})
	})

	sse, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	signingCertificate := Attribute{
		Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}, // SigningCertificateV2
		Value: asn1.RawValue{FullBytes: sse},
	}
	if context.SignData.DigestAlgorithm.HashFunc() == crypto.SHA1 {
		signingCertificate.Type = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12} // SigningCertificate
	}
	return &signingCertificate, nil
}

// verifyPartialChain checks that a given cert is issued by the first parent in the list,
// then continue down the path. It doesn't require the last parent to be a root CA,
// or to be trusted in any truststore. It simply verifies that the chain provided, albeit
// partial, makes sense.
func verifyPartialChain(cert *x509.Certificate, parents []*x509.Certificate) error {
	if len(parents) == 0 {
		return fmt.Errorf("pkcs7: zero parents provided to verify the signature of certificate %q", cert.Subject.CommonName)
	}
	err := cert.CheckSignatureFrom(parents[0])
	if err != nil {
		return fmt.Errorf("pkcs7: certificate signature from parent is invalid: %v", err)
	}
	if len(parents) == 1 {
		// there is no more parent to check, return
		return nil
	}
	return verifyPartialChain(parents[0], parents[1:])
}

func signAttributes(attrs []attribute, pKey crypto.PublicKey, sd SignData, digestAlg crypto.Hash) ([]byte, error) {
	attrBytes, err := marshalAttributes(attrs)
	if err != nil {
		return nil, err
	}

	var signature []byte

	switch pKey.(type) {
	case *rsa.PublicKey:
		signature, err = sd.TPPOpts.TPP.Sign(&endpoint.SignOption{
			KeyID:     sd.TPPOpts.KeyID,
			Mechanism: c.RsaPkcs,
			DigestAlg: sd.TPPOpts.Digest,
			Payload:   []byte(c.EncodeBase64(attrBytes)),
			B64Flag:   true,
			RawFlag:   false,
		})
		if err != nil {
			return nil, err
		}
	case *ecdsa.PublicKey:
		signature, err = sd.TPPOpts.TPP.Sign(&endpoint.SignOption{
			KeyID:     sd.TPPOpts.KeyID,
			Mechanism: c.EcDsa,
			DigestAlg: sd.TPPOpts.Digest,
			Payload:   []byte(c.EncodeBase64(attrBytes)),
			B64Flag:   true,
			RawFlag:   false,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid signing algorithm")
	}

	return signature, nil
}

func (context *SignContext) addSignerChain(sd *SignedData, ee *x509.Certificate, parents []*x509.Certificate, config SignerInfoConfig) error {

	// Following RFC 2315, 9.2 SignerInfo type, the distinguished name of
	// the issuer of the end-entity signer is stored in the issuerAndSerialNumber
	// section of the SignedData.SignerInfo, alongside the serial number of
	// the end-entity.
	var ias issuerAndSerial
	ias.SerialNumber = ee.SerialNumber
	if len(parents) == 0 {
		// no parent, the issuer is the end-entity cert itself
		ias.IssuerName = asn1.RawValue{FullBytes: ee.RawIssuer}
	} else {
		err := verifyPartialChain(ee, parents)
		if err != nil {
			return err
		}
		// the first parent is the issuer
		ias.IssuerName = asn1.RawValue{FullBytes: parents[0].RawSubject}
	}
	sd.sd.DigestAlgorithmIdentifiers = append(sd.sd.DigestAlgorithmIdentifiers,
		pkix.AlgorithmIdentifier{Algorithm: sd.digestOid},
	)
	hash, err := getHashForOID(sd.digestOid)
	if err != nil {
		return err
	}
	h := hash.New()
	h.Write(sd.data)
	sd.messageDigest = h.Sum(nil)
	encryptionOid, err := getOIDForEncryptionAlgorithm(ee.PublicKey, sd.digestOid)
	if err != nil {
		return err
	}
	attrs := &attributes{}
	attrs.Add(OIDAttributeContentType, sd.sd.ContentInfo.ContentType)
	attrs.Add(OIDAttributeMessageDigest, sd.messageDigest)
	attrs.Add(OIDAttributeSigningTime, time.Now().UTC())
	for _, attr := range config.ExtraSignedAttributes {
		attrs.Add(attr.Type, attr.Value)
	}
	finalAttrs, err := attrs.ForMarshalling()
	if err != nil {
		return err
	}
	unsignedAttrs := &attributes{}
	for _, attr := range config.ExtraUnsignedAttributes {
		unsignedAttrs.Add(attr.Type, attr.Value)
	}
	finalUnsignedAttrs, err := unsignedAttrs.ForMarshalling()
	if err != nil {
		return err
	}
	// create signature of signed attributes
	signature, err := signAttributes(finalAttrs, ee.PublicKey, context.SignData, hash)
	if err != nil {
		return err
	}
	signerInfo := signerInfo{
		AuthenticatedAttributes:   finalAttrs,
		UnauthenticatedAttributes: finalUnsignedAttrs,
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: sd.digestOid},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: encryptionOid},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}
	if !config.SkipCertificates {
		sd.certs = append(sd.certs, ee)
		if len(parents) > 0 {
			sd.certs = append(sd.certs, parents...)
		}
	}
	sd.sd.SignerInfos = append(sd.sd.SignerInfos, signerInfo)
	return nil
}

func (context *SignContext) createSignature() ([]byte, error) {
	if _, err := context.OutputBuffer.Seek(0, 0); err != nil {
		return nil, err
	}

	// Sadly we can't efficiently sign a file, we need to read all the bytes we want to sign.
	file_content := context.OutputBuffer.Buff.Bytes()

	// Collect the parts to sign.
	sign_content := make([]byte, 0)
	sign_content = append(sign_content, file_content[context.ByteRangeValues[0]:(context.ByteRangeValues[0]+context.ByteRangeValues[1])]...)
	sign_content = append(sign_content, file_content[context.ByteRangeValues[2]:(context.ByteRangeValues[2]+context.ByteRangeValues[3])]...)

	// Initialize pkcs7 signer.
	signed_data, err := NewSignedData(sign_content)
	if err != nil {
		return nil, fmt.Errorf("new signed data: %w", err)
	}

	signed_data.SetDigestAlgorithm(getOIDFromHashAlgorithm(context.SignData.DigestAlgorithm))
	signingCertificate, err := context.createSigningCertificateAttribute()
	if err != nil {
		return nil, fmt.Errorf("new signed data: %w", err)
	}

	signer_config := SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{
			{
				Type:  asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8},
				Value: context.SignData.RevocationData,
			},
			*signingCertificate,
		},
	}

	// Add the first certificate chain without our own certificate.
	var certificate_chain []*x509.Certificate
	if len(context.SignData.CertificateChains) > 0 && len(context.SignData.CertificateChains[0]) > 1 {
		certificate_chain = context.SignData.CertificateChains[0][1:]
	}

	// Add the signer and sign the data.
	// Custom signer to leverage CodeSign Protect
	if err := context.addSignerChain(signed_data, context.SignData.Certificate, certificate_chain, signer_config); err != nil {
		return nil, fmt.Errorf("add signer chain: %w", err)
	}

	// PDF needs a detached signature, meaning the content isn't included.
	signed_data.Detach()

	if context.SignData.TSA.URL != "" {
		signature_data := signed_data.GetSignedData()

		timestamp_response, err := context.GetTSA(signature_data.SignerInfos[0].EncryptedDigest)
		if err != nil {
			return nil, fmt.Errorf("get timestamp: %w", err)
		}

		ts, err := timestamp.ParseResponse(timestamp_response)
		if err != nil {
			return nil, fmt.Errorf("parse timestamp: %w", err)
		}

		_, err = Parse(ts.RawToken)
		if err != nil {
			return nil, fmt.Errorf("parse timestamp token: %w", err)
		}

		timestamp_attribute := Attribute{
			Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14},
			Value: asn1.RawValue{FullBytes: ts.RawToken},
		}
		if err := signature_data.SignerInfos[0].SetUnauthenticatedAttributes([]Attribute{timestamp_attribute}); err != nil {
			return nil, err
		}
	}

	return signed_data.Finish()
}

func (context *SignContext) GetTSA(sign_content []byte) (timestamp_response []byte, err error) {
	sign_reader := bytes.NewReader(sign_content)
	ts_request, err := timestamp.CreateRequest(sign_reader, &timestamp.RequestOptions{
		Certificates: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	ts_request_reader := bytes.NewReader(ts_request)
	req, err := http.NewRequest("POST", context.SignData.TSA.URL, ts_request_reader)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare request (%s): %w", context.SignData.TSA.URL, err)
	}

	req.Header.Add("Content-Type", "application/timestamp-query")
	req.Header.Add("Content-Transfer-Encoding", "binary")

	if context.SignData.TSA.Username != "" && context.SignData.TSA.Password != "" {
		req.SetBasicAuth(context.SignData.TSA.Username, context.SignData.TSA.Password)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	code := 0

	if resp != nil {
		code = resp.StatusCode
	}

	if err != nil || (code < 200 || code > 299) {
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return nil, errors.New("non success response (" + strconv.Itoa(code) + "): " + string(body))
		}

		return nil, errors.New("non success response (" + strconv.Itoa(code) + ")")
	}

	defer resp.Body.Close()
	timestamp_response_body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return timestamp_response_body, nil
}

func (context *SignContext) replaceSignature() ([]byte, error) {
	signature, err := context.createSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	dst := make([]byte, hex.EncodedLen(len(signature)))
	hex.Encode(dst, signature)

	if uint32(len(dst)) > context.SignatureMaxLength {
		// TODO: Should we log this retry?
		// set new base and try signing again
		context.SignatureMaxLengthBase += (uint32(len(dst)) - context.SignatureMaxLength) + 1
		return context.SignPDF()
	}

	if _, err := context.OutputBuffer.Seek(0, 0); err != nil {
		return nil, err
	}
	file_content := context.OutputBuffer.Buff.Bytes()

	if _, err := context.OutputBuffer.Write(file_content[:(context.ByteRangeValues[0] + context.ByteRangeValues[1] + 1)]); err != nil {
		return nil, err
	}

	// Write new ByteRange.
	if _, err := context.OutputBuffer.Write([]byte(dst)); err != nil {
		return nil, err
	}

	if _, err := context.OutputBuffer.Write(file_content[(context.ByteRangeValues[0]+context.ByteRangeValues[1]+1)+int64(len(dst)):]); err != nil {
		return nil, err
	}

	return file_content, nil
}
