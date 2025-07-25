package pdfsig

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pkcs7"

	"github.com/mattetti/filebuffer"

	"github.com/venafi/vsign/pkg/plugin/signers"
)

type CatalogData struct {
	ObjectId   uint32
	Length     int64
	RootString string
}

type TSA struct {
	URL      string
	Username string
	Password string
}

type CertType uint

type RevocationFunction func(cert, issuer *x509.Certificate, i *revocation.InfoArchival) error

type signedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               rawCertificates        `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo           `asn1:"set"`
}

// SetDigestAlgorithm sets the digest algorithm to be used in the signing process.
//
// This should be called before adding signers
func (sd *SignedData) SetDigestAlgorithm(d asn1.ObjectIdentifier) {
	sd.digestOid = d
}

// NewSignedData takes data and initializes a PKCS7 SignedData struct that is
// ready to be signed via AddSigner. The digest algorithm is set to SHA1 by default
// and can be changed by calling SetDigestAlgorithm.
func NewSignedData(data []byte) (*SignedData, error) {
	content, err := asn1.Marshal(data)
	if err != nil {
		return nil, err
	}
	ci := contentInfo{
		ContentType: OIDData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
	}
	sd := signedData{
		ContentInfo: ci,
		Version:     1,
	}
	return &SignedData{sd: sd, data: data, digestOid: OIDDigestAlgorithmSHA1}, nil
}

// Detach removes content from the signed data struct to make it a detached signature.
// This must be called right before Finish()
func (sd *SignedData) Detach() {
	sd.sd.ContentInfo = contentInfo{ContentType: OIDData}
}

// GetSignedData returns the private Signed Data
func (sd *SignedData) GetSignedData() *signedData {
	return &sd.sd
}

func (si *signerInfo) SetUnauthenticatedAttributes(extraUnsignedAttrs []Attribute) error {
	unsignedAttrs := &attributes{}
	for _, attr := range extraUnsignedAttrs {
		unsignedAttrs.Add(attr.Type, attr.Value)
	}
	finalUnsignedAttrs, err := unsignedAttrs.ForMarshalling()
	if err != nil {
		return err
	}

	si.UnauthenticatedAttributes = finalUnsignedAttrs

	return nil
}

// Even though, the tag & length are stripped out during marshalling the
// RawContent, we have to encode it into the RawContent. If its missing,
// then `asn1.Marshal()` will strip out the certificate wrapper instead.
func marshalCertificateBytes(certs []byte) (rawCertificates, error) {
	var val = asn1.RawValue{Bytes: certs, Class: 2, Tag: 0, IsCompound: true}
	b, err := asn1.Marshal(val)
	if err != nil {
		return rawCertificates{}, err
	}
	return rawCertificates{Raw: b}, nil
}

// concats and wraps the certificates in the RawValue structure
func marshalCertificates(certs []*x509.Certificate) rawCertificates {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	rawCerts, _ := marshalCertificateBytes(buf.Bytes())
	return rawCerts
}

// Finish marshals the content and its signers
func (sd *SignedData) Finish() ([]byte, error) {
	sd.sd.Certificates = marshalCertificates(sd.certs)
	inner, err := asn1.Marshal(sd.sd)
	if err != nil {
		return nil, err
	}
	outer := contentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	}
	return asn1.Marshal(outer)
}

type SignerInfoConfig struct {
	ExtraSignedAttributes   []Attribute
	ExtraUnsignedAttributes []Attribute
	SkipCertificates        bool
}

// SignedData is an opaque data structure for creating signed data payloads
type SignedData struct {
	sd                  signedData
	certs               []*x509.Certificate
	data, messageDigest []byte
	digestOid           asn1.ObjectIdentifier
	//encryptionOid       asn1.ObjectIdentifier
}

type SignData struct {
	Signature          SignDataSignature
	PlatformOpts       signers.SignOpts
	DigestAlgorithm    crypto.Hash
	Certificate        *x509.Certificate
	CertificateChains  [][]*x509.Certificate
	TSA                TSA
	RevocationData     revocation.InfoArchival
	RevocationFunction RevocationFunction
	Appearance         Appearance
	objectId           uint32
}

// Appearance represents the appearance of the signature
type Appearance struct {
	Visible     bool
	Page        uint32
	LowerLeftX  float64
	LowerLeftY  float64
	UpperRightX float64
	UpperRightY float64
}

type VisualSignData struct {
	pageObjectId uint32
	objectId     uint32
}

type InfoData struct {
	ObjectId uint32
}

type SignDataSignature struct {
	CertType   CertType
	DocMDPPerm uint
	Info       SignDataSignatureInfo
}

const (
	CertificationSignature CertType = iota + 1
	ApprovalSignature
	UsageRightsSignature
	TimeStampSignature
)

const (
	DoNotAllowAnyChangesPerms = iota + 1
	AllowFillingExistingFormFieldsAndSignaturesPerms
	AllowFillingExistingFormFieldsAndSignaturesAndCRUDAnnotationsPerms
)

type SignDataSignatureInfo struct {
	Name        string
	Location    string
	Reason      string
	ContactInfo string
	Date        time.Time
}

type SignContext struct {
	InputFile                  io.ReadSeeker
	OutputFile                 io.Writer
	OutputBuffer               *filebuffer.Buffer
	SignData                   SignData
	CatalogData                CatalogData
	VisualSignData             VisualSignData
	InfoData                   InfoData
	PDFReader                  *pdf.Reader
	NewXrefStart               int64
	ByteRangeStartByte         int64
	SignatureContentsStartByte int64
	ByteRangeValues            []int64
	SignatureMaxLength         uint32
	SignatureMaxLengthBase     uint32

	existingSignatures []SignData
	lastXrefID         uint32
	newXrefEntries     []xrefEntry
	updatedXrefEntries []xrefEntry
}

func SignFile(r io.Reader, sign_data SignData) ([]byte, error) {
	input_file, err := os.Open(sign_data.PlatformOpts.Path)
	if err != nil {
		return nil, err
	}
	defer input_file.Close()

	finfo, err := input_file.Stat()
	if err != nil {
		return nil, err
	}
	size := finfo.Size()

	rdr, err := pdf.NewReader(input_file, size)
	if err != nil {
		return nil, err
	}

	return Sign(input_file, rdr, size, sign_data)
}

func Sign(input io.ReadSeeker, rdr *pdf.Reader, size int64, sign_data SignData) ([]byte, error) {
	sign_data.objectId = uint32(rdr.XrefInformation.ItemCount) + 2

	context := SignContext{
		PDFReader:              rdr,
		InputFile:              input,
		SignData:               sign_data,
		SignatureMaxLengthBase: uint32(hex.EncodedLen(512)),
	}

	// Fetch existing signatures
	existingSignatures, err := context.fetchExistingSignatures()
	if err != nil {
		return nil, err
	}
	context.existingSignatures = existingSignatures

	signedPayload, err := context.SignPDF()
	if err != nil {
		return nil, err
	}

	return signedPayload, nil
}

func (context *SignContext) SignPDF() ([]byte, error) {
	// set defaults
	if context.SignData.Signature.CertType == 0 {
		context.SignData.Signature.CertType = 1
	}
	if context.SignData.Signature.DocMDPPerm == 0 {
		context.SignData.Signature.DocMDPPerm = 1
	}
	if !context.SignData.DigestAlgorithm.Available() {
		context.SignData.DigestAlgorithm = crypto.SHA256
	}
	if context.SignData.Appearance.Page == 0 {
		context.SignData.Appearance.Page = 1
	}

	context.OutputBuffer = filebuffer.New([]byte{})

	// Copy old file into new buffer.
	_, err := context.InputFile.Seek(0, 0)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(context.OutputBuffer, context.InputFile); err != nil {
		return nil, err
	}

	// File always needs an empty line after %%EOF.
	if _, err := context.OutputBuffer.Write([]byte("\n")); err != nil {
		return nil, err
	}

	// Base size for signature.
	context.SignatureMaxLength = context.SignatureMaxLengthBase

	// If not a timestamp signature
	if context.SignData.Signature.CertType != TimeStampSignature {
		switch context.SignData.Certificate.SignatureAlgorithm.String() {
		case "SHA1-RSA":
		case "ECDSA-SHA1":
		case "DSA-SHA1":
			context.SignatureMaxLength += uint32(hex.EncodedLen(128))
		case "SHA256-RSA":
		case "ECDSA-SHA256":
		case "DSA-SHA256":
			context.SignatureMaxLength += uint32(hex.EncodedLen(256))
		case "SHA384-RSA":
		case "ECDSA-SHA384":
			context.SignatureMaxLength += uint32(hex.EncodedLen(384))
		case "SHA512-RSA":
		case "ECDSA-SHA512":
			context.SignatureMaxLength += uint32(hex.EncodedLen(512))
		}

		// Add size of digest algorithm twice (for file digist and signing certificate attribute)
		context.SignatureMaxLength += uint32(hex.EncodedLen(context.SignData.DigestAlgorithm.Size() * 2))

		// Add size for my certificate.
		degenerated, err := pkcs7.DegenerateCertificate(context.SignData.Certificate.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to degenerate certificate: %w", err)
		}

		context.SignatureMaxLength += uint32(hex.EncodedLen(len(degenerated)))

		// Add size of the raw issuer which is added by AddSignerChain
		context.SignatureMaxLength += uint32(hex.EncodedLen(len(context.SignData.Certificate.RawIssuer)))

		// Add size for certificate chain.
		var certificate_chain []*x509.Certificate
		if len(context.SignData.CertificateChains) > 0 && len(context.SignData.CertificateChains[0]) > 1 {
			certificate_chain = context.SignData.CertificateChains[0][1:]
		}

		if len(certificate_chain) > 0 {
			for _, cert := range certificate_chain {
				degenerated, err := pkcs7.DegenerateCertificate(cert.Raw)
				if err != nil {
					return nil, fmt.Errorf("failed to degenerate certificate in chain: %w", err)
				}

				context.SignatureMaxLength += uint32(hex.EncodedLen(len(degenerated)))
			}
		}

		// Fetch revocation data before adding signature placeholder.
		// Revocation data can be quite large and we need to create enough space in the placeholder.
		if err := context.fetchRevocationData(); err != nil {
			return nil, fmt.Errorf("failed to fetch revocation data: %w", err)
		}
	}

	// Add estimated size for TSA.
	// We can't kow actual size of TSA until after signing.
	//
	// Different TSA servers provide different response sizes, we
	// might need to make this configurable or detect and store.
	if context.SignData.TSA.URL != "" {
		context.SignatureMaxLength += uint32(hex.EncodedLen(9000))
	}

	// Create the signature object
	var signature_object []byte

	switch context.SignData.Signature.CertType {
	case TimeStampSignature:
		signature_object = context.createTimestampPlaceholder()
	default:
		signature_object = context.createSignaturePlaceholder()
	}

	// Write the new signature object
	context.SignData.objectId, err = context.addObject(signature_object)
	if err != nil {
		return nil, fmt.Errorf("failed to add signature object: %w", err)
	}

	// Create visual signature (visible or invisible based on CertType)
	visible := false
	rectangle := [4]float64{0, 0, 0, 0}
	if context.SignData.Signature.CertType != ApprovalSignature && context.SignData.Appearance.Visible {
		return nil, fmt.Errorf("visible signatures are only allowed for approval signatures")
	} else if context.SignData.Signature.CertType == ApprovalSignature && context.SignData.Appearance.Visible {
		visible = true
		rectangle = [4]float64{
			context.SignData.Appearance.LowerLeftX,
			context.SignData.Appearance.LowerLeftY,
			context.SignData.Appearance.UpperRightX,
			context.SignData.Appearance.UpperRightY,
		}
	}

	// Example usage: passing page number and default rect values
	visual_signature, err := context.createVisualSignature(visible, context.SignData.Appearance.Page, rectangle)
	if err != nil {
		return nil, fmt.Errorf("failed to create visual signature: %w", err)
	}

	// Write the new visual signature object.
	context.VisualSignData.objectId, err = context.addObject(visual_signature)
	if err != nil {
		return nil, fmt.Errorf("failed to add visual signature object: %w", err)
	}

	if context.SignData.Appearance.Visible {
		inc_page_update, err := context.createIncPageUpdate(context.SignData.Appearance.Page, context.VisualSignData.objectId)
		if err != nil {
			return nil, fmt.Errorf("failed to create incremental page update: %w", err)
		}
		err = context.updateObject(context.VisualSignData.pageObjectId, inc_page_update)
		if err != nil {
			return nil, fmt.Errorf("failed to add incremental page update object: %w", err)
		}
	}

	// Create a new catalog object
	catalog, err := context.createCatalog()
	if err != nil {
		return nil, fmt.Errorf("failed to create catalog: %w", err)
	}

	// Write the new catalog object
	context.CatalogData.ObjectId, err = context.addObject(catalog)
	if err != nil {
		return nil, fmt.Errorf("failed to add catalog object: %w", err)
	}

	// Write xref table
	if err := context.writeXref(); err != nil {
		return nil, fmt.Errorf("failed to write xref: %w", err)
	}

	// Write trailer
	if err := context.writeTrailer(); err != nil {
		return nil, fmt.Errorf("failed to write trailer: %w", err)
	}

	// Update byte range
	if err := context.updateByteRange(); err != nil {
		return nil, fmt.Errorf("failed to update byte range: %w", err)
	}

	// Replace signature
	if _, err := context.replaceSignature(); err != nil {
		return nil, fmt.Errorf("failed to replace signature: %w", err)
	}

	// Write final output
	if _, err := context.OutputBuffer.Seek(0, 0); err != nil {
		return nil, err
	}
	file_content := context.OutputBuffer.Buff.Bytes()

	/*
		if _, err := context.OutputFile.Write(file_content); err != nil {
			return nil, err
		}*/

	return file_content, nil
}
