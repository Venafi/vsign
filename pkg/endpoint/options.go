package endpoint

// KeyID = CodeSign Protect environment key guid
// Mechanism = CodeSign Protect PKCS#11 mechanism
// DigestAlg = {sha1, sha256, sha384, sha512}
// Payload = Raw byte stream data to be signed
// B64 = Boolean -> is incoming data already Base64 encoded
// Raw = Boolean -> Do we need the resulting raw signature ASN1. encoded
type SignOption struct {
	KeyID      string `json:"-"`
	Mechanism  int    `json:"-"`
	DigestAlg  string `json:"-"`
	Payload    []byte `json:"-"`
	B64Flag    bool   `json:"-"`
	RawFlag    bool   `json:"-"`
	DigestFlag bool   `json:"-"`
}
