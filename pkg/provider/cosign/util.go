package cosign

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	co "github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// Cosign functionality
func GenerateImageManifest(ctx context.Context, imageRef string, annotations map[string]interface{}) ([]byte, error) {

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	regOpts := co.RegistryOptions{}

	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return nil, err
	}

	digest, err := ociremote.ResolveDigest(ref, ociremoteOpts...)
	if err != nil {
		return nil, err
	}
	// Overwrite "ref" with a digest to avoid a race where we use a tag
	// multiple times, and it potentially points to different things at
	// each access.
	ref = digest

	json, err := (&payload.Cosign{Image: digest, Annotations: annotations}).MarshalJSON()
	if err != nil {
		return nil, err
	}

	return json, err
}

func WriteSignatures(ctx context.Context, imageRef string, payload []byte, b64SigBytes []byte, b64sig string) error {

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	regOpts := co.RegistryOptions{}

	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return err
	}

	digest, err := ociremote.ResolveDigest(ref, ociremoteOpts...)
	if err != nil {
		return err
	}
	// Overwrite "ref" with a digest to avoid a race where we use a tag
	// multiple times, and it potentially points to different things at
	// each access.
	ref = digest

	//sig, err := static.NewSignature(payload, string(b64SigBytes))
	sig, err := static.NewSignature(payload, b64sig)

	if err != nil {
		return err
	}

	se, err := ociremote.SignedEntity(digest, ociremoteOpts...)
	if err != nil {
		return err
	}

	// Attach the signature to the entity.
	newSE, err := mutate.AttachSignatureToEntity(se, sig)
	if err != nil {
		return err
	}

	// Publish the signatures associated with this entity
	return ociremote.WriteSignatures(digest.Repository, newSE, ociremoteOpts...)

}
