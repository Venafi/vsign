package test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/venafi/vsign/cmd/vsign/cli/options"
	"github.com/venafi/vsign/cmd/vsign/cli/sign"
	"github.com/venafi/vsign/cmd/vsign/cli/verify"
	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/venafi/tpp"
	"github.com/venafi/vsign/pkg/vsign"

	// Initialize signer providers
	_ "github.com/venafi/vsign/pkg/plugin/signers/generic"
	_ "github.com/venafi/vsign/pkg/plugin/signers/jar"
	_ "github.com/venafi/vsign/pkg/plugin/signers/pdf"
	_ "github.com/venafi/vsign/pkg/plugin/signers/xml"
)

func TestSignVerifyCleanGeneric(t *testing.T) {
	ctx := context.Background()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chdir("./"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Chdir(wd)
	}()

	configPath := filepath.Join("./", "config.ini")
	payloadPath := filepath.Join("./", "payload.txt")

	//Test RSAPKCS SHA256
	signaturePath := filepath.Join("./", "testrsa2048sha256.sig")
	publicKeyPath := filepath.Join("./", "rsa2048-cert.pub")

	fs := pflag.NewFlagSet("sign", pflag.ContinueOnError)
	fs.String("config", configPath, "config")
	fs.String("payload", payloadPath, "payload")
	fs.String("output-signature", signaturePath, "signature")
	fs.String("digest", "sha256", "digest")
	fs.Int("mechanism", 64, "mechanism")

	must(sign.SignCmd(ctx, fs, options.SignOptions{Config: configPath, OutputSignature: signaturePath, ImageRef: "", PayloadPath: payloadPath, Mechanism: 64, Digest: "sha256"}, nil), t)
	must(verify.VerifyCmd(ctx, options.VerifyOptions{SignaturePath: signaturePath, PayloadPath: payloadPath, PublicKeyPath: publicKeyPath, Digest: "sha256"}, nil), t)
}

func TestJWKSLookupAndCertRetrievalPKS(t *testing.T) {
	cfg, err := vsign.BuildConfig(context.TODO(), "config.ini")
	if err != nil {
		t.Error("error building config")
	}
	connector, err := vsign.NewClient(&cfg)
	if err != nil {
		t.Error("error")
	}
	env, err := connector.GetEnvironment()
	if err != nil {
		t.Error(err)
	}
	cert, err := c.ParseCertificates(env.CertificateChainData)
	if err != nil {
		t.Error(err)
	}
	url, err := connector.GetJwksX5u(cert[0])
	if err != nil {
		t.Error(err)
	}
	_, err = tpp.GetPKSCertificate(url)
	if err != nil {
		t.Error(err)
	}
}

func TestJarSign(t *testing.T) {

	ctx := context.Background()

	configPath := filepath.Join("./", "config.ini")
	payloadPath := filepath.Join("./", "hello.jar")
	println(payloadPath)

	//Test RSAPKCS SHA256
	signaturePath := filepath.Join("./", "hello-signed.jar")
	//publicKeyPath := filepath.Join("../../../../test/", "rsa2048-cert.pub")

	fs := pflag.NewFlagSet("sign", pflag.ContinueOnError)
	fs.String("config", configPath, "config")
	fs.String("payload", payloadPath, "payload")
	fs.String("output-signature", signaturePath, "signature")
	fs.String("digest", "sha256", "digest")
	fs.Int("mechanism", 1, "mechanism")

	must(sign.SignCmd(ctx, fs, options.SignOptions{Config: configPath, OutputSignature: signaturePath, ImageRef: "", PayloadPath: payloadPath, Mechanism: 1, Digest: "sha256"}, nil), t)
	must(verify.VerifyCmd(ctx, options.VerifyOptions{Config: configPath, SignaturePath: signaturePath, Digest: "sha256"}, nil), t)

	// Verification using jarsigner
	// jarsigner -verify hello-signed.jar
}

func TestXMLSign(t *testing.T) {
	ctx := context.Background()

	//Test RSAPKCS SHA256
	configPath := filepath.Join("./", "config.ini")
	payloadPath := filepath.Join("./", "payloadnosig-rsasha2.xml")
	println(payloadPath)

	signaturePath := filepath.Join("./", "payloadnosig-rsasha256.xml.signed")
	//publicKeyPath := filepath.Join("../../../../test/", "rsa2048-cert.pub")

	fs := pflag.NewFlagSet("sign", pflag.ContinueOnError)
	fs.String("config", configPath, "config")
	fs.String("payload", payloadPath, "payload")
	fs.String("output-signature", signaturePath, "signature")
	fs.String("digest", "sha256", "digest")
	fs.Int("mechanism", c.RsaPkcs, "mechanism")

	must(sign.SignCmd(ctx, fs, options.SignOptions{Config: configPath, OutputSignature: signaturePath, ImageRef: "", PayloadPath: payloadPath, Mechanism: c.RsaPkcs, Digest: "sha256"}, nil), t)
	must(verify.VerifyCmd(ctx, options.VerifyOptions{Config: configPath, SignaturePath: signaturePath, PayloadPath: payloadPath, Digest: "sha256"}, nil), t)

	//Test RSAPKCS SHA1
	configPath = filepath.Join("./", "config.ini")
	payloadPath = filepath.Join("./", "payloadnosig-rsasha1.xml")
	println(payloadPath)

	signaturePath = filepath.Join("./", "payloadnosig-rsasha1.xml.signed")
	//publicKeyPath := filepath.Join("../../../../test/", "rsa2048-cert.pub")

	fs = pflag.NewFlagSet("sign", pflag.ContinueOnError)
	fs.String("config", configPath, "config")
	fs.String("payload", payloadPath, "payload")
	fs.String("output-signature", signaturePath, "signature")
	fs.String("digest", "sha1", "digest")
	fs.Int("mechanism", c.RsaPkcs, "mechanism")

	must(sign.SignCmd(ctx, fs, options.SignOptions{Config: configPath, OutputSignature: signaturePath, ImageRef: "", PayloadPath: payloadPath, Mechanism: c.RsaPkcs, Digest: "sha1"}, nil), t)
	must(verify.VerifyCmd(ctx, options.VerifyOptions{Config: configPath, SignaturePath: signaturePath, PayloadPath: payloadPath, Digest: "sha1"}, nil), t)

	//Test ECDSA SHA256
	configPath = filepath.Join("./", "config-ecdsa.ini")
	payloadPath = filepath.Join("./", "payloadnosig-ecdsasha256.xml")
	println(payloadPath)

	signaturePath = filepath.Join("./", "payloadnosig-ecdsasha256.xml.signed")
	//publicKeyPath := filepath.Join("../../../../test/", "rsa2048-cert.pub")

	fs = pflag.NewFlagSet("sign", pflag.ContinueOnError)
	fs.String("config", configPath, "config")
	fs.String("payload", payloadPath, "payload")
	fs.String("output-signature", signaturePath, "signature")
	fs.String("digest", "sha256", "digest")
	fs.Int("mechanism", c.EcDsa, "mechanism")

	must(sign.SignCmd(ctx, fs, options.SignOptions{Config: configPath, OutputSignature: signaturePath, ImageRef: "", PayloadPath: payloadPath, Mechanism: c.EcDsa, Digest: "sha256"}, nil), t)
	must(verify.VerifyCmd(ctx, options.VerifyOptions{Config: configPath, SignaturePath: signaturePath, PayloadPath: payloadPath, Digest: "sha256"}, nil), t)

}

func TestPDFSign(t *testing.T) {
	ctx := context.Background()

	//Test RSAPKCS SHA256
	configPath := filepath.Join("./", "config.ini")
	payloadPath := filepath.Join("./", "dummy.pdf")
	signaturePath := filepath.Join("./", "dummy-signed-rsasha256.pdf")

	fs := pflag.NewFlagSet("sign", pflag.ContinueOnError)
	fs.String("config", configPath, "config")
	fs.String("payload", payloadPath, "payload")
	fs.String("output-signature", signaturePath, "signature")
	fs.String("digest", "sha256", "digest")
	fs.Int("mechanism", c.RsaPkcs, "mechanism")
	fs.String("name", "John Doe", "name")
	fs.String("location", "Palo Alto", "location")
	fs.String("reason", "Testing", "reason")
	fs.String("contact", "johndoe@example.com", "contact")
	fs.String("tsa", "http://timestamp.digicert.com", "tsa")

	must(sign.SignCmd(ctx, fs, options.SignOptions{Config: configPath, OutputSignature: signaturePath, ImageRef: "", PayloadPath: payloadPath, Mechanism: c.RsaPkcs, Digest: "sha256"}, nil), t)
	must(verify.VerifyCmd(ctx, options.VerifyOptions{Config: configPath, SignaturePath: signaturePath, PayloadPath: payloadPath, Digest: "sha256"}, nil), t)

	//Test RSAPKCS SHA1
	signaturePath = filepath.Join("./", "dummy-signed-rsasha1.pdf")

	fs = pflag.NewFlagSet("sign", pflag.ContinueOnError)
	fs.String("config", configPath, "config")
	fs.String("payload", payloadPath, "payload")
	fs.String("output-signature", signaturePath, "signature")
	fs.String("digest", "sha1", "digest")
	fs.Int("mechanism", c.RsaPkcs, "mechanism")
	fs.String("name", "John Doe", "name")
	fs.String("location", "Palo Alto", "location")
	fs.String("reason", "Testing", "reason")
	fs.String("contact", "johndoe@example.com", "contact")
	fs.String("tsa", "http://timestamp.digicert.com", "tsa")

	must(sign.SignCmd(ctx, fs, options.SignOptions{Config: configPath, OutputSignature: signaturePath, ImageRef: "", PayloadPath: payloadPath, Mechanism: c.RsaPkcs, Digest: "sha1"}, nil), t)
	must(verify.VerifyCmd(ctx, options.VerifyOptions{Config: configPath, SignaturePath: signaturePath, PayloadPath: payloadPath, Digest: "sha1"}, nil), t)

	//Test ECDSA SHA256
	configPath = filepath.Join("./", "config-ecdsa.ini")
	signaturePath = filepath.Join("./", "dummy-signed-ecdsasha256.pdf")

	fs = pflag.NewFlagSet("sign", pflag.ContinueOnError)
	fs.String("config", configPath, "config")
	fs.String("payload", payloadPath, "payload")
	fs.String("output-signature", signaturePath, "signature")
	fs.String("digest", "sha256", "digest")
	fs.Int("mechanism", c.EcDsa, "mechanism")
	fs.String("name", "John Doe", "name")
	fs.String("location", "Palo Alto", "location")
	fs.String("reason", "Testing", "reason")
	fs.String("contact", "johndoe@example.com", "contact")
	fs.String("tsa", "http://timestamp.digicert.com", "tsa")

	must(sign.SignCmd(ctx, fs, options.SignOptions{Config: configPath, OutputSignature: signaturePath, ImageRef: "", PayloadPath: payloadPath, Mechanism: c.EcDsa, Digest: "sha256"}, nil), t)
	must(verify.VerifyCmd(ctx, options.VerifyOptions{Config: configPath, SignaturePath: signaturePath, PayloadPath: payloadPath, Digest: "sha256"}, nil), t)

}

func must(err error, t *testing.T) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
