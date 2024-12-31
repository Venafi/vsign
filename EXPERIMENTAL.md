### What ** is not ** production ready?

While parts of `vsign` are stable, we are continuing to experiment and add new features.  The following feature set is not considered stable yet, but we are commiteted to stabilizing it over time!

**Note: the following providers require online access to CodeSign Protect for both signing and verification**

#### PQC Experimental Signing Support

ML-DSA44 example

```
vsign sign --config test/config.ini --output-signature test/output.sig --payload test/data.txt --mechanism 2147483650
```

SLH-DSA-SHA2-256S example

```
vsign sign --config test/config.ini --output-signature test/output.sig --payload test/data.txt --mechanism 2147483652
```

SLH-DSA-SHAKE-256S example

```
vsign sign --config test/config.ini --output-signature test/output.sig --payload test/data.txt --mechanism 2147483652 --digest shake
```

**Note: PQC verification not currently supported given experimental state of algorithms and no official library support**

#### Jar Signing

Inspired by the [Relic](https://github.com/sassoftware/relic) project

```
vsign sign --config test/config.ini --payload test/hello.jar --output-signature ~/hello-signed.jar --digest sha256 --mechanism 1 --sig-type jar
```

Supported flags are:

`sections-only` - Don't compute hash of entire manifest
`inline-signature` - Include .SF inside the signature block
`apk-v2-present` - Add X-Android-APK-Signed header to signature

#### Jar Signature Verification

```
vsign verify --config test/config.ini --payload test/hello.jar --signature test/hello-signed.jar --digest sha256
```

You can also use jarsigner to perform verification:

```
jarsigner -verify hello-signed.jar
```

#### XML Signing

Inspired by the [Relic](https://github.com/sassoftware/relic) project

```
vsign sign --config test/config.ini --payload test/hello.xml --output-signature ~/hello-signed.xml --digest sha256 --mechanism 1
```

#### XML Signature Verification

```
vsign verify --config test/config.ini --payload test/hello.jar --signature test/hello-signed.jar --digest sha256
```

#### Cosign Image Signing
   ```
   vsign sign --config test/config.ini --image myorg/myapp:v1 --mechanism 64
   ```

#### PDF Signing with Visual Signatures

Initial (experimental) support for PDF visual signatures based on [digitorus/pdfsign](https://github.com/digitorus/pdfsign) commit [b9112bb](https://github.com/digitorus/pdfsign/commit/b9112bb85ba5e2439bfacae2ce694e7f1cb66db1).  Currently only available on [main](https://github.com/Venafi/vsign) branch

```
git clone https://github.com/Venafi/vsign
cd vsign
make vsign
./vsign sign --config test/config.ini --payload test/dummy.pdf --output-signature test/dummy-signed.pdf --digest sha256 --mechanism 1 --name "John Doe" --location "Pleasantville" --reason "Contract" --contact "john@doe.com" --visual
```