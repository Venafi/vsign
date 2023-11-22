### What ** is not ** production ready?

While parts of `vsign` are stable, we are continuing to experiment and add new features.  The following feature set is not considered stable yet, but we are commiteted to stabilizing it over time!

**Note: the following providers require online access to CodeSign Protect for both signing and verification**

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