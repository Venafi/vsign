[![Venafi](https://raw.githubusercontent.com/Venafi/.github/master/images/Venafi_logo.png)](https://www.venafi.com/)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 21.x](https://img.shields.io/badge/Compatibility-TPP%2021.x-f9a90c)
[![codecov](https://codecov.io/gh/zosocanuck/vsign/branch/main/graph/badge.svg?token=9CF4DJTZBC)](https://codecov.io/gh/venafi/vsign)  
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# vSign

vSign is a Go library, SDK, and command line utility designed to secure the code signing process by using
[Venafi CodeSign Protect](https://venafi.com/codesign-protect/)

**IMPORTANT** - vSign was not designed as a substitute for existing industry-standard signing tools such as signtool, jarsigner, etc.

## Use Cases
1. Notation signing [plugin](https://github.com/venafi/notation-venafi-csp) that supports Venafi CodeSign Protect 
2. Generic artifact signing
3. PDF signing
4. SDK (see simple use case [here](examples/simple-cli))

![](media/usecases.png)

## Developer Setup
1. Configure your Go environment according to https://golang.org/doc/install.
2. Verify that GOPATH environment variable is set correctly.
3. Download the source code:

   `go get github.com/venafi/vsign`
4. Build the command line utility:

   `make vsign`

## Using vSign to integrate Venafi CodeSign Protect into your Code Signing workflow:

You can either use environment variables or a configuration file to customize interaction with the underlying WebSDK.

#### Pre-requisites for using with CodeSign Protect:
1. `vsign-sdk` API Integration has been created with the following minimum scopes: 
   
| TPP Version | Minimum Scopes | Permissions |
| ----------- | -------------- | ----------- |
| <= 22.4 | `codesignclient;codesign;certificate:manage,discover` | Code signing certificate must be granted `View,Read` since `POST Certificates/Retrieve` is used to fetch the code signing certificates and optional chain |
| >= 23.x | `codesignclient;codesign` | None |

2. Code signing user is assigned to `vsign-sdk` API integration.

#### Create Environment variables

```
VSIGN_URL = "https://tpp.example.com"
VSIGN_TOKEN = "xxx"
VSIGN_JWT = "xxx"
VSIGN_PROJECT = "Project\Environment"
VSIGN_TRUST_BUNDLE = "/my/path/chain.pem"
```

#### Create Configuration file (config.ini)

```
tpp_url = "https://tpp.example.com" 
access_token = "xxx"
jwt = "xxx"
tpp_project = "Project\\Environment"
trust_bundle = "/my/path/chain.pem"
```

For authentication only use either `access_token/VSIGN_TOKEN` or `jwt/VSIGN_JWT`, since the JWT will be exchanged for an access token.

`tpp_url` / `VSIGN_URL` = base URL for TPP

`access_token` / `VSIGN_TOKEN` = Access token for CodeSign Protect user with minimum scope:

```
codesignclient;codesign;certificate:manage,discover
```

certificate scope needed by some parts of vSign library for retrieving code signing certificates.

`tpp_project` / `VSIGN_PROJECT` = Path to CodeSign Protect environment to use for signing

`tpp_jwt` / `VSIGN_JWT` = JWT useful when TPP is configured for JWT authentication.  Helpful for automated pipelines where you would want to exchange and short-lived OIDC token for a (short-lived) TPP access token.  Only supported with JWT authentication introduced in 22.4.

`tpp_bundle` / `VSIGN_TRUST_BUNDLE` = Path to certificate chain in case of private chain of trust for Venafi TPP VOC

### Signing
   ```
   vsign sign --config test/config.ini --output-signature test/output.sig --payload test/data.txt --mechanism 64
   ```
* Refer to [vSign Mechanism compatibility guide](COMPATIBILITY.md) for list of supported Venafi CodeSign Protect PKCS#11 mechanisms
* **IMPORTANT**: Client-side hashing mechanisms are the preferred approach for signing payloads.  vSign will automatically detect if you are attempting to sign a large payload with a server-side hashing mechanism and terminate.
  
### Verification
   ```
   vsign verify --digest sha256 --signature output.sig --payload data.txt --key my.pub
   ```

### JWT Signing
   ```
   vsign jwt --config test/config.ini --header test/jwt_header.json --payload test/jwt_payload.json
   ```
* Refer to CodeSign Protect Developer guide for list of supported JWT signing algorithms

### Retrieve Access Token
   ```
   vsign getcred --url https://tpp.example.com --username test-cs-user --password MyPassword1234!
   
   access_token: P1sfL7l4uCWwH/zMkJY7IA==
   ```

   ```
   vsign getcred --url https://tpp.example.com --jwt ey...
   
   access_token: P1sfL7l4uCWwH/zMkJY7IA==
   ```

### PDF Signing

Inspired by the [Digitorus pdfsign](https://github.com/digitorus/pdfsign) project

```
vsign sign --config test/config.ini --payload test/dummy.pdf --output-signature test/dummy-signed.pdf --digest sha256 --mechanism 1 --name "John Doe" --location "Pleasantville" --reason "Contract" --contact "john@doe.com"
```

##### Troubleshooting

vSign relies on a compliant PDF document for successful signing and verification.  In the scenario where the originating PDF tool produces a malformed PDF, such as with the following error: `malformed PDF: malformed xref table`, it may be possible to repair the PDF using tools such as from [qpdf](https://github.com/qpdf/qpdf).

Example:

`qpdf invalid.pdf repaired.pdf`

You can also analyze the PDF as follows:

`qpdf --check invalid.pdf`

```
checking invalid.pdf
PDF Version: 1.6
File is not encrypted
File is linearized
WARNING: invalid.pdf: page 0 has shared identifier entries
WARNING: invalid.pdf: page 0: shared object 6: in hint table but not computed list
qpdf: operation succeeded with warnings
```

#### PDF Signature Verification

```
vsign verify --config test/config.ini --payload test/dummy.pdf --signature test/dummy-signed.pdf --digest sha256
```
### Other Use Cases

Refer [here](EXPERIMENTAL.md) to use cases we are looking at officially supporting in the near future.