# vSign Mechanism Compatibility with Venafi CodeSign Protect

| Mechanism | Sign | Verify | Digest | Environment Type | Software Storage | Hardware Storage |
| --------- | ---- | ------ | ------ | ---------------- | ---------------- | ---------------- |
| RsaPkcs (1) | :heavy_check_mark: |  :heavy_check_mark: | Sha1,Sha256,Sha384,Sha512 | Certificate,KeyPair | TBD | TBD |
| RsaSha1 (6) | :heavy_check_mark: | :heavy_check_mark: | Sha1 | Certificate,KeyPair | TBD | TBD |
| RsaSha224 (70) | :x: | :x: | Sha224 | Certificate,KeyPair | TBD | TBD |
| RsaSha256 (64) | :heavy_check_mark: | :heavy_check_mark: | Sha256 | Certificate,KeyPair | TBD | TBD |
| RsaSha384 (65) | :heavy_check_mark: | :heavy_check_mark: | Sha384 | Certificate,KeyPair | TBD | TBD |
| RsaSha512 (66) | :heavy_check_mark: | :heavy_check_mark: | Sha512 | Certificate,KeyPair | TBD | TBD |
| RsaPkcsPss (13) | :heavy_check_mark: | :heavy_check_mark: | Sha1,Sha256,Sha384,Sha512 | Certificate,KeyPair | TBD | TBD
| RsaPkcsPssSha1 (14) | :heavy_check_mark: | :heavy_check_mark: | Sha1 | Certificate,KeyPair | TBD | TBD |
| RsaPkcsPssSha256 (67) | :heavy_check_mark: | :heavy_check_mark: | Sha256 | Certificate,KeyPair | :heavy_check_mark: | :x: |
| RsaPkcsPssSha384 (68) | :heavy_check_mark: | :heavy_check_mark: | Sha384 | Certificate,KeyPair | TBD | TBD |
| RsaPkcsPssSha512 (69) | :heavy_check_mark: | :heavy_check_mark: | Sha512 | Certificate,KeyPair | TBD | TBD |
| EcDsa (4161) | :heavy_check_mark: | :heavy_check_mark: | Sha1,Sha256,Sha384,Sha512 | Certificate,KeyPair | TBD | TBD |
| EcDsaSha1 (4162) | :heavy_check_mark: | :heavy_check_mark: | Sha1 | Certificate,KeyPair | TBD | TBD |
| EcDsaSha256 (4164) | :heavy_check_mark: | :heavy_check_mark: | Sha256 | Certificate,KeyPair | TBD | TBD |
| EcDsaSha384 (4165) | :heavy_check_mark: | :heavy_check_mark: | Sha384 | Certificate,KeyPair | TBD | TBD |
| EcDsaSha512 (4166) | :heavy_check_mark: | :heavy_check_mark: | Sha512 | Certificate,KeyPair | TBD | TBD |
| EdDsa (4183) | :heavy_check_mark: | :heavy_check_mark: | Sha1,Sha256,Sha384,Sha512 | Certificate,KeyPair | TBD | TBD |

## JWT Signature Algorithm Compatibility

| Algorithm | Sign | Environment | Software Storage | Hardware Storage |
| --------- | ---- | ----------- | ---------------- | ---------------- |
| RS224 | :x: | Certificate,KeyPair | :x: | :x: |
| RS256 | :heavy_check_mark: | Certificate,KeyPair | :heavy_check_mark: | TBD |
| RS384 | :heavy_check_mark: | Certificate,KeyPair | :heavy_check_mark: | TBD |
| RS512 | :heavy_check_mark: | Certificate,KeyPair | :heavy_check_mark: | TBD |
| ES224 | :x: | Certificate,KeyPair | :x: | :x: |
| ES256 | :heavy_check_mark: | Certificate,KeyPair | :heavy_check_mark: | TBD |
| ES384 | :heavy_check_mark: | Certificate,KeyPair | :heavy_check_mark: | TBD |
| ES512 | :heavy_check_mark: | Certificate,KeyPair | :heavy_check_mark: | TBD |
