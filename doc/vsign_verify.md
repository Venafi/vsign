## vsign verify

Verify the supplied payload and signature.

### Synopsis

Verify the supplied payload and signature.

```
vsign verify [flags]
```

### Examples

```
  vsign verify --payload <path> --signature <path> --digest <hash_alg> --key <public_key_path>
```

### Options

```
      --config string      path to the Venafi configuration file
      --digest string      sha digest algorithm
  -f, --force              skip warnings and confirmations
  -h, --help               help for verify
      --key string         public key for verification
      --payload string     path to a payload file to use rather than generating one
      --signature string   write the signature to FILE
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -d, --verbose              log debug output
```

### SEE ALSO

* [vsign](vsign.md)	 - 

