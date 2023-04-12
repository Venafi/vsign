## vsign sign

Sign the supplied payload.

### Synopsis

Sign the supplied payload.

```
vsign sign [flags]
```

### Examples

```
  vsign sign --config <config path> --output-signature <path> --payload <path> --image <image> --mechanism <mechanism_id>
```

### Options

```
      --config string             path to the Venafi configuration file
      --digest string             sha digest algorithm
  -f, --force                     skip warnings and confirmations
  -h, --help                      help for sign
      --image string              path to a container image
      --mechanism int             mechanism (default 4164)
      --output-signature string   write the signature to FILE
      --payload string            path to a payload file to use rather than generating one
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -d, --verbose              log debug output
```

### SEE ALSO

* [vsign](vsign.md)	 - 

