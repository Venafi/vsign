## vsign jwt

Sign the supplied JWT payload.

### Synopsis

Sign the supplied JWT payload.

```
vsign jwt [flags]
```

### Examples

```
  vsign jwt --config <config path> --payload <path> --algorithm <algorithm>
```

### Options

```
      --algorithm string   JWT algorithm e.g. RS256.  Default is RS256 (default "RS256")
      --config string      path to the Venafi configuration file
  -h, --help               help for jwt
      --payload string     path to the JWT payload file
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -d, --verbose              log debug output
```

### SEE ALSO

* [vsign](vsign.md)	 - 

