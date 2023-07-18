# dot-net-rsa-finder.py
Python script to find private RSA keys in .NET binary mem dumps given the public key

TLDR: `rsakeyfinder` didn't work for me even specifying the modulus of the public key ¯\_(ツ)_/¯

### Program description

Finds all occurrences of the modulus of the given public key, and tries to parse the next data in the dump as P, then calculate Q... etc

### USAGE:

```usage: dot-net-rsa-finder.py [-h] -f FILE -o OUTPUT (-m MOD | -M MOD_FILE | -p PUBKEY_PEM | -P PUBKEY_XML) [-e EXP] [-d {debug,info,warn,error}]

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Dump file to look for the key inside.
  -o OUTPUT, --output OUTPUT
                        File to export the private RSA key to
  -m MOD, --mod MOD     Modulus as hex stream
  -M MOD_FILE, --mod-file MOD_FILE
                        File containing the modulus as hex stream
  -p PUBKEY_PEM, --pubkey-pem PUBKEY_PEM
                        File containing the public key in PEM format
  -P PUBKEY_XML, --pubkey-xml PUBKEY_XML
                        File containing the public key in XML format
  -e EXP, --exp EXP     Public exponent as hex stream (only if -m is used)
  -d {debug,info,warn,error}, --debug-level {debug,info,warn,error}
                        Debug level. Default is warn
```

### Example:

Reading public key from a PEM file:

`dot-net-rsa-finder.py -f powershell.dmp -p pub.pem -o priv.pem`

Passing mod and exp as parameters:

`dot-net-rsa-finder.py -f powershell.dmp -m 'ef765ad87f4...8ee786fa65ef' -e 'ef7...65ae'`
