# hsSGP

* A CLI tool
* The Haskell implementation of [SuperGenPass](https://github.com/chriszarate/supergenpass-lib)

## Usage

```
Usage: hsSGP [OPTION...]
  -a           --subdomains         subdomains enabled
  -r NUMBER    --round=NUMBER       the minimum count of rounds
  -l NUMBER    --length=NUMBER      the generated password length
  -h TYPE      --hash=TYPE          the hash function: MD5 | SHA512
  -s PASSWORD  --secret=PASSWORD    the secret password part
  -p PASSWORD  --password=PASSWORD  the main password part
  -u URL       --url=URL            the url
```