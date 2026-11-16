# certval-fips for Windows

`certval-fips.exe` is the `certval` command built with AWS-LC's FIPS-validated module,
`--crypto aws-lc`, in the `aws_lc_fips_*_crypto.dll` beside it. Keep the two together. It needs no
setup. certval-cli offers no OpenSSL on Windows; `--crypto cng` uses Windows' own CNG, whose
cryptographic modules Microsoft has FIPS-validated.

The FIPS module is validated; this build of certval is not itself a validated module. `--only`
makes certval use the chosen module alone, with no software fallback.
