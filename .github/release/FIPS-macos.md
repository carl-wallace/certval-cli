# certval-fips for macOS

`certval-fips` is the `certval` command built with FIPS-validated cryptographic modules, for Apple
silicon and Intel Macs:

- **AWS-LC's FIPS module**, `--crypto aws-lc`, in `libaws_lc_fips_*_crypto.dylib` beside the
  command. It needs no setup.
- **OpenSSL's FIPS provider**, `--crypto openssl`: OpenSSL 3.5's libraries in `lib/` with the FIPS
  provider from OpenSSL 3.0.9, the validated release, in `lib/ossl-modules/`. Before first use, run
  `./fips-setup.sh` in this folder. It runs `openssl fipsinstall` on this machine, as OpenSSL's
  FIPS rules require, writes `ssl/openssl.cnf`, and prints the two environment variables that point
  `certval-fips` at it. Run it again if the folder is moved.

Keep the folder together: the command finds its libraries relative to itself.

The FIPS modules are validated; this build of certval is not itself a validated module. The OpenSSL
3.0.9 FIPS provider has no ML-KEM or ML-DSA, so under `--crypto openssl` with the FIPS provider
only classical algorithms are available. `--only` makes certval use the chosen module alone, with
no software fallback.
