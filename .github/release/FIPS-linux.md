# certval-fips for Linux

`certval-fips` is the `certval` command built with FIPS-validated cryptographic modules:

- **AWS-LC's FIPS module**, `--crypto aws-lc`, linked into the command. It needs no setup.
- **OpenSSL**, `--crypto openssl`, through the system's OpenSSL 3 (`libssl.so.3`), which must be
  installed. Whether it uses a FIPS provider is the system's configuration: on a system in FIPS
  mode (RHEL with `fips-mode-setup`, for example) OpenSSL loads its FIPS provider by default.

The FIPS modules are validated; this build of certval is not itself a validated module. `--only`
makes certval use the chosen module alone, with no software fallback.
