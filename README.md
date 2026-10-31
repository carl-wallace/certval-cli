# certval-cli

`certval`, an openssl-style command-line tool for X.509 certificates, CRLs, OCSP and DER, with
certification path validation by [certval](https://github.com/carl-wallace/rust-pki): RFC 5280 and
RFC 5937, including certificate policies, name constraints and cross-certified (bridge) topologies.

```sh
cargo install certval-cli
```

This installs a command named `certval`. The subcommands take openssl's names; the flags are this
tool's own. Every command reads DER, or PEM where the file holds it.

## Commands

### `certval x509` describes a certificate

```text
$ certval x509 GoodCACert.crt
Subject:     CN=Good CA,O=Test Certificates 2011,C=US
Issuer:      CN=Trust Anchor,O=Test Certificates 2011,C=US
Serial:      02
Version:     V3
Not before:  2010-01-01T08:30:00Z
Not after:   2030-12-31T08:30:00Z
Public key:  RSA Encryption (1.2.840.113549.1.1.1), 2048 bits
Signature:   SHA256 with RSA Encryption (1.2.840.113549.1.1.11)
SHA-256:     86:D2:18:37:...:34:3F
Extensions:
    id-ce-keyUsage (2.5.29.15), critical
        KeyCertSign, CRLSign
    id-ce-basicConstraints (2.5.29.19), critical
        CA: true
    ...
```

`--subject`, `--issuer` and `--fingerprint` print one field alone. `--der-out FILE` also writes the
certificate as DER, which converts a PEM file.

### `certval crl` describes a CRL

Issuer, this and next update, the number of revoked certificates and the CRL's extensions.
`--revoked` lists each entry with its revocation date and reason.

### `certval asn1parse` dumps DER

One line per element, in `openssl asn1parse`'s layout, which is familiar enough to keep. Object
identifiers are named. `--nested` also opens OCTET STRING and BIT STRING contents that are
themselves DER, such as extension values and public keys.

### `certval verify` validates a certification path

```text
$ certval verify --anchor TrustAnchorRootCertificate.crt --chain GoodCACert.crt ValidCertificatePathTest1EE.crt
path 0: Valid
    anchor        CN=Trust Anchor,O=Test Certificates 2011,C=US
    intermediate  CN=Good CA,O=Test Certificates 2011,C=US
    target        CN=Valid EE Certificate Test1,O=Test Certificates 2011,C=US
```

Trust anchors come from `--anchor` files or from a store compiled into the binary, `--store fpki`
or `--store webpki_root_certs` (`--list-stores` lists them). `--chain` adds intermediates. Both
flags repeat, and a PEM file may hold several certificates, so a bundle can be named once. Every
path the sources can assemble is validated and reported, and a failure names the check that failed:

```text
path 0: SignatureVerificationFailure
```

`--settings FILE` takes certval's JSON path validation settings: the time of interest, the initial
policy set, name constraint and key usage handling. Revocation is not checked unless
`--check-revocation` (or a settings file) asks for it, as with `openssl verify`. `--crl FILE`
(repeatable) names CRLs to consult first, as `openssl verify -CRLfile` does; beyond those, CRLs
and OCSP responses are fetched over the network.

### `certval ocsp` queries a responder

```sh
certval ocsp --issuer issuer.crt cert.crt          # responder taken from the certificate's AIA
certval ocsp --issuer issuer.crt --url http://ocsp.example cert.crt --nonce --out response.der
certval ocsp --response response.der               # describe a saved response
```

Prints the response status, the responder, and each certificate's status with its this and next
update, and with `--nonce` whether the nonce was echoed. **The response's signature is not
verified**, and the output says so: certval verifies OCSP responses as part of checking a path.
`certval verify --check-revocation` is the command that does that.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success; for `verify`, at least one path is valid |
| 1 | `verify` found no valid path |
| 2 | an error: a file that cannot be read or decoded, a missing argument, a responder that cannot be reached |

## Not yet

The commands that create things (`req`, `x509 -req`, `ca`, `pkcs12`, `cms`, `ts`) are not here yet.
Their building blocks exist, but several depend on crates that have no compatible crates.io release,
and a published crate cannot depend on git.

## Testing

`cargo test` runs the unit tests with no setup. The command tests run the binary against rust-pki's
example files, named by an environment variable; when it is unset they say so and pass.

```sh
CERTVAL_CLI_EXAMPLES=../rust-pki/certval/tests/examples cargo test
```

## License

Apache-2.0 OR MIT.
