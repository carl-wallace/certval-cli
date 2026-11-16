certval-cli @VERSION@: the `certval` command for Linux (x86_64, glibc 2.35 or later), macOS (Apple
silicon) and Windows (x86_64). Each archive holds the binary, the README, the changelog and the
licenses. SHA256SUMS lists each archive's SHA-256, and each archive carries a build provenance
attestation, checked with `gh attestation verify <archive> --repo carl-wallace/certval-cli`.

## What the binaries offer

| Platform | `--crypto` choices |
| --- | --- |
| Linux | `software`, `aws-lc`, `pkcs11` |
| macOS | `software`, `aws-lc`, `security-framework` (with CryptoKit's ML-KEM and ML-DSA on macOS 26), `pkcs11` |
| Windows | `software`, `aws-lc`, `cng`, `pkcs11` |

The Linux binary is built without the `openssl` feature, so that it loads no library but glibc and
runs whether or not OpenSSL 3 is installed. For `--crypto openssl`, the system's OpenSSL 3 through
certval-openssl, including the FIPS provider when the system's `openssl.cnf` enables it, build the
command with that feature by either of the ways below.

## Adding OpenSSL on Linux

Both ways need Rust 1.89 or later, a C compiler (for AWS-LC), pkg-config and OpenSSL 3's headers:

```sh
sudo apt-get install build-essential pkg-config libssl-dev    # Debian, Ubuntu
sudo dnf install gcc pkgconf-pkg-config openssl-devel         # Fedora, RHEL
```

### With cargo install

```sh
cargo install certval-cli --version @VERSION@ --locked --features openssl
```

`--version` is needed while certval-cli has only pre-releases, which cargo does not choose on its
own. `--locked` builds with the dependency versions this release was tested with. The command is
installed as `~/.cargo/bin/certval`. If a `certval` command is already installed there, add
`--force` to replace it. Without it, cargo stops when the same version and features are already
installed, and refuses when the existing command came from another source, such as a
`cargo install --path` of a checkout.

### From the source

```sh
git clone https://github.com/carl-wallace/certval-cli
cd certval-cli
git checkout @TAG@
cargo build --release --locked --features openssl
```

The command is `target/release/certval`. Check that it offers OpenSSL with `certval verify --help`,
which lists `openssl` among the `--crypto` values.
