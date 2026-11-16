#!/bin/sh
#
# Prepares OpenSSL's FIPS provider in this folder for use by certval-fips: runs openssl fipsinstall
# on this machine, as OpenSSL's FIPS rules require (it runs the provider's self-tests and records
# its integrity check in ssl/fipsmodule.cnf), and writes ssl/openssl.cnf, which loads the FIPS
# provider and makes it the only source of algorithms. Run it again if the folder is moved.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$here/ssl"

# The fipsinstall of the provider's own release, 3.0.9.
"$here/libexec/openssl-fipsinstall" fipsinstall \
    -module "$here/lib/ossl-modules/fips.dylib" -out "$here/ssl/fipsmodule.cnf"

cat > "$here/ssl/openssl.cnf" <<CNF
config_diagnostics = 1
openssl_conf = openssl_init

.include $here/ssl/fipsmodule.cnf

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect
base = base_sect

[base_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
CNF

cat <<MSG

OpenSSL's FIPS provider is ready. To use it with certval-fips --crypto openssl:

  export OPENSSL_CONF="$here/ssl/openssl.cnf"
  export OPENSSL_MODULES="$here/lib/ossl-modules"
MSG
