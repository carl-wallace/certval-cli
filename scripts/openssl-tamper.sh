#!/usr/bin/env bash
# Runs `certval cms` against messages openssl made and the script then broke, under every --crypto
# choice the certval binary offers, and reports a matrix of what each choice did with each case.
# Every case is expected to be refused, and for a stated reason.
#
#   decrypt  openssl encrypts, one field of the message is changed, certval decrypts:
#            RSA PKCS #1 v1.5 and OAEP encryptedKey; ECDH originator key, KDF, key wrap and
#            encryptedKey; ML-KEM ciphertext, KDF, kekLength and encryptedKey; the content
#            algorithm's key size; AES-CBC padding; AES-GCM tag, nonce, ciphertext and tag length;
#            and the recipient's certificate presented with another key
#   verify   openssl signs, one field of the message is changed, certval verifies and validates
#            against the test CA: the signature (RSA PKCS #1 v1.5 and PSS, ECDSA, ML-DSA), the
#            content with and without signed attributes, the messageDigest, signingTime and
#            content-type attributes, a digestAlgorithm the signature algorithm does not use,
#            detached content, and signers whose certificates do not lead to the test CA
#
# A test CA and keys are made with openssl in WORKDIR, as scripts/openssl-interop.sh makes them.
# ML-DSA needs openssl 3.5, and ML-KEM in CMS 3.6; with an older openssl those cases are left
# out and the summary says so.
#
# On Windows the script runs under Git for Windows' bash, with a certval.exe built there (the
# openssl choice is not offered on Windows). Git's own openssl is 3.1, which leaves ML-DSA and
# ML-KEM out; -s names a newer one, such as the OpenSSL winget installs.
#
# Each field is found with `openssl asn1parse` and changed in place, one octet, so that the
# message still decodes and the change reaches the check the case is about rather than the
# decoder. Each case runs first unbroken, as a control: a control certval does not pass proves
# nothing about the broken message. The broken message then runs with --only, so that the choice
# alone handles it, and again without --only when the choice declines:
#
#   ok        the choice refused it, for the reason the case expects
#   sw        the choice declined, and software behind it refused it for that reason
#   no        the choice declined, and software could not stand in either
#   n/a       the choice has no key for it (PKCS #11 holds only the keys pkcs11-tool can import)
#   ACCEPTED  certval succeeded with the broken message
#   REASON    certval refused it, but not for the reason the case expects
#   DECODE    certval refused it as undecodable: the change broke the encoding, not the field
#   CTRL      certval did not pass the unbroken message, so the case says nothing
#   NOFIELD   the field the case changes was not found in openssl's message
#   OSSL      openssl could not make the input for the case (the row is openssl's limit)
#
# Usage:
#   scripts/openssl-tamper.sh [-c CERTVAL] [-s OPENSSL] [-w WORKDIR] [--crypto LIST]
#                             [--ops decrypt,verify]
#                             [--pkcs11-module FILE] [--pkcs11-token LABEL] [--pkcs11-pin PIN]
#                             [--log FILE] [--archive]
#
#   -c CERTVAL        the certval binary, built with the openssl feature to include that choice;
#                     defaults to $CERTVAL, then certval on PATH
#   -s OPENSSL        the openssl binary; defaults to $OPENSSL, then openssl on PATH
#   -w WORKDIR        where the keys, messages and results go; defaults to a new directory under
#                     $TMPDIR
#   --crypto LIST     the --crypto choices to run; defaults to every one the binary offers, without
#                     pkcs11 when no module is named
#   --ops LIST        run only these operations
#   --pkcs11-module, --pkcs11-token, --pkcs11-pin
#                     the module, token label and user PIN for pkcs11; default to
#                     $CERTVAL_PKCS11_MODULE, $CERTVAL_PKCS11_TOKEN_LABEL and
#                     $CERTVAL_PKCS11_USER_PIN, as certval-pkcs11's env script sets them
#   --log FILE        writes every openssl, certval and pkcs11-tool command the script runs to FILE,
#                     under a comment line for each case, ready to paste into a shell (the PIN
#                     included); the octet changes are logged as comments
#   --archive         keeps each case's messages in WORKDIR/archive/OP/CASE: control.der, the
#                     message openssl made; broken.der, the message certval refused; and
#                     change.txt, what was changed, with `cmp -l` of the two. The cases that
#                     change no octet keep the files they vary instead
#
# For pkcs11, the RSA, EC and ML-KEM keys are put on the token with pkcs11-tool (OpenSC) as token
# objects with an ID of this run's own, and removed when the script exits. Decrypting takes the key
# by the message's recipient identifiers, as `certval cms decrypt` does without --key.
#
# Exit status: 0 when every cell is ok, sw, no or n/a; 1 when any is ACCEPTED, REASON, DECODE,
# CTRL, NOFIELD or OSSL; 2 on a usage error. Every non-ok cell's commands and messages are in
# WORKDIR/report.txt, the matrix in WORKDIR/summary.txt, one line per cell in WORKDIR/results.tsv,
# and the message of every refusal in WORKDIR/reasons.tsv.

set -euo pipefail

CERTVAL=${CERTVAL:-certval}
OPENSSL=${OPENSSL:-openssl}
WORK=
CRYPTOS=
OPS=decrypt,verify
PKCS11_MODULE=${CERTVAL_PKCS11_MODULE:-}
PKCS11_TOKEN=${CERTVAL_PKCS11_TOKEN_LABEL:-}
PKCS11_PIN=${CERTVAL_PKCS11_USER_PIN:-}
LOG=
ARCHIVE=0

usage() {
    sed -n '/^# Usage:/,/^# For pkcs11/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case $1 in
        -c) CERTVAL=$2; shift 2 ;;
        -s) OPENSSL=$2; shift 2 ;;
        -w) WORK=$2; shift 2 ;;
        --crypto) CRYPTOS=$2; shift 2 ;;
        --ops) OPS=$2; shift 2 ;;
        --pkcs11-module) PKCS11_MODULE=$2; shift 2 ;;
        --pkcs11-token) PKCS11_TOKEN=$2; shift 2 ;;
        --pkcs11-pin) PKCS11_PIN=$2; shift 2 ;;
        --log) LOG=$2; shift 2 ;;
        --archive) ARCHIVE=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

for op in $(printf '%s\n' "$OPS" | tr ',' ' '); do
    case $op in decrypt|verify) ;; *) echo "unknown operation: $op" >&2; usage ;; esac
done

command -v "$CERTVAL" >/dev/null || { echo "certval not found: $CERTVAL" >&2; exit 2; }
command -v "$OPENSSL" >/dev/null || { echo "openssl not found: $OPENSSL" >&2; exit 2; }
# Absolute, since certval and openssl run from inside WORKDIR.
absolute() { local p; p=$(command -v "$1"); case $p in /*) echo "$p" ;; *) echo "$(cd "$(dirname "$p")" && pwd)/$(basename "$p")" ;; esac; }
CERTVAL=$(absolute "$CERTVAL")
OPENSSL=$(absolute "$OPENSSL")
[ -n "$WORK" ] || WORK=$(mktemp -d "${TMPDIR:-/tmp}/certval-openssl-tamper.XXXXXX")
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)
PKI=$WORK/pki
mkdir -p "$PKI"
REPORT=$WORK/report.txt
RESULTS=$WORK/results.tsv
REASONS=$WORK/reasons.tsv
: > "$REPORT"
: > "$RESULTS"
: > "$REASONS"
if [ -n "$LOG" ]; then
    : > "$LOG"
    LOG=$(cd "$(dirname "$LOG")" && pwd)/$(basename "$LOG")
fi

# logcmd COMMAND...: appends COMMAND to the --log file, quoted for a shell.
logcmd() {
    [ -n "$LOG" ] || return 0
    { printf '%q' "$1"; shift; [ $# -eq 0 ] || printf ' %q' "$@"; printf '\n'; } >> "$LOG"
}
# logcase TEXT: a comment line in the --log file ahead of a case's commands.
logcase() {
    [ -n "$LOG" ] || return 0
    printf '\n# %s\n' "$*" >> "$LOG"
}
# lognote TEXT: a comment line in the --log file among a case's commands.
lognote() {
    [ -n "$LOG" ] || return 0
    printf '# %s\n' "$*" >> "$LOG"
}

# The choices the binary offers, from its short help: "[possible values: software, openssl, ...]".
help=$("$CERTVAL" cms decrypt -h)
offered=$(printf '%s\n' "$help" | awk '/--crypto/ {c = 1} c && /possible values:/ {sub(/.*possible values: /, ""); sub(/\].*/, ""); gsub(/ /, ""); print; exit}')
[ -n "$offered" ] || { echo "could not read the --crypto choices from certval cms decrypt -h" >&2; exit 2; }
if [ -z "$CRYPTOS" ]; then
    CRYPTOS=$offered
    [ -n "$PKCS11_MODULE" ] || CRYPTOS=$(printf '%s\n' "$CRYPTOS" | tr ',' '\n' | grep -vx pkcs11 | paste -sd, -)
fi
for c in $(printf '%s\n' "$CRYPTOS" | tr ',' ' '); do
    case ",$offered," in *",$c,"*) ;; *) echo "$CERTVAL does not offer --crypto $c (it offers $offered)" >&2; exit 2 ;; esac
done
BACKENDS=$(printf '%s\n' "$CRYPTOS" | tr ',' ' ')

wanted() { case ",$OPS," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

# contains TEXT PATTERN: whether TEXT holds PATTERN, matched in the shell (see openssl-interop.sh
# for why not `printf | grep -q` under pipefail).
contains() { case $1 in *"$2"*) return 0 ;; *) return 1 ;; esac; }

# ---- openssl's version decides the post-quantum cases

version=$("$OPENSSL" version | awk '{print $2}')
major=${version%%.*}
minor=${version#*.}; minor=${minor%%.*}
PQ_SIG=0; PQ_KEM=0
if [ "$major" -gt 3 ] || { [ "$major" = 3 ] && [ "$minor" -ge 5 ]; }; then PQ_SIG=1; fi
if [ "$major" -gt 3 ] || { [ "$major" = 3 ] && [ "$minor" -ge 6 ]; }; then PQ_KEM=1; fi

# Under Git for Windows' bash, certval and openssl are native programs: the shell converts the
# POSIX paths among their arguments to Windows paths, which keeps WORKDIR usable as it is, but
# would make a path of -subj's /CN=... too, so that is excluded; and a path in an environment
# variable is not converted, so OPENSSL_CONF is given a Windows one.
windows_path() { printf '%s\n' "$1"; }
case $(uname -s) in
    MINGW*|MSYS*) export MSYS2_ARG_CONV_EXCL='/CN='; windows_path() { cygpath -m "$1"; } ;;
esac
export OPENSSL_CONF
OPENSSL_CONF=$(windows_path "$PKI/openssl.cnf")
printf '[req]\ndistinguished_name = dn\n[dn]\n' > "$OPENSSL_CONF"
if [ -n "$LOG" ]; then
    logcmd cd "$PKI"
    logcmd export "OPENSSL_CONF=$OPENSSL_CONF"
    logcase "the test PKI"
fi

ossl() { logcmd "$OPENSSL" "$@"; (cd "$PKI" && "$OPENSSL" "$@"); }

# ---- the test PKI

MSG=$PKI/message.txt
printf 'certval openssl-tamper, a message longer than one AES block so that padding is exercised\n' > "$MSG"

echo "making the test PKI in $PKI"
ca_ext="-addext basicConstraints=critical,CA:TRUE -addext keyUsage=keyCertSign,cRLSign"
# shellcheck disable=SC2086
ossl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt \
    -subj "/CN=certval openssl-tamper CA" -days 2 $ca_ext 2>/dev/null
# Two CAs the anchor does not lead to: one with the test CA's name and a key of its own, and one
# with a name of its own.
# shellcheck disable=SC2086
ossl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout same-name.key -out same-name.crt \
    -subj "/CN=certval openssl-tamper CA" -days 2 $ca_ext 2>/dev/null
# shellcheck disable=SC2086
ossl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout other.key -out other.crt \
    -subj "/CN=another CA" -days 2 $ca_ext 2>/dev/null
printf 'basicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$PKI/ee.ext"

RSA_KEYS="rsa2048"
EC_KEYS="p256 p384"
KEM_KEYS=""
DSA_KEYS=""
[ "$PQ_KEM" = 1 ] && KEM_KEYS="mlkem768"
[ "$PQ_SIG" = 1 ] && DSA_KEYS="mldsa65"

genkey() {
    case $1 in
        rsa2048) ossl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" ;;
        p256) ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key" ;;
        p384) ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$1.key" ;;
        mlkem768) ossl genpkey -algorithm ML-KEM-768 -out "$1.key" ;;
        mldsa65) ossl genpkey -algorithm ML-DSA-65 -out "$1.key" ;;
    esac
}

for k in $RSA_KEYS $EC_KEYS $KEM_KEYS $DSA_KEYS; do
    genkey "$k" 2>/dev/null
    issue="-CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile ee.ext -out $k.crt"
    case $k in
        mlkem*)
            # An ML-KEM key cannot sign a request, so its certificate is made from the public key.
            ossl pkey -in "$k.key" -pubout -out "$k.pub"
            # shellcheck disable=SC2086
            ossl x509 -new -subj "/CN=$k" -force_pubkey "$k.pub" $issue 2>/dev/null ;;
        *)
            ossl req -new -key "$k.key" -subj "/CN=$k" -out "$k.csr"
            # shellcheck disable=SC2086
            ossl x509 -req -in "$k.csr" $issue 2>/dev/null ;;
    esac
done
# A key of rsa2048's kind that is not rsa2048's.
ossl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out other-rsa2048.key 2>/dev/null
for ca in same-name other; do
    ossl x509 -req -in p256.csr -CA "$ca.crt" -CAkey "$ca.key" -CAcreateserial -days 2 \
        -extfile ee.ext -out "p256-from-$ca.crt" 2>/dev/null
done

# ---- keys on a PKCS #11 token

ON_TOKEN=" "
TOKEN_IDS=""
P11_ARGS=()
p11tool() {
    local token=()
    [ -z "$PKCS11_TOKEN" ] || token=(--token-label "$PKCS11_TOKEN")
    logcmd pkcs11-tool --module "$PKCS11_MODULE" ${token[@]+"${token[@]}"} --login --pin "$PKCS11_PIN" "$@"
    pkcs11-tool --module "$PKCS11_MODULE" ${token[@]+"${token[@]}"} --login --pin "$PKCS11_PIN" "$@"
}
cleanup_token() {
    local id
    logcase "removing the keys from the token"
    for id in $TOKEN_IDS; do
        p11tool --delete-object --type privkey --id "$id" >/dev/null 2>&1 || true
        p11tool --delete-object --type cert --id "$id" >/dev/null 2>&1 || true
    done
}
case " $BACKENDS " in
    *" pkcs11 "*)
        [ -n "$PKCS11_PIN" ] || { echo "pkcs11 needs --pkcs11-pin (or CERTVAL_PKCS11_USER_PIN)" >&2; exit 2; }
        P11_ARGS=(--pkcs11-module "$PKCS11_MODULE" --pkcs11-pin "$PKCS11_PIN")
        [ -z "$PKCS11_TOKEN" ] || P11_ARGS+=(--pkcs11-token "$PKCS11_TOKEN")
        if command -v pkcs11-tool >/dev/null; then
            trap cleanup_token EXIT
            logcase "keys on the token"
            run_id=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
            n=0
            for k in $RSA_KEYS $EC_KEYS $KEM_KEYS; do
                n=$((n + 1))
                id=$run_id$(printf '%02x' "$n")
                ossl pkcs8 -topk8 -nocrypt -in "$k.key" -outform DER -out "$k.p8"
                ossl x509 -in "$k.crt" -outform DER -out "$k.der"
                if p11tool --write-object "$PKI/$k.p8" --type privkey --id "$id" --label "certval-tamper-$k" \
                        --usage-decrypt --usage-derive >/dev/null 2>&1; then
                    TOKEN_IDS="$TOKEN_IDS $id"
                    if p11tool --write-object "$PKI/$k.der" --type cert --id "$id" --label "certval-tamper-$k" >/dev/null 2>&1; then
                        ON_TOKEN="$ON_TOKEN$k "
                    fi
                fi
            done
            echo "keys on the token: ${ON_TOKEN# }"
        else
            echo "pkcs11-tool not found: pkcs11 decrypts with no key (n/a)"
        fi ;;
esac

# ---- finding and changing a field

# locate FILE WHICH PATTERN [AFTER]: finds, in openssl asn1parse's listing of FILE, the first or
# last (WHICH) line holding PATTERN, after the first line holding AFTER when one is given. Sets AT
# to the offset of its contents and LEN to their length; returns 1 when there is no such line.
locate() {
    local file=$1 which=$2 pattern=$3 after=${4:-} found
    found=$("$OPENSSL" asn1parse -inform DER -in "$file" | awk -v p="$pattern" -v a="$after" -v w="$which" '
        a != "" && !seen { if (index($0, a)) seen = 1; next }
        index($0, p) {
            split($0, f, ":"); o = f[1] + 0
            match($0, /hl= *[0-9]+/); h = substr($0, RSTART + 3, RLENGTH - 3) + 0
            match($0, / l= *[0-9]+/); l = substr($0, RSTART + 3, RLENGTH - 3) + 0
            r = (o + h) " " l
            if (w == "first") { print r; exit }
        }
        END { if (w == "last" && r != "") print r }')
    [ -n "$found" ] || return 1
    # shellcheck disable=SC2034 # AT and LEN are read by the POSITION expression mutate evaluates
    read -r AT LEN <<< "$found"
}

octet() { od -An -tx1 -j "$2" -N1 "$1" | tr -d ' \n'; }
poke() { printf "\\x$3" | dd of="$1" bs=1 seek="$2" count=1 conv=notrunc 2>/dev/null; }

# mutate FILE MODE WHICH PATTERN AFTER POSITION [VALUE]: locates the field (see locate) and, at
# POSITION, an arithmetic expression in AT and LEN, flips the low bit of the octet (MODE flip) or
# writes VALUE, two hex digits, in its place (MODE set). Returns 1 when the field is not found.
mutate() {
    local file=$1 mode=$2 which=$3 pattern=$4 after=$5 position=$6 value=${7:-} at old
    locate "$file" "$which" "$pattern" "$after" || return 1
    at=$((position))
    old=$(octet "$file" "$at")
    case $mode in
        flip) value=$(printf '%02x' $((0x$old ^ 1))) ;;
        set) ;;
    esac
    poke "$file" "$at" "$value"
    CHANGE="octet $at ($which \"$pattern\"${after:+ after \"$after\"}): $old -> $value"
    lognote "$CHANGE"
}

# archive TEXT FILE...: with --archive, copies each FILE (a path, or NAME=PATH to save it as
# NAME) to the case's directory under WORKDIR/archive, and writes TEXT to its change.txt, with
# `cmp -l` of control.der and broken.der when both are among the files.
archive() {
    [ "$ARCHIVE" = 1 ] || return 0
    local text=$1 dir f
    shift
    dir=$WORK/archive/$OP/$(printf '%s' "$CASE" | tr -cs 'A-Za-z0-9' '-' | sed 's/-$//')
    mkdir -p "$dir"
    for f in "$@"; do
        case $f in
            *=*) cp "${f#*=}" "$dir/${f%%=*}" ;;
            *) cp "$f" "$dir/" ;;
        esac
    done
    {
        printf '%s\n%s\n' "$OP  $CASE" "$text"
        if [ -f "$dir/control.der" ] && [ -f "$dir/broken.der" ]; then
            printf '\ncmp -l control.der broken.der (offset from 1, octets in octal):\n'
            cmp -l "$dir/control.der" "$dir/broken.der" || true
        fi
    } > "$dir/change.txt"
}

# ---- running certval and recording what happened

CV_OUT=$WORK/certval.out
CV_ERR=$WORK/certval.err
CONTENT=$WORK/content.out

cv() {
    local status=0
    logcmd "$CERTVAL" "$@"
    (cd "$PKI" && "$CERTVAL" "$@") > "$CV_OUT" 2> "$CV_ERR" || status=$?
    LAST_CMD="certval $*"
    return $status
}

record() {
    printf '%s\t%s\t%s\t%s\n' "$OP" "$CASE" "$1" "$2" >> "$RESULTS"
}

# note BACKEND OUTCOME TEXT: a non-ok cell, with what explains it, in the report.
note() {
    {
        printf '%s  %s  %s  %s\n' "$OP" "$CASE" "$1" "$2"
        printf '%s\n' "$3" | sed 's/^/    /'
    } >> "$REPORT"
}

# The openssl side of a case could not be made, or its field not found: every backend's cell
# says so.
every_cell() {
    local b
    for b in $BACKENDS; do record "$b" "$1"; done
    note "-" "$1" "$2"
}

DECLINED='not performed by this implementation'
UNDECODABLE='not a CMS message'

# run_both BACKEND ARGS...: runs certval ARGS with --crypto BACKEND and --only, and again without
# --only when the choice declines. Sets RAN to only, all or declined (both declined), and
# returns certval's status from the last run.
run_both() {
    local b=$1
    shift
    local cargs=(--crypto "$b")
    [ "$b" != pkcs11 ] || cargs+=("${P11_ARGS[@]}")
    RAN=only
    if cv "$@" "${cargs[@]}" --only; then return 0; fi
    contains "$(cat "$CV_ERR")" "$DECLINED" || return 1
    [ "$b" != software ] || { RAN=declined; return 1; }
    RAN=all
    if cv "$@" "${cargs[@]}"; then return 0; fi
    contains "$(cat "$CV_ERR")" "$DECLINED" && RAN=declined
    return 1
}

# control BACKEND CHECK ARGS...: runs certval ARGS, the unbroken case, which CHECK (a function)
# must accept. When it does not, records the outcome and returns 1.
control() {
    local b=$1 check=$2 outcome
    shift 2
    if run_both "$b" "$@" && $check; then return 0; fi
    if [ "$RAN" = declined ]; then
        outcome=no; note "$b" "$outcome" "control: $LAST_CMD"$'\n'"$(cat "$CV_ERR")"
    else
        outcome=CTRL; note "$b" "$outcome" "control: $LAST_CMD"$'\n'"$(cat "$CV_ERR")${CHECK_MSG:+$'\n'$CHECK_MSG}"
    fi
    CHECK_MSG=; record "$b" "$outcome"
    return 1
}

# refusal BACKEND EXPECT ARGS...: runs certval ARGS, the broken case, which certval must refuse
# with a message matching EXPECT, an extended regular expression; records the outcome.
refusal() {
    local b=$1 expect=$2 err outcome
    shift 2
    if run_both "$b" "$@"; then
        outcome=ACCEPTED
        note "$b" "$outcome" "$LAST_CMD"$'\n'"$(cat "$CV_OUT")"
        record "$b" "$outcome"; return
    fi
    err=$(cat "$CV_ERR")
    printf '%s\t%s\t%s\t%s\t%s\n' "$OP" "$CASE" "$b" "$RAN" "$err" >> "$REASONS"
    if [ "$RAN" = declined ]; then
        outcome=no; note "$b" "$outcome" "$LAST_CMD"$'\n'"$err"
    elif contains "$err" "$UNDECODABLE"; then
        outcome=DECODE; note "$b" "$outcome" "$LAST_CMD"$'\n'"$err"
    elif ! printf '%s\n' "$err" | grep -Eq -- "$expect"; then
        outcome=REASON; note "$b" "$outcome" "$LAST_CMD"$'\n'"expected: $expect"$'\n'"got: $err"
    elif [ "$RAN" = all ]; then
        outcome=sw; note "$b" "$outcome" "$LAST_CMD"$'\n'"$err"
    else
        outcome=ok
    fi
    record "$b" "$outcome"
}

# ---- checks, run on the control after certval succeeds; each sets CHECK_MSG when it fails

CHECK_MSG=
content_matches() {
    if cmp -s "$CONTENT" "$MSG"; then return 0; fi
    CHECK_MSG="the decrypted content differs from the message"; return 1
}
certval_validates() {
    if ! grep -q 'signature verified, certificate validated' "$CV_OUT"; then
        CHECK_MSG="certval: $(cat "$CV_OUT")"; return 1
    fi
    content_matches
}

# ---- decrypt: openssl encrypts, the message is broken, certval decrypts

# The reasons certval gives.
KT_FAILED='key transport failed'
UNWRAP_FAILED='key unwrap failed'
CONTENT_FAILED='content decryption failed'

# decrypt_case CASE KEY EXPECT MUTATION OPENSSL_ARGS...: openssl encrypts to KEY with
# OPENSSL_ARGS; MUTATION, the arguments of mutate after the file, breaks a copy. A MUTATION of
# "other-key KEY2" breaks nothing and presents KEY's certificate with KEY2's private key.
decrypt_case() {
    CASE=$1; local key=$2 expect=$3 mutation=$4
    shift 4
    logcase "$OP  $CASE"
    local err control=$WORK/control.der broken=$WORK/broken.der b
    if ! err=$(ossl cms -encrypt -binary -in "$MSG" -outform DER -out "$control" -recip "$key.crt" "$@" 2>&1); then
        every_cell OSSL "openssl cms -encrypt -recip $key.crt $*: $err"; return
    fi
    cp "$control" "$broken"
    local key_file=$PKI/$key.key
    case $mutation in
        other-key\ *)
            key_file=$PKI/${mutation#other-key }.key; broken=$control
            archive "the message is unchanged; certval is given $key.crt with ${key_file##*/} in place of $key.key" \
                "$control" "$PKI/$key.crt" "$PKI/$key.key" "$key_file" ;;
        *)
            # shellcheck disable=SC2086
            if ! eval mutate '"$broken"' $mutation; then
                every_cell NOFIELD "not found: $mutation"; return
            fi
            archive "$CHANGE" "$control" "$broken" ;;
    esac
    for b in $BACKENDS; do
        local good=(--cert "$PKI/$key.crt" --key "$PKI/$key.key") bad
        if [ "$b" = pkcs11 ]; then
            case $ON_TOKEN in *" $key "*) ;; *) record "$b" n/a; continue ;; esac
            case $mutation in other-key\ *) record "$b" n/a; continue ;; esac
            good=()
        fi
        bad=(${good[@]+"${good[@]}"})
        [ "$key_file" = "$PKI/$key.key" ] || bad=(--cert "$PKI/$key.crt" --key "$key_file")
        control "$b" content_matches cms decrypt --out "$CONTENT" ${good[@]+"${good[@]}"} --in "$control" || continue
        refusal "$b" "$expect" cms decrypt --out "$CONTENT" ${bad[@]+"${bad[@]}"} --in "$broken"
    done
}

OAEP="-keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha256"
ECDH="-keyopt ecdh_kdf_md:sha256"

if wanted decrypt; then
    OP=decrypt
    echo "== decrypt (openssl encrypts, the message is broken, certval decrypts)"
    # shellcheck disable=SC2086
    {
        # RSA. PKCS #1 v1.5 goes on with a random key when the padding is bad (RFC 3218), so it
        # fails at content decryption; with AES-GCM, so that the failure does not depend on the
        # random key's CBC padding coming out wrong, which it does not 1 time in 256.
        decrypt_case "rsa2048 pkcs1v15 encryptedKey" rsa2048 "$CONTENT_FAILED" \
            "flip first 'OCTET STRING' '' AT+LEN-1" -aes-256-gcm
        decrypt_case "rsa2048 oaep encryptedKey" rsa2048 "$KT_FAILED" \
            "flip first 'OCTET STRING' '' AT+LEN-1" -aes-256-gcm $OAEP
        decrypt_case "rsa2048 oaep aes-256-gcm named aes-128-gcm" rsa2048 "$CONTENT_FAILED" \
            "set first ':aes-256-gcm' '' AT+LEN-1 06" -aes-256-gcm $OAEP
        decrypt_case "rsa2048 the certificate with another RSA key" rsa2048 \
            "not the certificate's|not the key the certificate contains" \
            "other-key other-rsa2048" -aes-256-gcm $OAEP

        # ECDH. The originator key's first X octet: a point off the curve, which must not reach
        # the key agreement as a point of another curve.
        decrypt_case "p256 originator key off the curve" p256 "key agreement failed" \
            "flip first 'BIT STRING' '' AT+5" -aes-256-cbc $ECDH
        decrypt_case "p384 originator key off the curve" p384 "key agreement failed" \
            "flip first 'BIT STRING' '' AT+5" -aes-256-gcm -keyopt ecdh_kdf_md:sha384
        decrypt_case "p256 encryptedKey" p256 "$UNWRAP_FAILED" \
            "flip first 'OCTET STRING' '' AT+LEN-1" -aes-256-cbc $ECDH
        decrypt_case "p256 sha256 KDF named sha384" p256 "$UNWRAP_FAILED" \
            "set first ':dhSinglePass-stdDH-sha256kdf-scheme' '' AT+LEN-1 02" -aes-256-cbc $ECDH
        decrypt_case "p256 aes256-wrap named aes128-wrap" p256 "$UNWRAP_FAILED" \
            "set first ':id-aes256-wrap' '' AT+LEN-1 05" -aes-256-cbc $ECDH
        decrypt_case "p256 aes-256-cbc named aes-128-cbc" p256 "$CONTENT_FAILED" \
            "set first ':aes-256-cbc' '' AT+LEN-1 02" -aes-256-cbc $ECDH

        # Content. The CBC case changes the last octet of the next-to-last ciphertext block, which
        # changes the padding length octet of the last plaintext block and nothing else.
        decrypt_case "aes-256-cbc padding" p256 "$CONTENT_FAILED" \
            "flip last 'prim: cont [ 0 ]' '' AT+LEN-17" -aes-256-cbc $ECDH
        decrypt_case "aes-256-gcm tag" p256 "$CONTENT_FAILED" \
            "flip last 'OCTET STRING' '' AT+LEN-1" -aes-256-gcm $ECDH
        decrypt_case "aes-256-gcm ciphertext" p256 "$CONTENT_FAILED" \
            "flip last 'prim: cont [ 0 ]' '' AT" -aes-256-gcm $ECDH
        decrypt_case "aes-256-gcm nonce" p256 "$CONTENT_FAILED" \
            "flip first 'OCTET STRING' ':aes-256-gcm' AT" -aes-256-gcm $ECDH
        decrypt_case "aes-256-gcm 16-octet tag, icvLen 12" p256 "where GCMParameters gives 12" \
            "set first 'INTEGER' ':aes-256-gcm' AT 0c" -aes-256-gcm $ECDH
        decrypt_case "aes-256-gcm icvLen 8" p256 "RFC 5084 allows 12 to 16" \
            "set first 'INTEGER' ':aes-256-gcm' AT 08" -aes-256-gcm $ECDH

        # ML-KEM. A changed ciphertext decapsulates, implicitly rejected, to a key that unwraps
        # nothing.
        for k in $KEM_KEYS; do
            decrypt_case "$k kemct" "$k" "$UNWRAP_FAILED" \
                "flip first 'OCTET STRING' '' AT+100" -aes-256-gcm
            decrypt_case "$k encryptedKey" "$k" "$UNWRAP_FAILED" \
                "flip first 'OCTET STRING' ':id-aes256-wrap' AT+LEN-1" -aes-256-gcm
            decrypt_case "$k hkdf-sha256 named hkdf-sha384" "$k" "$UNWRAP_FAILED" \
                "flip first ':HKDF-SHA256' '' AT+LEN-1" -aes-256-gcm
            decrypt_case "$k kekLength 16 with aes256-wrap" "$k" "kekLength does not match" \
                "set first 'INTEGER' ':HKDF-SHA256' AT 10" -aes-256-gcm
        done
    }
fi

# ---- verify: openssl signs, the message is broken, certval verifies and validates

SIG_FAILED='Signature verification failure'
DIGEST_FAILED='message digest does not match'

# verify_case CASE KEY EXPECT MUTATION OPENSSL_ARGS...: openssl signs with KEY's key and
# certificate (KEY may name another certificate as KEY:CERT) and OPENSSL_ARGS; MUTATION, the
# arguments of mutate after the file, breaks a copy. A MUTATION of "content" signs detached and
# breaks the content instead. With "none" nothing is broken: CERT is KEY-from-CA, and the control
# validates against CA's certificate where the broken run validates against the test CA's.
verify_case() {
    CASE=$1; local key=${2%%:*} cert=${2#*:} expect=$3 mutation=$4
    shift 4
    [ "$cert" != "$2" ] || cert=$key
    logcase "$OP  $CASE"
    local err control=$WORK/control.der broken=$WORK/broken.der b
    if ! err=$(ossl cms -sign -binary -in "$MSG" -signer "$cert.crt" -inkey "$key.key" -outform DER -out "$control" "$@" 2>&1); then
        every_cell OSSL "openssl cms -sign -signer $cert.crt $*: $err"; return
    fi
    cp "$control" "$broken"
    case $mutation in
        none)
            archive "the message is unchanged; the control validates against ${cert#*-from-}.crt, the broken run against ca.crt" \
                "$control" "$PKI/$cert.crt" "$PKI/${cert#*-from-}.crt" "$PKI/ca.crt" ;;
        content)
            sed 's/openssl-tamper/openssl-Tamper/' "$MSG" > "$WORK/content.txt"
            lognote "the detached content changed: $WORK/content.txt"
            archive "the message is unchanged; the control verifies content-control.txt, the broken run content-broken.txt"$'\n\n'"$(diff "$MSG" "$WORK/content.txt" || true)" \
                "$control" "content-control.txt=$MSG" "content-broken.txt=$WORK/content.txt" ;;
        *)
            # shellcheck disable=SC2086
            if ! eval mutate '"$broken"' $mutation; then
                every_cell NOFIELD "not found: $mutation"; return
            fi
            archive "$CHANGE" "$control" "$broken" ;;
    esac
    local anchor=$PKI/ca.crt good=() bad=()
    case $mutation in
        # The certificate's own CA, which the control validates against.
        none) anchor=$PKI/${cert#*-from-}.crt ;;
        content) good=(--content "$MSG"); bad=(--content "$WORK/content.txt") ;;
    esac
    for b in $BACKENDS; do
        if [ "$b" = pkcs11 ]; then record "$b" n/a; continue; fi
        control "$b" certval_validates cms verify --anchor "$anchor" --out "$CONTENT" ${good[@]+"${good[@]}"} --in "$control" || continue
        refusal "$b" "$expect" cms verify --anchor "$PKI/ca.crt" --out "$CONTENT" ${bad[@]+"${bad[@]}"} --in "$broken"
    done
}

if wanted verify; then
    OP=verify
    echo "== verify (openssl signs, the message is broken, certval verifies and validates)"
    # The signature is the last OCTET STRING of a message openssl signs: one SignerInfo, no
    # unsigned attributes. The content is the first.
    SIGNATURE="flip last 'OCTET STRING' '' AT+LEN-1"
    CONTENT_OCTET="flip first 'OCTET STRING' '' AT+10"
    verify_case "rsa2048 pkcs1v15 signature" rsa2048 "$SIG_FAILED" "$SIGNATURE" -nodetach -md sha256
    verify_case "rsa2048 pss signature" rsa2048 "$SIG_FAILED" "$SIGNATURE" -nodetach -md sha256 \
        -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:digest
    verify_case "p256 ecdsa signature" p256 "$SIG_FAILED" "$SIGNATURE" -nodetach -md sha256
    verify_case "p384 ecdsa signature" p384 "$SIG_FAILED" "$SIGNATURE" -nodetach -md sha384
    for k in $DSA_KEYS; do
        verify_case "$k signature" "$k" "$SIG_FAILED" "$SIGNATURE" -nodetach -md sha512
    done
    verify_case "p256 content" p256 "$DIGEST_FAILED" "$CONTENT_OCTET" -nodetach -md sha256
    verify_case "p256 content, without signed attributes" p256 "$SIG_FAILED" "$CONTENT_OCTET" \
        -nodetach -md sha256 -noattr
    verify_case "p256 detached content" p256 "$DIGEST_FAILED" content -md sha256
    verify_case "p256 messageDigest attribute" p256 "$DIGEST_FAILED" \
        "flip first 'OCTET STRING' ':messageDigest' AT+LEN-1" -nodetach -md sha256
    verify_case "p256 signingTime attribute" p256 "$SIG_FAILED" \
        "flip first 'UTCTIME' ':signingTime' AT+3" -nodetach -md sha256
    verify_case "p256 content-type attribute names signedData" p256 "content-type attribute" \
        "set first ':pkcs7-data' ':contentType' AT+LEN-1 02" -nodetach -md sha256
    # The SignerInfo's digestAlgorithm is the last sha384 OID; the SignedData's set is left alone.
    verify_case "p384 sha256 digestAlgorithm with ecdsa-with-SHA384" p384 "digestAlgorithm with a" \
        "set last ':sha384' '' AT+LEN-1 01" -nodetach -md sha384
    verify_case "p256 signer from a CA with the anchor's name and another key" p256:p256-from-same-name \
        "$SIG_FAILED|PathValidationError" none -nodetach -md sha256
    verify_case "p256 signer from another CA" p256:p256-from-other \
        "PathValidationError|path" none -nodetach -md sha256
fi

# ---- the matrix

{
    echo "certval: $CERTVAL"
    echo "openssl: $OPENSSL ($("$OPENSSL" version))"
    echo "choices: $BACKENDS"
    [ "$PQ_SIG" = 1 ] || echo "left out: ML-DSA (openssl $version is older than 3.5)"
    [ "$PQ_KEM" = 1 ] || echo "left out: ML-KEM (openssl $version is older than 3.6)"
    echo
    awk -F '\t' -v backends="$BACKENDS" '
        BEGIN { nb = split(backends, b, " "); w = 52 }
        {
            row = $1 "  " $2
            if (!(row in seen)) { seen[row] = 1; rows[++nr] = row; if (length(row) > w) w = length(row) }
            cell[row, $3] = $4
            count[$4]++
        }
        END {
            printf "%-" w "s", ""
            for (i = 1; i <= nb; i++) printf "  %-18s", b[i]
            printf "\n"
            for (r = 1; r <= nr; r++) {
                printf "%-" w "s", rows[r]
                for (i = 1; i <= nb; i++) printf "  %-18s", ((rows[r], b[i]) in cell ? cell[rows[r], b[i]] : "-")
                printf "\n"
            }
            printf "\ncells:"
            for (o in count) printf "  %s %d", o, count[o]
            printf "\n"
        }' "$RESULTS"
} > "$WORK/summary.txt"

cat "$WORK/summary.txt"
echo
echo "results: $WORK/summary.txt, $RESULTS; explanations: $REPORT; refusals: $REASONS"
if grep -qE $'\t(ACCEPTED|REASON|DECODE|CTRL|NOFIELD|OSSL)$' "$RESULTS"; then exit 1; fi
exit 0
