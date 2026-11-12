#!/usr/bin/env bash
# tlsfuzzer's TLS 1.3 scripts against the moontls server in `tls-peer`, all of them.
#
#     moon build --target native
#     TLSFUZZER=path/to/tlsfuzzer bash scripts/tls_fuzz.sh [script...]
#
# Each script is a conversation: tlsfuzzer plays the client and expects the server to answer every
# message the way RFC 8446 says, or to refuse it with a named alert. A script that fails names the
# case and the assertion, which is what `README.md` under "Conformance" lists.
#
# Eight servers are started, because the scripts differ in what they need of the server and not only
# in what they send it: a certificate under a given key type, a request for a client certificate,
# the TLS 1.2 suites a TLS 1.3 script probes for, and a server that sends the first KeyUpdate. The
# suites, the groups and the extensions are the same on all eight.
#
# A server is also told to leave a conversation its client has stopped speaking in (`timeout=`),
# because a script that says its last word and then reads would otherwise be ended by the runner's
# own clock and recorded as a hang, which says nothing about the library.
set -u
only=" $* "

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(dirname "$here")
# The peer is the `integration/` module's, not the library's: a socket and an event loop are
# what a consumer brings, and the library brings neither. A workspace (`moon.work`) resolves
# `moonbitstack/moontls` to this checkout, so the peer exercises the source under test.
peer="${PEER:-$root/_build/native/debug/build/moonbitstack/moontls-interop/peer/peer}"
[ -x "$peer" ] || peer="$peer.exe"
test -x "$peer" || { echo "build the peer first: moon build --target native"; exit 2; }
fuzzer=$(cd "${TLSFUZZER:?set TLSFUZZER to a tlsfuzzer checkout}" && pwd)
python=${PYTHON:-python3}
[[ "$python" != */* ]] || python="$(cd "$(dirname "$python")" && pwd)/$(basename "$python")"
# `mktemp -d` answers in the platform's own shape — a backslashed path here — and these paths are
# handed to a Python that parses them again, so they are put back into the form the shell speaks.
work=$(cd "$(mktemp -d)" && pwd)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$work"' EXIT
cd "$work"

# ---------------------------------------------------------------- certificates
#
# A root, and under it a leaf for each key type a script needs the server to hold. A script that
# checks a signature scheme needs a server certificate under that scheme, and one that checks a
# client certificate needs a root its own certificate chains to — tlsfuzzer's bundled ones expired
# in 2017, so this run issues its own and hands the scripts `-c`/`-k` for them.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key \
  -out ca.pem -days 3650 -subj "/CN=fuzz root" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
# `issue name keygen-args...` — a localhost leaf under the root, for the server or for a client.
issue() {
  local name=$1 usage=$2; shift 2
  openssl req -newkey "$@" -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=localhost" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -out "$name.pem" \
    -days 3650 -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=%s\n" "$usage") 2>/dev/null
}
issue rsa serverAuth rsa:2048
issue ec serverAuth ec -pkeyopt ec_paramgen_curve:P-256
issue ed serverAuth ed25519
issue bp serverAuth ec -pkeyopt ec_paramgen_curve:brainpoolP256r1
# RSASSA-PSS: the key's own type is the scheme, which is what `rsapss-signatures` is about.
pss=0
if openssl req -newkey rsa-pss -pkeyopt rsa_keygen_bits:2048 -nodes -keyout pss.key \
     -out pss.csr -subj "/CN=localhost" >/dev/null 2>&1 &&
   openssl x509 -req -in pss.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out pss.pem -days 3650 \
     -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n") >/dev/null 2>&1; then
  pss=1
fi
# The client certificates the scripts are handed, one per key type they name.
issue crsa clientAuth rsa:2048
issue cec clientAuth ec -pkeyopt ec_paramgen_curve:P-256
issue ced clientAuth ed25519
issue cbp clientAuth ec -pkeyopt ec_paramgen_curve:brainpoolP256r1
cmldsa=0
if openssl req -newkey mldsa65 -nodes -keyout cmldsa.key -out cmldsa.csr -subj "/CN=localhost" >/dev/null 2>&1 &&
   openssl x509 -req -in cmldsa.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out cmldsa.pem -days 3650 \
     -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=clientAuth\n") >/dev/null 2>&1; then
  cmldsa=1
fi

# Every group this library speaks, so a script that offers one of them is not refused for the wrong
# reason. The hybrids stay in: they are what this library offers first.
all=x25519,p256,p384,p521,x448,ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192,x25519mlkem768,mlkem768
base=${PORT_BASE:-4433}
# A server that leaves a conversation its client has stopped speaking in. Five seconds is longer
# than any silence a script means and shorter than the runner's patience.
hold=timeout=${HOLD:-5000}

# The eight servers, by index. A name is what a script is routed by, not a port, so that the table
# below reads as what the script needs rather than as arithmetic.
# 0 rsa        the general one
# 1 ec         an ECDSA P-256 certificate
# 2 ed         an Ed25519 certificate
# 3 ask        asks for a client certificate, under the root above
# 4 twelve     every version and every TLS 1.2 suite
# 5 update     sends the first KeyUpdate
# 6 brainpool  a brainpoolP256r1 certificate
# 7 pss        an RSASSA-PSS certificate
# 8 ask-post   asks for a client certificate once the connection is open
pids=()
started=""
start() { # index name certificate key options...
  local i=$1; shift 2
  "$peer" server $((base + i)) "$@" > "$work/server-$i.log" 2>&1 &
  pids[$i]=$!
  started="$started $i"
}
start 0 rsa rsa.pem rsa.key http groups=$all suites=aes128,aes256,chacha20 $hold
start 1 ec ec.pem ec.key http groups=$all suites=aes128,aes256,chacha20 $hold
start 2 ed ed.pem ed.key http groups=$all suites=aes128,aes256,chacha20 $hold
start 3 ask rsa.pem rsa.key http groups=$all suites=aes128,aes256,chacha20 ask=1 roots=ca.pem $hold
start 4 twelve rsa.pem rsa.key http groups=$all suites=aes128,aes256,chacha20 \
  versions=10,11,12,13 suites12=all $hold
start 5 update rsa.pem rsa.key http groups=$all suites=aes128,aes256,chacha20 update-server $hold
start 6 brainpool bp.pem bp.key http groups=$all suites=aes128,aes256,chacha20 $hold
start 8 ask-post rsa.pem rsa.key http groups=$all suites=aes128,aes256,chacha20 ask=1 roots=ca.pem \
  ask-post $hold
[ "$pss" = 1 ] && start 7 pss pss.pem pss.key http groups=$all suites=aes128,aes256,chacha20 $hold

# A server that did not come up would make every script routed to it fail with "connection
# refused", which says nothing about the library: say which it was, and judge only the rest. A
# server that exits is known at once rather than after the retries, because a configuration this
# library refuses — an RSASSA-PSS certificate is one — has nothing to wait for.
up() { # port pid
  for _ in $(seq 40); do
    (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0
    kill -0 "$2" 2>/dev/null || return 1
    sleep 0.1
  done
  return 1
}
dead=""
for i in $started; do
  up $((base + i)) "${pids[$i]}" || dead="$dead $i"
done
[ "$pss" = 1 ] || dead="$dead 7"

# The signature schemes this library verifies a peer's certificate with, in the order it names
# them: what a CertificateRequest it sends carries, and therefore what a script that checks that
# request has to be told to expect. Kept in step with `@tls.verifiable`.
schemes="ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 ecdsa_secp521r1_sha512"
schemes="$schemes ecdsa_brainpoolP256r1tls13_sha256 ecdsa_brainpoolP384r1tls13_sha384"
schemes="$schemes ecdsa_brainpoolP512r1tls13_sha512 ed25519"
schemes="$schemes rsa_pss_rsae_sha256 rsa_pss_rsae_sha384 rsa_pss_rsae_sha512"
schemes="$schemes mldsa44 mldsa65 mldsa87"

# What each script needs of the server and of its own command line: the index above, then `-c`/`-k`
# for a script that answers a CertificateRequest, `-s` for the schemes it expects the server to take,
# and `-e` for a case it is told to skip.
route() {
  case $1 in
    post-handshake-auth) echo "8 -s '$schemes' -c $work/crsa.pem -k $work/crsa.key";;
    certificate-request|certificate-verify|client-certificate-compression)
      echo "3 -s '$schemes' -c $work/crsa.pem -k $work/crsa.key";;
    ecdsa-in-certificate-verify) echo "3 -s '$schemes' -c $work/cec.pem -k $work/cec.key";;
    eddsa-in-certificate-verify) echo "3 -s '$schemes' -c $work/ced.pem -k $work/ced.key";;
    ecdsa-brainpool-in-certificate-verify) echo "3 -s '$schemes' -c $work/cbp.pem -k $work/cbp.key";;
    mldsa-in-certificate-verify)
      [ "$cmldsa" = 1 ] && echo "3 -s '$schemes' -c $work/cmldsa.pem -k $work/cmldsa.key" || echo "3";;
    symetric-ciphers|non-support|version-negotiation) echo "4";;
    keyupdate-from-server) echo "5";;
    ecdhe-brainpool-curves|obsolete-curves) echo "6";;
    rsapss-signatures) echo "7";;
    minerva|ecdsa-support) echo "1";;
    eddsa) echo "2 -e 'ed448 only'";;
    no-unknown-groups) echo "0 -e 'unknown groups' --groups x25519,secp256r1,secp384r1,secp521r1,x448";;
    *) echo "0";;
  esac
}

pass=0; fail=0; skipped=0; gone=0
summary="$work/summary"
: > "$summary"
for script in "$fuzzer"/scripts/test-tls13-*.py; do
  name=$(basename "$script" .py)
  name=${name#test-tls13-}
  [ "$only" = "  " ] || [[ "$only" == *" $name "* ]] || continue
  read -r where extra <<< "$(route "$name")"
  if [[ " $dead " == *" $where "* ]]; then
    printf 'NOSRV %-40s server %s did not start\n' "$name" "$where" | tee -a "$summary"
    gone=$((gone + 1))
    continue
  fi
  eval "set -- $extra"
  log="$work/$name.log"
  (cd "$fuzzer" && PYTHONPATH=. timeout "${SCRIPT_TIMEOUT:-300}" "$python" "scripts/test-tls13-$name.py" \
    -h localhost -p $((base + where)) "$@" > "$log" 2>&1)
  rc=$?
  totals=$(grep -E '^(PASS|FAIL): ' "$log" | tr '\n' ' ')
  if [ $rc -eq 0 ]; then
    pass=$((pass + 1)); printf 'PASS %-40s %s\n' "$name" "$totals" | tee -a "$summary"
  elif [ $rc -eq 124 ]; then
    skipped=$((skipped + 1)); printf 'HANG %-40s %s\n' "$name" "$(tail -1 "$log" | head -c 100)" | tee -a "$summary"
  else
    fail=$((fail + 1)); printf 'FAIL %-40s %s\n' "$name" "$totals" | tee -a "$summary"
    grep -E '^(AssertionError|[A-Za-z]*Error): ' "$log" | sort | uniq -c | sort -rn | head -3
  fi
done

echo
echo "$pass passed, $fail failed, $skipped did not answer, $gone unrouted"

# `scripts/tls_fuzz.expected` is what this library says about each script today: `pass`, `gap` for
# a conversation it answers wrongly, `hang` for one that does not end. A `pass` that fails is a
# regression and the run fails; a `gap` that passes is an improvement and only gets a line, because
# a table that has to be edited before a fix can land is a table that will be edited wrongly.
expected="$here/tls_fuzz.expected"
[ -f "$expected" ] || exit $([ $fail -eq 0 ] && echo 0 || echo 1)
status=0
while read -r name want; do
  case $name in ''|'#'*) continue;; esac
  got=$(grep -E "^(PASS|FAIL|HANG|NOSRV) $name " "$summary" | awk '{print $1}' | head -1)
  case "$got" in
    PASS) got=pass;;
    FAIL) got=gap;;
    HANG) got=hang;;
    NOSRV) got=nosrv;;
    *) continue;;  # a script this run did not ask for
  esac
  if [ "$want" = pass ] && [ "$got" != pass ]; then
    echo "regression: $name was passing, now $got"; status=1
  elif [ "$want" != pass ] && [ "$got" = pass ]; then
    echo "now passing: $name (the table says $want)"
  fi
done < "$expected"
exit $status
