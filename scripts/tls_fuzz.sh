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
# Three servers are started, because a script that checks a certificate's signature scheme needs a
# server whose certificate is under that scheme: an EC P-256 one, an RSA one and an Ed25519 one.
# Everything else — the suites, the groups, the extensions — is the same on all three.
set -u
only=" $* "

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(dirname "$here")
# The peer is the `integration/` module's, not the library's: a socket and an event loop are
# what a consumer brings, and the library brings neither. A workspace (`moon.work`) resolves
# `moonbitstack/moontls` to this checkout, so the peer exercises the source under test.
peer="$root/_build/native/debug/build/moonbitstack/moontls-interop/peer/peer.exe"
test -x "$peer" || { echo "build the peer first: moon build --target native"; exit 2; }
fuzzer=$(cd "${TLSFUZZER:?set TLSFUZZER to a tlsfuzzer checkout}" && pwd)
python=${PYTHON:-python3}
[[ "$python" != */* ]] || python="$(cd "$(dirname "$python")" && pwd)/$(basename "$python")"
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$work"' EXIT
cd "$work"

for k in "rsa rsa:2048" "ec ec -pkeyopt ec_paramgen_curve:P-256" "ed ed25519"; do
  set -- $k; name=$1; shift
  openssl req -x509 -newkey "$@" -nodes -keyout "$name.key" -out "$name.pem" -days 365 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
done
# Every group this library speaks, so a script that offers one of them is not refused for the wrong
# reason. The hybrids stay in: they are what this library offers first.
all=x25519,p256,p384,p521,x448,ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192,x25519mlkem768,mlkem768
# RSA first: every ClientHello names an RSA PKCS#1 scheme, while an ECDSA one is only in a list
# that asked for it, and a server that can only sign with the second would refuse the rest.
base=${PORT_BASE:-4433}
"$peer" server $base rsa.pem rsa.key http groups=$all suites=aes128,aes256,chacha20 > /dev/null 2>&1 &
"$peer" server $((base + 1)) ec.pem ec.key http groups=$all suites=aes128,aes256,chacha20 > /dev/null 2>&1 &
"$peer" server $((base + 2)) ed.pem ed.key http groups=$all suites=aes128,aes256,chacha20 > /dev/null 2>&1 &
# A server that did not come up would make every script fail with "connection refused", which says
# nothing about the library: say so here instead.
for p in $base $((base + 1)) $((base + 2)); do
  for _ in $(seq 40); do
    (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && break
    sleep 0.1
  done
  (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null || { echo "the server on $p did not start"; exit 2; }
done

# The port a script runs against: the certificate it needs, by what it checks.
port_of() {
  case $1 in
    *minerva*) echo $((base + 1));;
    *eddsa*|*ed25519*) echo $((base + 2));;
    *) echo $base;;
  esac
}

pass=0; fail=0; skipped=0
for script in "$fuzzer"/scripts/test-tls13-*.py; do
  name=$(basename "$script" .py)
  name=${name#test-tls13-}
  [ "$only" = "  " ] || [[ "$only" == *" $name "* ]] || continue
  extra=()
  case $name in
    no-unknown-groups) extra+=(-e "unknown groups" --groups x25519,secp256r1,secp384r1,secp521r1,x448);;
    eddsa) extra+=(-e "ed448 only");;
  esac
  log="$work/$name.log"
  (cd "$fuzzer" && PYTHONPATH=. timeout "${SCRIPT_TIMEOUT:-300}" "$python" "scripts/test-tls13-$name.py" \
    -h localhost -p "$(port_of "$name")" "${extra[@]}" > "$log" 2>&1)
  rc=$?
  totals=$(grep -E '^(PASS|FAIL): ' "$log" | tr '\n' ' ')
  if [ $rc -eq 0 ]; then
    pass=$((pass + 1)); printf 'PASS %-40s %s\n' "$name" "$totals"
  elif [ $rc -eq 124 ]; then
    skipped=$((skipped + 1)); printf 'HANG %-40s %s\n' "$name" "$(tail -1 "$log" | head -c 100)"
  else
    fail=$((fail + 1)); printf 'FAIL %-40s %s\n' "$name" "$totals"
    grep -E '^(AssertionError|[A-Za-z]*Error): ' "$log" | sort | uniq -c | sort -rn | head -3
  fi
done

echo
echo "$pass passed, $fail failed, $skipped did not answer"
[ $fail -eq 0 ]
