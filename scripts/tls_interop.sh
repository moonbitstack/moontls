#!/usr/bin/env bash
# TLS 1.0 to 1.3 and DTLS 1.2 and 1.3 interop between moontls and OpenSSL, Go's crypto/tls and
# pion, in both directions.
#
#     moon build --target native
#     bash scripts/tls_interop.sh [--quick]
#
# Each case states what should happen — a handshake with a named suite, group or ALPN, or a clean
# refusal — and the run fails on any case that does something else. OpenSSL is required; the Go
# and pion sections are skipped when `go` is not on the path, and `--quick` skips the long suite
# table.
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(dirname "$here")
# The peer is the `integration/` module's, not the library's: a socket and an event loop are
# what a consumer brings, and the library brings neither. A workspace (`moon.work`) resolves
# `moonbitstack/moontls` to this checkout, so the peer exercises the source under test.
peer="$root/_build/native/debug/build/moonbitstack/moontls-interop/peer/peer.exe"
test -x "$peer" || { echo "build the peer first: moon build --target native"; exit 2; }
quick=0
[ "${1:-}" = "--quick" ] && quick=1
# `ONLY='a substring'` runs just the cases whose name carries it, which is what a case being
# repaired is read with. Unset, every case runs.
only=${ONLY:-}
work=$(mktemp -d)
# `KEEP=1` leaves the work directory and the logs behind, for a case that has to be read rather
# than re-run.
if [ -n "${KEEP:-}" ]; then
  trap 'kill $(jobs -p) 2>/dev/null; echo "work: $work"' EXIT
else
  trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$work"' EXIT
fi
cd "$work"

# ---------------------------------------------------------------- certificates
#
# A root, an intermediate, and a leaf for each key type, all for localhost. The intermediate is what
# makes a client's chain longer than one certificate, which is where a handshake that miscounts the
# chain breaks.
# The root carries keyUsage as well as basicConstraints: OpenSSL 3's verification does not insist,
# Python's `ssl` answers "CA cert does not include key usage extension" without it, and every CA
# that has ever been issued has it.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout root.key \
  -out root.pem -days 3650 -subj "/CN=interop root" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout mid.key -out mid.csr \
  -subj "/CN=interop intermediate" 2>/dev/null
openssl x509 -req -in mid.csr -CA root.pem -CAkey root.key -CAcreateserial -out mid.pem -days 3650 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n") 2>/dev/null
leaf() { # name keygen-args... ; a leaf for localhost issued by the intermediate
  local name=$1; shift
  openssl req -newkey "$@" -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=localhost" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA mid.pem -CAkey mid.key -CAcreateserial -out "$name.crt" \
    -days 3650 -extfile <(printf "subjectAltName=DNS:localhost,DNS:alt.test,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n") 2>/dev/null
  cat "$name.crt" mid.pem > "$name.pem"
}
issue() { # name ca extensions x509-args... ; an EC P-256 leaf issued by `ca` directly
  local name=$1 ca=$2 ext=$3; shift 3
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$name.key" -out "$name.csr" \
    -subj "/CN=localhost" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA "$ca.pem" -CAkey "$ca.key" -CAcreateserial -out "$name.crt" \
    -extfile <(printf "$ext") "$@" 2>/dev/null
  cat "$name.crt" > "$name.pem"
}
leaf ec256 ec -pkeyopt ec_paramgen_curve:P-256
leaf ec384 ec -pkeyopt ec_paramgen_curve:P-384
leaf rsa2048 rsa:2048
leaf ed25519 ed25519
# RSASSA-PSS: the key's own type names the scheme it signs under (RFC 8446 §4.2.3).
leaf pss rsa-pss -pkeyopt rsa_keygen_bits:2048
# DSA, for the DSS suites TLS 1.2 still has.
openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -out dsaparams.pem 2>/dev/null
# A 2048-bit group for the DHE_PSK server: left to itself, OpenSSL's choice for a PSK suite is
# below the floor this library's clients hold a server to.
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe2048 -out ffdhe2048.pem 2>/dev/null
leaf dsa dsa:dsaparams.pem
san='subjectAltName=DNS:localhost,DNS:alt.test,IP:127.0.0.1\n'
server_ext="${san}extendedKeyUsage=serverAuth\n"
client_ext="${san}extendedKeyUsage=clientAuth\n"
issue alt root "$server_ext" -days 3650
issue clientleaf root "$client_ext" -days 3650
# An ML-DSA leaf, when this OpenSSL can make one: the scheme follows the key, so nothing else
# about the case changes.
mldsa=0
if openssl req -newkey mldsa65 -nodes -keyout mldsa.key -out mldsa.csr -subj "/CN=localhost" >/dev/null 2>&1 &&
   openssl x509 -req -in mldsa.csr -CA mid.pem -CAkey mid.key -CAcreateserial -out mldsa.crt -days 3650 \
     -extfile <(printf "subjectAltName=DNS:localhost,DNS:alt.test,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n") >/dev/null 2>&1; then
  cat mldsa.crt mid.pem > mldsa.pem
  mldsa=1
fi
# One certificate in both roles — the server's and the trust anchor the client is given. `openssl
# req -x509` makes one by default, and OpenSSL and Go both accept it as a leaf because it is also
# the anchor. What this library does with it is the pair of cases under "TLS 1.3".
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout alone.key -out alone.pem \
  -days 3650 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
head -c 1048576 /dev/urandom > big.bin

# ------------------------------------------------------------------- harness
pass=0; fail=0; gap=0
# GAP is a case that names a defect this run found rather than a case that passed. It does not fail
# the run: it is what `README.md` under "Conformance" lists, one line each.
# The same client against the same server, with the answer measured in octets: `bytes=` in the
# line the peer prints, against a floor. A reversed echo answers in whatever the server's buffer
# held, so the floor is what proves the transfer ran.
transfer_case() { # name floor key server-args... -- client-args...
  local name=$1 floor=$2 key=$3; shift 3
  skipped "$name" && return
  local sargs=() cargs=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do sargs+=("$1"); shift; done
  shift
  cargs=("$@")
  port=$((port + 1))
  openssl s_server -accept $port "${sargs[@]}" > "t.$port.log" 2>&1 &
  local pid=$!
  if ! wait_port $port; then
    report FAIL "$name" "s_server did not start"
    kill $pid 2>/dev/null; return
  fi
  local out bytes
  out=$(timeout 60 "$peer" client 127.0.0.1 $port root.pem sni=localhost "${cargs[@]}" 2>&1 | tail -1)
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  bytes=$(sed -n 's/.*bytes=\([0-9]*\).*/\1/p' <<< "$out")
  if [[ "$out" == ok* ]] && [ "${bytes:-0}" -ge "$floor" ]; then
    report PASS "$name" "$out"
  elif [[ "$name" == known:* ]]; then
    report GAP "$name" "${out:-nothing}"
  else
    report FAIL "$name" "want ok with at least $floor octets, got: ${out:-nothing}"
  fi
}

# Whether this run asked for the case: with `ONLY` unset, every case is asked for.
skipped() { # name
  [ -n "$only" ] && [[ "$1" != *"$only"* ]]
}

report() { # verdict name detail
  skipped "$2" && return
  case $1 in
    PASS) pass=$((pass + 1));;
    GAP) gap=$((gap + 1));;
    *) fail=$((fail + 1));;
  esac
  printf '%-4s %-46s %s\n' "$1" "$2" "$3"
  # One line is rarely the reason: the newest logs are this case's two ends.
  if [ "$1" = FAIL ]; then
    for f in $(ls -t ./*.log 2>/dev/null | head -2); do
      echo "     -- $f"
      tail -n 12 "$f" | sed 's/^/     /'
    done
  fi
}
port=${PORT_BASE:-24433}
wait_port() { for _ in $(seq 40); do timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

# moontls as the client, against `openssl s_server`. want is `ok` or `refused`; check, when given,
# must appear in the answer line.
#
# `expect_log`, when set, is a pattern the server's own log has to carry as well. A case whose point
# is a message neither end prints in its answer — a compressed Certificate, say — is evidence only
# if the end that sent it says so, and `s_server -msg` is where it says it.
client_case() { # name want check server-args... -- client-args...
  local name=$1 want=$2 check=$3; shift 3
  skipped "$name" && return
  local logwant=${expect_log:-}
  local sargs=() cargs=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do sargs+=("$1"); shift; done
  shift
  cargs=("$@")
  port=$((port + 1))
  openssl s_server -accept $port "${sargs[@]}" > "s.$port.log" 2>&1 &
  local pid=$!
  if ! wait_port $port; then
    report FAIL "$name" "s_server did not start: $(head -c 200 "s.$port.log")"
    kill $pid 2>/dev/null; return
  fi
  # Three attempts: the first connection to a freshly started server is the one place this harness
  # has ever been flaky, and a case that is genuinely broken fails all three.
  local out
  for _ in 1 2 3; do
    out=$(timeout 30 "$peer" client 127.0.0.1 $port root.pem sni=localhost "${cargs[@]}" 2>&1 | tail -1)
    local seen=${out%% *}
    if [ "$seen" = "$want" ] && { [ -z "$check" ] || [[ "$out" == *"$check"* ]]; }; then break; fi
    sleep 0.3
  done
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  local got=${out%% *}
  local ok=0
  local detail=$out
  if [ "$got" = "$want" ] && { [ -z "$check" ] || [[ "$out" == *"$check"* ]]; }; then ok=1; fi
  if [ "$ok" = 1 ] && [ -n "$logwant" ] && ! grep -q "$logwant" "s.$port.log"; then
    ok=0
    detail="answer $got, but the server's log never named $logwant"
  fi
  if [ "$ok" = 1 ]; then
    report PASS "$name" "$out"
  elif [[ "$name" == known:* ]]; then
    report GAP "$name" "${detail:-nothing (timeout?)}"
  else
    report FAIL "$name" "want $want${check:+ with $check}${logwant:+ and $logwant sent}, got: ${detail:-nothing (timeout?)}"
  fi
}

# moontls as the server, against `openssl s_client`. The server echoes each line, so `ping` coming
# back as `pong`... rather as itself is the proof that data flowed.
server_case() { # name want key server-args... -- s_client-args...
  local name=$1 want=$2 key=$3; shift 3
  skipped "$name" && return
  local sargs=() cargs=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do sargs+=("$1"); shift; done
  shift
  cargs=("$@")
  port=$((port + 1))
  "$peer" server $port "$key.pem" "$key.key" "${sargs[@]}" > "p.$port.log" 2>&1 &
  local pid=$!
  if ! wait_port $port; then
    report FAIL "$name" "peer did not start: $(head -c 200 "p.$port.log")"
    kill $pid 2>/dev/null; return
  fi
  local out
  # The lines go in on a timer because `s_client` writes its stdin as soon as the handshake is up:
  # a certificate that takes longer to sign than the first line takes to reach it leaves the echo
  # with nothing to answer, which reads as a failure of the library.
  out=$( (sleep 0.5; printf 'ping\n'; sleep 1; printf 'pong\n'; sleep 1) |
    timeout 30 openssl s_client -connect 127.0.0.1:$port -CAfile root.pem -verify_return_error \
      $([[ " ${cargs[*]} " == *" -noservername "* ]] || echo -servername localhost) "${cargs[@]}" 2>&1)
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  if [[ "$out" =~ $want ]]; then
    report PASS "$name" "$(grep -m1 -oE 'Ciphersuite: [A-Z0-9_-]+|Negotiated TLS1.3 group: [A-Za-z0-9-]+|New, TLSv1[^,]*, Cipher is [A-Z0-9_-]+' <<< "$out" | tr '\n' ' ')"
  elif [[ "$name" == known:* ]]; then
    report GAP "$name" "$(grep -m2 -iE 'error|alert' <<< "$out" | tr '\n' ' ' | head -c 200)"
  else
    report FAIL "$name" "$(grep -m3 -iE 'error|alert|Verify return code' <<< "$out" | tr '\n' ' ' | head -c 260) | peer: $(tail -2 "p.$port.log" | tr '\n' ' ')"
  fi
}

# A server that asks for a second handshake, driven by `s_client -state`. `RENEGOTIATING` is what
# `s_client` prints for the `R` command a reader types; a server that asks prints nothing of its
# own, so the evidence is the state trace — a HelloRequest read, and two complete handshakes — plus
# a line that still comes back afterwards, which says the connection survived the change of keys.
renegotiate_case() { # name key
  local name=$1 key=$2
  skipped "$name" && return
  port=$((port + 1))
  "$peer" server $port "$key.pem" "$key.key" versions=12,13 suites12=all renegotiate \
    > "r.$port.log" 2>&1 &
  local pid=$!
  if ! wait_port $port; then
    report FAIL "$name" "peer did not start: $(head -c 200 "r.$port.log")"
    kill $pid 2>/dev/null; return
  fi
  local out
  out=$( (sleep 0.5; printf 'ping\n'; sleep 2; printf 'again\n'; sleep 2) |
    timeout 30 openssl s_client -connect 127.0.0.1:$port -CAfile root.pem -verify_return_error \
      -servername localhost -tls1_2 -state 2>&1)
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  local requests finished
  requests=$(grep -c 'TLS read hello request' <<< "$out")
  finished=$(grep -c 'TLS read finished' <<< "$out")
  if [ "$requests" -ge 1 ] && [ "$finished" -ge 2 ] && grep -qx 'again' <<< "$out"; then
    report PASS "$name" "$requests HelloRequest, $finished handshakes, data after both"
  else
    report FAIL "$name" \
      "$requests HelloRequest, $finished handshakes, data: $(grep -c '^again$' <<< "$out") | $(grep -m2 -iE 'error|alert' <<< "$out" | tr '\n' ' ' | head -c 160)"
  fi
}

echo "== TLS 1.3: moontls as the client"
www=(-www)

for key in ec256 ec384 rsa2048 ed25519; do
  for suite in aes128 aes256 chacha20; do
    client_case "client: $key $suite" ok "suite=$suite" -cert "$key.crt" -key "$key.key" -cert_chain mid.pem -rev -- suites=$suite send=ping
  done
done
for group in X25519 P-256 P-384 P-521 X448; do
  client_case "client: server group $group" ok "version=1.3" -cert ec256.crt -key ec256.key -cert_chain mid.pem -groups $group -rev -- send=ping
done
# The two AES-CCM suites are not in OpenSSL's default list either, so both ends name them, and
# OpenSSL holds the 8-octet tag below its default security level.
for pair in TLS_AES_128_CCM_SHA256:aes128ccm TLS_AES_128_CCM_8_SHA256:aes128ccm8; do
  client_case "client: ec256 ${pair%%:*}" ok "suite=${pair##*:}" -cert ec256.crt -key ec256.key -cert_chain mid.pem -ciphersuites "${pair%%:*}" -cipher "DEFAULT:@SECLEVEL=0" -rev -- "suites=${pair##*:}" send=ping
done
client_case "client: RSASSA-PSS certificate" ok "version=1.3" -cert pss.crt -key pss.key -cert_chain mid.pem -rev -- send=ping
client_case "client: HRR to P-384" ok "group=24" -cert ec256.crt -key ec256.key -cert_chain mid.pem -groups P-384 -rev -- send=ping groups=x25519,p384
client_case "client: no common group" refused "handshake_failure" -cert ec256.crt -key ec256.key -cert_chain mid.pem -groups ffdhe2048 -rev -- send=ping
client_case "client: finite-field group when asked for" ok "version=1.3" -cert ec256.crt -key ec256.key -cert_chain mid.pem -groups ffdhe2048 -rev -- send=ping groups=ffdhe2048
client_case "client: ALPN agreed" ok "alpn=http/1.1" -cert ec256.crt -key ec256.key -cert_chain mid.pem -alpn h2,http/1.1 -rev -- send=ping alpn=foo,http/1.1
client_case "client: ALPN not agreed" refused "no_application_protocol" -cert ec256.crt -key ec256.key -cert_chain mid.pem -alpn h2 -rev -- send=ping alpn=foo
client_case "client: SNI picks the second chain" ok "version=1.3" -cert rsa2048.crt -key rsa2048.key -cert_chain mid.pem -servername alt.test -cert2 alt.crt -key2 alt.key -rev -- send=ping sni=alt.test
client_case "client: leaf issued by the root" ok "version=1.3" -cert alt.crt -key alt.key -rev -- send=ping
client_case "client: key update before the request" ok "version=1.3" -cert ec256.crt -key ec256.key -cert_chain mid.pem -rev -- send=ping update
transfer_case "client: a megabyte" 16000 ec256 -cert ec256.crt -key ec256.key -cert_chain mid.pem -rev -- big=1048576
transfer_case "client: records of 512 octets" 16000 ec256 -cert ec256.crt -key ec256.key -cert_chain mid.pem -rev -max_send_frag 512 -- big=1048576
client_case "client: bad host" refused "certificate does not name" -cert ec256.crt -key ec256.key -cert_chain mid.pem -rev -- send=ping sni=wrong.test

# The same handshake twice on one session store: the second one either resumed or did not, and the
# point of the case is that it did.
client_case "client: resumption" ok "resumed=1" -cert ec256.crt -key ec256.key -cert_chain mid.pem -num_tickets 2 -rev -- send=ping resume
# 0-RTT: the server has to accept the early data for `early=1`, and the ticket has to say the
# server will take it.
client_case "known: client 0-RTT echoed" ok "early=1" -cert ec256.crt -key ec256.key -cert_chain mid.pem -num_tickets 2 -max_early_data 4096 -rev -- send=ping resume early
# A certificate asked for and answered: the server is the one that judges it.
client_case "client: client certificate sent" ok "version=1.3" -cert ec256.crt -key ec256.key -cert_chain mid.pem -verify 2 -CAfile root.pem -rev -- send=ping cert=clientleaf.pem key=clientleaf.key
client_case "client: client certificate required, none sent" refused "certificate_required" -cert ec256.crt -key ec256.key -cert_chain mid.pem -Verify 2 -CAfile root.pem -rev -- send=ping
# OCSP stapling: the client asks, the server answers from the file it was given.
if openssl ocsp -issuer mid.pem -cert ec256.crt -reqout req.der -no_nonce >/dev/null 2>&1 &&
   openssl ocsp -index <(printf '') -rsigner root.pem -rkey root.key -CA root.pem -reqin req.der \
     -respout ocsp.der >/dev/null 2>&1; then
  client_case "client: OCSP stapling" ok "version=1.3" -cert ec256.crt -key ec256.key -cert_chain mid.pem -status_file ocsp.der -rev -- send=ping ocsp
fi
transfer_case "client: record size limit" 16000 ec256 -cert ec256.crt -key ec256.key -cert_chain mid.pem -rev -- big=1048576 record_limit=512
if [ "$mldsa" = 1 ]; then
  client_case "client: ML-DSA certificate" ok "version=1.3" -cert mldsa.crt -key mldsa.key -cert_chain mid.pem -rev -- send=ping
fi

echo "== TLS 1.3: moontls as the server"
echoed='ping.*pong'
for key in ec256 ec384 rsa2048 ed25519; do
  for cs in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
    server_case "server: $key $cs" "$echoed" "$key" -- -ciphersuites $cs
  done
done
for pair in TLS_AES_128_CCM_SHA256:aes128ccm TLS_AES_128_CCM_8_SHA256:aes128ccm8; do
  server_case "server: ec256 ${pair%%:*}" "Cipher is ${pair%%:*}.*$echoed" ec256 "suites=${pair##*:}" -- -ciphersuites "${pair%%:*}" -cipher "DEFAULT:@SECLEVEL=0"
done
# OpenSSL before 3.5 prints both PSS kinds as RSA-PSS, 3.5 the scheme's own name.
server_case "server: RSASSA-PSS certificate" "Peer signature type: (RSA-PSS|rsa_pss_pss_sha256).*$echoed" pss --
# Two certificates: the client's signature algorithms leave the first out, so the second goes out.
server_case "server: the second certificate, for the client's signature algorithms" "Peer signature type: (RSA-PSS|rsa_pss_rsae_sha256).*$echoed" ec256 alternatives=rsa2048.pem:rsa2048.key -- -sigalgs rsa_pss_rsae_sha256
server_case "server: OpenSSL's default groups (ML-KEM first)" "$echoed" ec256 --
for group in X25519 P-256 P-384 P-521 X448; do
  server_case "server: client group $group" "$echoed" ec256 -- -groups $group
done
server_case "server: client group brainpoolP256r1tls13" "$echoed" ec256 groups=brainpool256tls13 -- -groups brainpoolP256r1tls13
server_case "server: HRR from ffdhe2048 to P-256" "$echoed" ec256 -- -groups ffdhe2048:P-256
server_case "server: no common group" "alert|handshake failure|error" ec256 -- -groups ffdhe2048
server_case "server: finite-field group when asked for" "$echoed" ec256 groups=ffdhe2048 -- -groups ffdhe2048
server_case "server: ALPN" "ALPN protocol: http/1.1" ec256 alpn=h2,http/1.1 -- -alpn http/1.1
server_case "server: no SNI" "$echoed" ec256 -- -noservername
server_case "server: middlebox compatibility off" "$echoed" ec256 -- -no_middlebox
server_case "server: records padded to 512" "$echoed" ec256 -- -record_padding 512
server_case "server: a KeyUpdate from the client" "$echoed" ec256 -- -keymatexport label
server_case "server: certificate requested, none sent" "$echoed" ec256 ask=1 roots=root.pem --
server_case "server: certificate required, none sent" "alert|error" ec256 ask=2 roots=root.pem --
server_case "server: certificate required, one sent" "$echoed" ec256 ask=2 roots=root.pem -- -cert clientleaf.crt -key clientleaf.key
if [ "$mldsa" = 1 ]; then
  server_case "server: ML-DSA certificate and signature" "$echoed" mldsa -- -sigalgs mldsa65
  server_case "server: ML-DSA certificate, ECDSA offered only" "alert|error" mldsa -- -sigalgs ecdsa_secp256r1_sha256
fi
server_case "server: 1.3 only, client offers 1.2 only" "alert protocol version|wrong version|unsupported protocol" ec256 versions=13 -- -tls1_2
# The same certificate on both ends: refused by the default policy, accepted by `lax=1`, which is
# what OpenSSL and Go do without being asked (see `@x509.Policy::new(anchor_leaf=true)`).
client_case "client: one certificate for both roles, strict" refused "acts outside its authority" -cert alone.pem -key alone.key -rev -- send=ping roots=alone.pem
client_case "client: one certificate for both roles, lax" ok "version=1.3" -cert alone.pem -key alone.key -rev -- send=ping roots=alone.pem lax=1

echo "== TLS 1.3: a pre-shared key, and a compressed certificate"
# RFC 8446 §4.2.11: an identity and a secret the two ends already hold, and nothing else
# authenticates the handshake. `-nocert` on the OpenSSL side is what makes that visible — there is
# no chain to fall back on — and `resumed=1` on the peer's line is the proof that the secret is what
# keyed the connection.
pskhex=1a2b3c4d5e6f
pskid=interop
client_case "client: external PSK" ok "resumed=1" -tls1_3 -nocert -psk "$pskhex" -psk_identity "$pskid" -rev -- send=ping "psk=$pskhex:$pskid"
# The binder is a MAC over the hello under a key the server does not hold, so a key the two ends do
# not share cannot be used, and OpenSSL says so before it sends anything.
client_case "client: external PSK, a key the server does not hold" refused "decrypt_error" -tls1_3 -nocert -psk 0f0e0d0c -psk_identity "$pskid" -rev -- send=ping "psk=$pskhex:$pskid"
# The other direction: OpenSSL is the end that presents the identity. `Reused` in its report is it
# saying the PSK is what authenticated the server, which is the whole point of the mode.
server_case "server: external PSK" "Reused, TLSv1.3.*ping" ec256 "psk=$pskhex:$pskid" -- -tls1_3 -psk "$pskhex" -psk_identity "$pskid"

# RFC 8879: the two ends name an algorithm and the Certificate travels compressed. Neither end's
# answer line has a word for the message, so each case reads the log of the end that sent it.
expect_log='CompressedCertificate'
client_case "client: certificate compression" ok "version=1.3" -cert ec256.crt -key ec256.key -cert_chain mid.pem -cert_comp -msg -rev -- send=ping compress
expect_log=
server_case "server: certificate compression" "CompressedCertificate.*ping" ec256 compress=1 -- -msg

# 0-RTT as the server. `s_client` has to be told to keep the session it is given and then to send
# the early data, so the case is two connections to one server: the first collects the ticket, the
# second resumes with `-early_data` and the server's own EncryptedExtensions say whether it took
# it. `-no_anti_replay` because a single run has nothing to replay.
server_early_case() { # name key
  local name=$1 key=$2
  skipped "$name" && return
  port=$((port + 1))
  printf 'early\n' > early.txt
  "$peer" server $port "$key.pem" "$key.key" tickets=2 early=4096 > "e.$port.log" 2>&1 &
  local pid=$!
  if ! wait_port $port; then
    report FAIL "$name" "peer did not start: $(head -c 200 "e.$port.log")"
    kill $pid 2>/dev/null; return
  fi
  printf 'ping\n' | timeout 20 openssl s_client -connect 127.0.0.1:$port -CAfile root.pem \
    -servername localhost -sess_out early-session.pem -quiet > /dev/null 2>&1
  local out
  out=$(printf 'ping\n' | timeout 20 openssl s_client -connect 127.0.0.1:$port -CAfile root.pem \
    -servername localhost -sess_in early-session.pem -early_data early.txt 2>&1)
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  if grep -q "Early data was accepted" <<< "$out" && grep -q "Reused" <<< "$out"; then
    report PASS "$name" "$(grep -m2 -oE 'Reused, TLSv1[^,]*, Cipher is [A-Z0-9_-]+|Early data was accepted' <<< "$out" | tr '\n' ' ')"
  else
    report FAIL "$name" "$(grep -m2 -iE 'early data|Reused|error' <<< "$out" | tr '\n' ' ' | head -c 200)"
  fi
}
server_early_case "server: 0-RTT accepted" ec256

echo "== TLS 1.2"
tls12_name() { case $1 in c02b) echo ECDHE-ECDSA-AES128-GCM-SHA256;; c02c) echo ECDHE-ECDSA-AES256-GCM-SHA384;; cca9) echo ECDHE-ECDSA-CHACHA20-POLY1305;; c02f) echo ECDHE-RSA-AES128-GCM-SHA256;; esac; }
for code in c02b c02c cca9; do
  client_case "client 1.2: ec256 $code" ok "suite=$code" -cert ec256.crt -key ec256.key -cert_chain mid.pem -tls1_2 -cipher "$(tls12_name $code):@SECLEVEL=0" -rev -- suites12=$code send=ping
done
client_case "client 1.2: rsa2048 c02f" ok "suite=c02f" -cert rsa2048.crt -key rsa2048.key -cert_chain mid.pem -tls1_2 -rev -- suites12=c02f send=ping
client_case "client 1.2: RSASSA-PSS certificate" ok "suite=c02f" -cert pss.crt -key pss.key -cert_chain mid.pem -tls1_2 -rev -- suites12=c02f send=ping
transfer_case "client 1.2: a megabyte" 16000 ec256 -cert ec256.crt -key ec256.key -cert_chain mid.pem -tls1_2 -rev -- big=1048576
client_case "client 1.2: ALPN agreed" ok "alpn=http/1.1" -cert ec256.crt -key ec256.key -cert_chain mid.pem -tls1_2 -alpn h2,http/1.1 -rev -- send=ping alpn=foo,http/1.1
client_case "client 1.2: bad host" refused "certificate does not name" -cert ec256.crt -key ec256.key -cert_chain mid.pem -tls1_2 -rev -- send=ping sni=wrong.test
client_case "client 1.2: certificate required, none sent" refused "handshake_failure" -cert ec256.crt -key ec256.key -cert_chain mid.pem -tls1_2 -Verify 2 -CAfile root.pem -rev -- send=ping
if [ "$quick" = 0 ]; then
  while read -r code name key; do
    [ -n "$code" ] || continue
    # DSA is in all_schemes12, not the default list, so a DSS suite asks for it on our end.
    more=(); [ "$key" = dsa ] && more=(schemes12)
    client_case "client 1.2: $name" ok "suite=$code" -cert "$key.crt" -key "$key.key" -cert_chain mid.pem -tls1_2 -cipher "$name:@SECLEVEL=0" -rev -- suites12=$code send=ping "${more[@]}"
    server_case "server 1.2: $name" "Cipher is $name.*$echoed" "$key" suites12=$code "${more[@]}" -- -tls1_2 -cipher "$name:@SECLEVEL=0"
  done <<'TABLE'
cca9 ECDHE-ECDSA-CHACHA20-POLY1305 ec256
c02b ECDHE-ECDSA-AES128-GCM-SHA256 ec256
c02c ECDHE-ECDSA-AES256-GCM-SHA384 ec256
c0ac ECDHE-ECDSA-AES128-CCM ec256
c023 ECDHE-ECDSA-AES128-SHA256 ec256
c009 ECDHE-ECDSA-AES128-SHA ec256
cca8 ECDHE-RSA-CHACHA20-POLY1305 rsa2048
c02f ECDHE-RSA-AES128-GCM-SHA256 rsa2048
c030 ECDHE-RSA-AES256-GCM-SHA384 rsa2048
c09e DHE-RSA-AES128-CCM rsa2048
c027 ECDHE-RSA-AES128-SHA256 rsa2048
9e DHE-RSA-AES128-GCM-SHA256 rsa2048
67 DHE-RSA-AES128-SHA256 rsa2048
9c AES128-GCM-SHA256 rsa2048
3c AES128-SHA256 rsa2048
2f AES128-SHA rsa2048
c072 ECDHE-ECDSA-CAMELLIA128-SHA256 ec256
c077 ECDHE-RSA-CAMELLIA256-SHA384 rsa2048
45 DHE-RSA-CAMELLIA128-SHA rsa2048
c4 DHE-RSA-CAMELLIA256-SHA256 rsa2048
ba CAMELLIA128-SHA256 rsa2048
84 CAMELLIA256-SHA rsa2048
c05c ECDHE-ECDSA-ARIA128-GCM-SHA256 ec256
c061 ECDHE-ARIA256-GCM-SHA384 rsa2048
c052 DHE-RSA-ARIA128-GCM-SHA256 rsa2048
c051 ARIA256-GCM-SHA384 rsa2048
a2 DHE-DSS-AES128-GCM-SHA256 dsa
40 DHE-DSS-AES128-SHA256 dsa
c056 DHE-DSS-ARIA128-GCM-SHA256 dsa
44 DHE-DSS-CAMELLIA128-SHA dsa
TABLE
fi
server_case "server 1.2: ECDHE-ECDSA-AES128-GCM" "$echoed" ec256 -- -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256
server_case "server 1.2: ECDHE-RSA-AES256-GCM" "$echoed" rsa2048 -- -tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384
server_case "server 1.2: extended master secret" "Extended master secret: yes" ec256 -- -tls1_2
server_case "server 1.2: RSASSA-PSS certificate" "Peer signature type: (RSA-PSS|rsa_pss_pss_sha256).*$echoed" pss -- -tls1_2
# The suite the client names needs an RSA key, which is the second certificate's.
server_case "server 1.2: the second certificate, for the client's suite" "Cipher is ECDHE-RSA-AES128-GCM-SHA256.*$echoed" ec256 alternatives=rsa2048.pem:rsa2048.key -- -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256
# RFC 5746 §4: the server sends HelloRequest and the client answers with a ClientHello naming the
# previous handshake's client verify_data. `Conn::renegotiate` is the server's alone: a client cannot
# start one, and no case asks it to.
renegotiate_case "server 1.2: the server asks to renegotiate" ec256

# RFC 4279 and RFC 5489: the pre-shared key suites, the same key and identity as the TLS 1.3
# cases above. Plain, DHE and ECDHE PSK show no certificate, so OpenSSL's server runs `-nocert`;
# RSA_PSK has the server's RSA certificate besides the key.
while read -r code name key; do
  [ -n "$code" ] || continue
  if [ "$key" = none ]; then cert=(-nocert); peerkey=ec256; else cert=(-cert "$key.crt" -key "$key.key" -cert_chain mid.pem); peerkey=$key; fi
  client_case "client 1.2: $name" ok "suite=$code" "${cert[@]}" -dhparam ffdhe2048.pem -tls1_2 -cipher "$name:@SECLEVEL=0" -psk "$pskhex" -psk_identity "$pskid" -rev -- suites12=$code send=ping "psk=$pskhex:$pskid"
  server_case "server 1.2: $name" "Cipher is $name.*$echoed" "$peerkey" suites12=$code "psk=$pskhex:$pskid" -- -tls1_2 -cipher "$name:@SECLEVEL=0" -psk "$pskhex" -psk_identity "$pskid"
done <<'PSK'
a8 PSK-AES128-GCM-SHA256 none
ccab PSK-CHACHA20-POLY1305 none
aa DHE-PSK-AES128-GCM-SHA256 none
c037 ECDHE-PSK-AES128-CBC-SHA256 none
ac RSA-PSK-AES128-GCM-SHA256 rsa2048
PSK

# RFC 5054: SRP. OpenSSL keeps its users in a verifier file `openssl srp` writes, in the
# 2048-bit group this library's clients take by default.
srp_ok=0
if : > srp.v && openssl srp -srpvfile srp.v -add -gn 2048 -passout pass:password123 alice >/dev/null 2>&1; then
  srp_ok=1
fi
if [ "$srp_ok" = 1 ]; then
  # OpenSSL's s_server segfaults in SRP mode (3.0 and 3.5, against its own s_client too), so these
  # stay known until another SRP server is in the matrix; srp12_test drives this client against
  # this library's server, which OpenSSL's client does accept below.
  client_case "known: client 1.2: SRP-AES-128-CBC-SHA" ok "suite=c01d" -nocert -srpvfile srp.v -tls1_2 -cipher "SRP-AES-128-CBC-SHA:@SECLEVEL=0" -rev -- suites12=c01d send=ping srp=alice:password123
  client_case "known: client 1.2: SRP-RSA-AES-128-CBC-SHA" ok "suite=c01e" -cert rsa2048.crt -key rsa2048.key -cert_chain mid.pem -srpvfile srp.v -tls1_2 -cipher "SRP-RSA-AES-128-CBC-SHA:@SECLEVEL=0" -rev -- suites12=c01e send=ping srp=alice:password123
  client_case "known: client 1.2: SRP-DSS-AES-128-CBC-SHA" ok "suite=c01f" -cert dsa.crt -key dsa.key -cert_chain mid.pem -srpvfile srp.v -tls1_2 -cipher "SRP-DSS-AES-128-CBC-SHA:@SECLEVEL=0" -rev -- suites12=c01f send=ping srp=alice:password123 schemes12
fi
# OpenSSL 3's s_client derives a premaster neither tlslite-ng nor this library agrees with, so
# these are known too; the tlslite-ng section near the end is where SRP is checked both ways.
server_case "known: server 1.2: SRP-AES-128-CBC-SHA" "Cipher is SRP-AES-128-CBC-SHA.*$echoed" ec256 suites12=c01d srp=alice:password123 -- -tls1_2 -cipher "SRP-AES-128-CBC-SHA:@SECLEVEL=0" -srpuser alice -srppass pass:password123
server_case "known: server 1.2: SRP-RSA-AES-128-CBC-SHA" "Cipher is SRP-RSA-AES-128-CBC-SHA.*$echoed" rsa2048 suites12=c01e srp=alice:password123 -- -tls1_2 -cipher "SRP-RSA-AES-128-CBC-SHA:@SECLEVEL=0" -srpuser alice -srppass pass:password123
server_case "known: server 1.2: SRP-DSS-AES-128-CBC-SHA" "Cipher is SRP-DSS-AES-128-CBC-SHA.*$echoed" dsa suites12=c01f srp=alice:password123 schemes12 -- -tls1_2 -cipher "SRP-DSS-AES-128-CBC-SHA:@SECLEVEL=0" -srpuser alice -srppass pass:password123

echo "== TLS 1.0 and 1.1"
client_case "client 1.0" ok "version=1.0" -cert rsa2048.crt -key rsa2048.key -cert_chain mid.pem -tls1 -cipher 'DEFAULT:@SECLEVEL=0' -rev -- versions=10 suites12=2f send=ping 2>/dev/null
client_case "client 1.1" ok "version=1.1" -cert rsa2048.crt -key rsa2048.key -cert_chain mid.pem -tls1_1 -cipher 'DEFAULT:@SECLEVEL=0' -rev -- versions=11 suites12=2f send=ping 2>/dev/null
server_case "server 1.0" "Protocol *: *TLSv1\b|Cipher is" rsa2048 versions=10,12 suites12=2f -- -tls1 -cipher 'DEFAULT:@SECLEVEL=0'

echo "== DTLS 1.2"
# OpenSSL's `s_server` refuses every mode that would carry data over DTLS — `-rev` and `-www` both
# answer "Can't use ... with DTLS" — so a case against it can only ever be about the handshake,
# and these are not: this library's DTLS 1.2 server never sends its own flight after the client's
# key exchange, so `s_client` retransmits until the case gives up. pion is the only external peer
# that can hold a DTLS 1.2 conversation, and it is exercised under "pion" below.
dtls_server_case() { # name want key server-args... -- s_client-args...
  local name=$1 want=$2 key=$3; shift 3
  skipped "$name" && return
  local sargs=() cargs=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do sargs+=("$1"); shift; done
  shift
  cargs=("$@")
  port=$((port + 1))
  "$peer" dtls-server $port "$key.pem" "$key.key" dtls12 "${sargs[@]}" > "q.$port.log" 2>&1 &
  local pid=$!
  sleep 1
  local out
  out=$( (printf 'ping\n'; sleep 0.5; printf 'pong\n'; sleep 0.5) |
    timeout 30 openssl s_client -dtls1_2 -connect 127.0.0.1:$port -CAfile root.pem "${cargs[@]}" 2>&1)
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  if [[ "$out" =~ $want ]]; then
    report PASS "$name" "$(grep -m1 -oE 'Cipher is [A-Z0-9_-]+' <<< "$out")"
  elif [[ "$name" == known:* ]]; then
    report GAP "$name" "$(grep -m1 -oE 'Cipher is [A-Z0-9_-]+' <<< "$out") handshake only, no data"
  else
    report FAIL "$name" "$(grep -m3 -iE 'error|alert' <<< "$out" | tr '\n' ' ' | head -c 200) | peer: $(tail -2 "q.$port.log" | tr '\n' ' ')"
  fi
}
dtls_server_case "dtls 1.2 server: echo" "pong" ec256 --
dtls_server_case "dtls 1.2 server: cookie" "pong" ec256 cookie --

# ---------------------------------------------------------------- BoringSSL
#
# BoringSSL's `bssl` tool, built from source — `cmake -GNinja -B build && ninja -C build bssl` — and
# pointed at by `BSSL`. It is the second implementation of TLS 1.3 with a different idea of what
# the specification means, and its ClientHello leads with the post-quantum hybrid by default, which
# is the case a server written against OpenSSL alone never meets.
if [ -n "${BSSL:-}" ] && [ -x "${BSSL:-/nonexistent}" ]; then
  echo "== BoringSSL"
  bssl_client_case() { # name want check server-args... -- client-args...
    local name=$1 want=$2 check=$3; shift 3
    local sargs=() cargs=()
    while [ $# -gt 0 ] && [ "$1" != -- ]; do sargs+=("$1"); shift; done
    shift
    cargs=("$@")
    port=$((port + 1))
    "$BSSL" s_server -accept $port "${sargs[@]}" > "bs.$port.log" 2>&1 &
    local pid=$!
    # No port probe: `s_server` serves one connection unless told to loop, and a probe would spend
    # it. The process being alive a moment later is what a start is.
    sleep 1
    if ! kill -0 $pid 2>/dev/null; then
      report FAIL "$name" "bssl s_server did not start: $(head -c 150 "bs.$port.log" | tr '\n' ' ')"
      return
    fi
    local out
    out=$(timeout 30 "$peer" client 127.0.0.1 $port root.pem sni=localhost "${cargs[@]}" 2>&1 | tail -1)
    kill $pid 2>/dev/null; wait $pid 2>/dev/null
    local got=${out%% *}
    if [ "$got" = "$want" ] && { [ -z "$check" ] || [[ "$out" == *"$check"* ]]; }; then
      report PASS "$name" "$out"
    elif [[ "$name" == known:* ]]; then
      report GAP "$name" "${out:-nothing}"
    else
      report FAIL "$name" "want $want${check:+ with $check}, got: ${out:-nothing}"
    fi
  }
  bssl_server_case() { # name pattern key server-args... -- s_client-args...
    local name=$1 want=$2 key=$3; shift 3
    local sargs=() cargs=()
    while [ $# -gt 0 ] && [ "$1" != -- ]; do sargs+=("$1"); shift; done
    shift
    cargs=("$@")
    port=$((port + 1))
    "$peer" server $port "$key.pem" "$key.key" "${sargs[@]}" > "bp.$port.log" 2>&1 &
    local pid=$!
    sleep 1
    local out
    out=$( (printf 'ping\n'; sleep 0.5) |
      timeout 30 "$BSSL" s_client -connect 127.0.0.1:$port -root-certs root.pem -server-name localhost "${cargs[@]}" 2>&1 )
    kill $pid 2>/dev/null; wait $pid 2>/dev/null
    if grep -qE "$want" <<< "$out"; then
      report PASS "$name" "$(grep -m1 -E 'Version: |Cipher: |ECDHE group: |ALPN protocol: ' <<< "$out" | tr '\n' ' ')"
    elif [[ "$name" == known:* ]]; then
      report GAP "$name" "$(grep -m2 -iE 'error|alert' <<< "$out" | tr '\n' ' ' | head -c 200)"
    else
      report FAIL "$name" "$(grep -m3 -iE 'error|alert|curl|Failed' <<< "$out" | tr '\n' ' ' | head -c 200) | peer: $(tail -2 "bp.$port.log" | tr '\n' ' ')"
    fi
  }
  # BoringSSL as the server.
  bssl_client_case "bssl server: default ClientHello" ok "version=1.3" -cert ec256.pem -key ec256.key -www -- get=/
  bssl_client_case "bssl server: P-256 only" ok "group=23" -cert ec256.pem -key ec256.key -curves P-256 -www -- get=/
  bssl_client_case "bssl server: X25519 only" ok "group=29" -cert ec256.pem -key ec256.key -curves X25519 -www -- get=/
  bssl_client_case "bssl server: TLS 1.2 only" ok "suite=c02b" -cert ec256.pem -key ec256.key -max-version tls1.2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -www -- suites12=c02b get=/
  bssl_client_case "bssl server: a client certificate" ok "version=1.3" -cert ec256.pem -key ec256.key -require-any-client-cert -www -- cert=clientleaf.pem key=clientleaf.key get=/
  bssl_client_case "bssl server: a client certificate required" refused "certificate_required" -cert ec256.pem -key ec256.key -require-any-client-cert -www -- get=/
  # BoringSSL as the client.
  bssl_server_case "moontls server: bssl client" "Version: TLSv1.3" ec256 --
  bssl_server_case "moontls server: bssl client, ML-KEM hybrid" "ECDHE group: X25519MLKEM768" ec256 --
  bssl_server_case "moontls server: bssl client, P-384" "ECDHE group: P-384" ec256 -- -curves P-384
  bssl_server_case "moontls server: bssl client, ALPN" "ALPN protocol: http/1.1" ec256 alpn=h2,http/1.1 -- -alpn-protos http/1.1
  bssl_server_case "moontls server: bssl client, TLS 1.2" "Cipher: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" ec256 suites12=c02b -- -min-version tls1.2 -max-version tls1.2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256
  bssl_server_case "moontls server: bssl client, certificate sent" "Version: TLSv1.3" ec256 ask=2 roots=root.pem -- -cert clientleaf.crt -key clientleaf.key
  # Triple DES: OpenSSL builds without its TLS suites, BoringSSL still speaks DES-CBC3-SHA. It is
  # also the case that pins the CBC framing at an 8-octet block, which IDEA's suite shares.
  bssl_client_case "bssl server: 3DES" ok "suite=a" -cert rsa2048.pem -key rsa2048.key -max-version tls1.2 -cipher DES-CBC3-SHA -www -- suites12=a get=/
  bssl_server_case "moontls server: bssl client, 3DES" "Cipher: TLS_RSA_WITH_3DES_EDE_CBC_SHA" rsa2048 suites12=a -- -min-version tls1.2 -max-version tls1.2 -cipher DES-CBC3-SHA
  # TLS 1.0 takes its first CBC IV from the key block, one block long: eight octets here, sixteen
  # for AES. Both ends of this library would agree on a wrong length, so only a peer can tell.
  bssl_client_case "bssl server: 3DES in TLS 1.0" ok "suite=a" -cert rsa2048.pem -key rsa2048.key -min-version tls1 -max-version tls1 -cipher DES-CBC3-SHA -www -- suites12=a versions=10 get=/
  bssl_server_case "moontls server: bssl client, 3DES in TLS 1.0" "Cipher: TLS_RSA_WITH_3DES_EDE_CBC_SHA" rsa2048 suites12=a versions=10 -- -min-version tls1 -max-version tls1 -cipher DES-CBC3-SHA
else
  echo "== BoringSSL: skipped, set BSSL to a built bssl"
fi

# ----------------------------------------------------------------- wolfSSL
#
# wolfSSL's example client and server, built from source and pointed at by `WOLFSSL` — the source
# tree rather than the binaries, because both programs look for `certs/dh2048.pem` by walking up
# from their working directory. The client is run from there and given absolute paths.
#
# Its ClientHello lists secp224r1, which RFC 8446 §A.3 says MUST NOT be offered, and this server
# refuses such a hello — that is what tlsfuzzer's `obsolete-curves` asks of it. The peer is
# therefore told to offer only the curves TLS 1.3 permits (`-H useSupCurve`), which keeps the case
# about this library rather than about a peer breaking a rule it agreed to.
if [ -n "${WOLFSSL:-}" ] && [ -x "${WOLFSSL:-/nonexistent}/examples/client/client" ]; then
  echo "== wolfSSL"
  # wolfSSL as the server: this library's client against it.
  wolfssl_server_case() { # name want key version client-args...
    local name=$1 want=$2 key=$3 version=$4; shift 4
    local sversion=(-v "$version")
    skipped "$name" && return
    port=$((port + 1))
    ( cd "$WOLFSSL" && sleep 25 | ./examples/server/server -p $port -c "$work/$key.pem" \
        -k "$work/$key.key" -d -e "${sversion[@]}" ) > "ws.$port.log" 2>&1 &
    local pid=$!
    # No port probe: wolfSSL's server answers one connection and exits, so a probe would spend it.
    sleep 1
    if ! kill -0 $pid 2>/dev/null; then
      report FAIL "$name" "wolfSSL server did not start: $(head -c 150 "ws.$port.log" | tr '\n' ' ')"
      return
    fi
    local out
    out=$(timeout 30 "$peer" client 127.0.0.1 $port root.pem sni=localhost "$@" 2>&1 | tail -1)
    kill $pid 2>/dev/null; wait $pid 2>/dev/null
    if [[ "$out" == "$want"* ]]; then
      report PASS "$name" "$out"
    elif [[ "$name" == known:* ]]; then
      report GAP "$name" "${out:-nothing}"
    else
      report FAIL "$name" "want $want, got: ${out:-nothing} | peer: $(tail -2 "ws.$port.log" | tr '\n' ' ' | head -c 160)"
    fi
  }
  # wolfSSL as the client: this library's server against it. The peer's own answer line is what is
  # judged, because the client's output does not say which version was settled.
  wolfssl_client_case() { # name want key server-args... -- client-args...
    local name=$1 want=$2 key=$3; shift 3
    skipped "$name" && return
    local sargs=() cargs=()
    while [ $# -gt 0 ] && [ "$1" != -- ]; do sargs+=("$1"); shift; done
    shift
    cargs=("$@")
    port=$((port + 1))
    "$peer" server $port "$key.pem" "$key.key" "${sargs[@]}" > "wc.$port.log" 2>&1 &
    local pid=$!
    if ! wait_port $port; then
      report FAIL "$name" "peer did not start: $(head -c 150 "wc.$port.log" | tr '\n' ' ')"
      kill $pid 2>/dev/null; return
    fi
    ( cd "$WOLFSSL" && printf 'ping\n' |
      timeout 30 ./examples/client/client -h 127.0.0.1 -p $port -A "$work/root.pem" \
        "${cargs[@]}" > "wcl.$port.log" 2>&1 )
    sleep 0.5
    kill $pid 2>/dev/null; wait $pid 2>/dev/null
    local out
    out=$(grep -m1 '^ok ' "wc.$port.log")
    if [[ "$out" == *"$want"* ]]; then
      report PASS "$name" "$out"
    elif [[ "$name" == known:* ]]; then
      report GAP "$name" "${out:-nothing} | $(tail -2 "wcl.$port.log" | tr '\n' ' ' | head -c 120)"
    else
      report FAIL "$name" "want $want, got: ${out:-nothing} | $(tail -2 "wcl.$port.log" | tr '\n' ' ' | head -c 160)"
    fi
  }
  wolfssl_server_case "wolfSSL server: TLS 1.3" ok ec256 4 -- send=ping
  wolfssl_server_case "wolfSSL server: TLS 1.2" ok ec256 3 -- versions=12 send=ping
  wolfssl_client_case "wolfSSL client: TLS 1.3" "version=1.3" ec256 -- -v 4 -H useSupCurve
  wolfssl_client_case "wolfSSL client: TLS 1.2" "version=1.2" ec256 -- -v 3
else
  echo "== wolfSSL: skipped, set WOLFSSL to a built source tree"
fi

# ------------------------------------------------------------------ rustls
#
# `integration/rustls-peer`, a program of its own written against rustls, pointed at by
# `RUSTLS_PEER`. rustls is the strictest of the five: no TLS 1.0 or 1.1, no CBC suite in 1.2, no
# renegotiation, and a ClientHello that offers the post-quantum hybrid first. What it accepts is
# therefore a statement about a modern peer rather than about this library's own two ends, which is
# the whole reason it is in the matrix.
if [ -n "${RUSTLS_PEER:-}" ] && [ -x "${RUSTLS_PEER:-/nonexistent}" ]; then
  echo "== rustls"
  # rustls as the server: this library's client against it.
  rustls_server_case() { # name want key server-args... -- client-args...
    local name=$1 want=$2 key=$3; shift 3
    skipped "$name" && return
    local sargs=() cargs=()
    while [ $# -gt 0 ] && [ "$1" != -- ]; do sargs+=("$1"); shift; done
    shift
    cargs=("$@")
    port=$((port + 1))
    "$RUSTLS_PEER" server $port "$key.pem" "$key.key" "${sargs[@]}" > "rs.$port.log" 2>&1 &
    local pid=$!
    if ! wait_port $port; then
      report FAIL "$name" "rustls-peer did not start: $(head -c 200 "rs.$port.log" | tr '\n' ' ')"
      kill $pid 2>/dev/null; return
    fi
    local out
    out=$(timeout 30 "$peer" client 127.0.0.1 $port root.pem sni=localhost "${cargs[@]}" 2>&1 | tail -1)
    kill $pid 2>/dev/null; wait $pid 2>/dev/null
    local got=${out%% *}
    if [ "$got" = "$want" ]; then
      report PASS "$name" "$out"
    elif [[ "$name" == known:* ]]; then
      report GAP "$name" "${out:-nothing}"
    else
      report FAIL "$name" "want $want, got: ${out:-nothing} | peer: $(tail -1 "rs.$port.log")"
    fi
  }
  # rustls as the client: this library's server against it.
  rustls_client_case() { # name want key server-args... -- client-args...
    local name=$1 want=$2 key=$3; shift 3
    skipped "$name" && return
    local sargs=() cargs=()
    while [ $# -gt 0 ] && [ "$1" != -- ]; do sargs+=("$1"); shift; done
    shift
    cargs=("$@")
    port=$((port + 1))
    "$peer" server $port "$key.pem" "$key.key" "${sargs[@]}" > "rc.$port.log" 2>&1 &
    local pid=$!
    if ! wait_port $port; then
      report FAIL "$name" "peer did not start: $(head -c 200 "rc.$port.log" | tr '\n' ' ')"
      kill $pid 2>/dev/null; return
    fi
    local out
    out=$(timeout 30 "$RUSTLS_PEER" client 127.0.0.1 $port root.pem sni=localhost "${cargs[@]}" 2>&1 | tail -1)
    kill $pid 2>/dev/null; wait $pid 2>/dev/null
    if [[ "$out" == *"$want"* ]]; then
      report PASS "$name" "$out"
    elif [[ "$name" == known:* ]]; then
      report GAP "$name" "${out:-nothing}"
    else
      report FAIL "$name" "want $want, got: ${out:-nothing} | peer: $(tail -1 "rc.$port.log")"
    fi
  }
  # The server is rustls. `versions=12` on this side is what makes the second case TLS 1.2: rustls
  # speaks both, and the ClientHello is what settles which.
  rustls_server_case "rustls server: TLS 1.3" ok ec256 -- send=ping
  rustls_server_case "rustls server: TLS 1.2" ok ec256 -- versions=12 send=ping
  rustls_server_case "rustls server: ALPN" ok ec256 alpn=http/1.1 -- send=ping alpn=h2,http/1.1
  rustls_server_case "rustls server: resumption" ok ec256 -- resume send=ping
  rustls_server_case "rustls server: a client certificate" ok ec256 clientca=root.pem -- \
    send=ping cert=clientleaf.pem key=clientleaf.key
  rustls_server_case "rustls server: a client certificate required, none sent" refused ec256 \
    clientca=root.pem -- send=ping
  # The server is this library. The ticket cases need a server that hands one out, which is
  # `tickets=2`; the client-certificate case needs one that asks, which is `ask=2`.
  rustls_client_case "rustls client: TLS 1.3" "version=1.3" ec256 --
  rustls_client_case "rustls client: TLS 1.2" "version=1.2" ec256 versions=12 --
  rustls_client_case "rustls client: ALPN" "alpn=http/1.1" ec256 alpn=h2,http/1.1 -- alpn=http/1.1
  rustls_client_case "rustls client: resumption" "resumed=1" ec256 tickets=2 -- resume
  rustls_client_case "rustls client: a client certificate" "version=1.3" ec256 ask=2 roots=root.pem -- \
    cert=clientleaf.pem key=clientleaf.key
else
  echo "== rustls: skipped, set RUSTLS_PEER to a built peer"
fi

# --------------------------------------------------------------- Go and pion
#
# A real Go client and server: `crypto/tls` for the stream, `github.com/pion/dtls/v3` for DTLS,
# which is the only one of the four that speaks DTLS 1.3.
if command -v go >/dev/null 2>&1; then
  echo "== Go crypto/tls"
  cat > go.mod <<'GO'
module interop

go 1.24

require github.com/pion/dtls/v4 v4.0.1
GO
  mkdir -p cmd
  cat > main.go <<'GO'
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/protocol"
)

func roots(path string) *x509.CertPool {
	pem, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return pool
}

func client(addr, ca string) {
	dial := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dial, "tcp", addr, &tls.Config{
		RootCAs:    roots(ca),
		ServerName: "localhost",
		MinVersion: tls.VersionTLS10,
	})
	if err != nil {
		fmt.Println("refused", err)
		return
	}
	defer conn.Close()
	state := conn.ConnectionState()
	fmt.Printf("ok version=%x suite=%04x alpn=%v resumed=%v\n",
		state.Version, state.CipherSuite, state.NegotiatedProtocol, state.DidResume)
	io.WriteString(conn, "ping\n")
}

func server(addr, cert, key string) {
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		panic(err)
	}
	listener, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{pair},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("listening", addr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			buf := make([]byte, 512)
			conn.SetDeadline(time.Now().Add(20 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			fmt.Printf("got %q\n", string(buf[:n]))
			conn.Write(buf[:n])
		}()
	}
}

// dtlsClient dials with pion, in the version it is told to speak, and says what it negotiated:
// the only external peer for DTLS 1.3, since OpenSSL has none.
func dtlsClient(addr, ca, version string) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Println("refused", err)
		return
	}
	opts := []dtls.ClientOption{dtls.WithRootCAs(roots(ca)), dtls.WithServerName("localhost")}
	if version == "13" {
		opts = append(opts, dtls.WithMinVersion(protocol.Version1_3))
	} else {
		opts = append(opts, dtls.WithMaxVersion(protocol.Version1_2))
	}
	conn, err := dtls.Dial("udp", raddr, opts...)
	if err != nil {
		fmt.Println("refused", err)
		return
	}
	defer conn.Close()
	// `Dial` returns before the handshake has run — the first read or write is what runs it — so the
	// state is asked for after the answer, not before.
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := conn.Write([]byte("ping\n")); err != nil {
		fmt.Println("refused", err)
		return
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("refused", err)
		return
	}
	state, _ := conn.ConnectionState()
	fmt.Printf("ok version=%04x suite=%04x echo=%q\n",
		uint16(state.NegotiatedVersion()), uint16(state.CipherSuiteID), string(buf[:n]))
}

// dtlsServer answers one line with the same line, over DTLS, in the version it is told to speak.
func dtlsServer(addr, cert, key, version string) {
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		panic(err)
	}
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		panic(err)
	}
	opts := []dtls.ServerOption{dtls.WithCertificates(pair)}
	if version == "13" {
		opts = append(opts, dtls.WithMinVersion(protocol.Version1_3))
	} else {
		opts = append(opts, dtls.WithMaxVersion(protocol.Version1_2))
	}
	listener, err := dtls.ListenAddr("udp", laddr, opts...)
	if err != nil {
		panic(err)
	}
	fmt.Println("listening", addr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			buf := make([]byte, 512)
			conn.SetReadDeadline(time.Now().Add(20 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			conn.Write(buf[:n])
		}()
	}
}

func main() {
	switch os.Args[1] {
	case "client":
		client(os.Args[2], os.Args[3])
	case "server":
		server(os.Args[2], os.Args[3], os.Args[4])
	case "dtls-client":
		dtlsClient(os.Args[2], os.Args[3], os.Args[4])
	case "dtls-server":
		dtlsServer(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	}
}
GO
  if go mod tidy > go.log 2>&1; then
    go build -o gotls . > go.build.log 2>&1
  fi
  if [ -x ./gotls ]; then
    # moontls as the client against a Go server. One server per case: the harness's own
    # port probe leaves a connection the Go program is still reading, and a second case on the
    # same listener then races it.
    go_client_case() { # name want client-args...
      local name=$1 want=$2; shift 2
      port=$((port + 1))
      ./gotls server 127.0.0.1:$port ec256.pem ec256.key > "gs.$port.log" 2>&1 &
      local pid=$!
      if wait_port $port; then
        local out=""
        for _ in 1 2 3; do
          out=$(timeout 30 "$peer" client 127.0.0.1 $port root.pem sni=localhost "$@" 2>&1 | tail -1)
          [[ "$out" == ok*"$want"* ]] && break
          sleep 0.3
        done
        [[ "$out" == ok*"$want"* ]] && report PASS "$name" "$out" ||
          report FAIL "$name" "$out"
      else
        report FAIL "$name" "did not start: $(head -c 200 "gs.$port.log")"
      fi
      kill $pid 2>/dev/null; wait $pid 2>/dev/null
    }
    go_client_case "go server: moontls client" "version=1.3" send=ping
    go_client_case "go server: ALPN agreed" "alpn=http/1.1" alpn=http/1.1 send=ping
    # A Go client against moontls as the server.
    port=$((port + 1))
    "$peer" server $port ec256.pem ec256.key alpn=h2,http/1.1 > p.$port.log 2>&1 &
    pid=$!
    if wait_port $port; then
      out=$(timeout 30 ./gotls client 127.0.0.1:$port root.pem 2>&1 | tail -1)
      [[ "$out" == ok*"version=304"* ]] && report PASS "moontls server: go client" "$out" ||
        report FAIL "moontls server: go client" "$out"
    else
      report FAIL "moontls server: go client" "peer did not start"
    fi
    kill $pid 2>/dev/null; wait $pid 2>/dev/null
    echo "== pion DTLS"
    # pion/dtls v4 speaks DTLS 1.3, which no OpenSSL release does: the only external peer the
    # datagram handshake has.
    pion_server_case() { # name version client-args...
      local name=$1 v=$2; shift 2
      port=$((port + 1))
      ./gotls dtls-server 127.0.0.1:$port ec256.pem ec256.key "$v" > "ps.$port.log" 2>&1 &
      local pid=$!
      sleep 1
      local out
      out=$(timeout 40 "$peer" dtls-client 127.0.0.1 $port root.pem sni=localhost "$@" 2>&1 | tail -1)
      kill $pid 2>/dev/null; wait $pid 2>/dev/null
      if [[ "$out" == ok* ]]; then
        report PASS "$name" "$out"
      elif [[ "$name" == known:* ]]; then
        report GAP "$name" "${out:-nothing}"
      else
        report FAIL "$name" "${out:-nothing} | pion: $(tail -2 "ps.$port.log" | tr '\n' ' ')"
      fi
    }
    pion_client_case() { # name version server-args...
      local name=$1 v=$2; shift 2
      port=$((port + 1))
      "$peer" dtls-server $port ec256.pem ec256.key "$@" > "pc.$port.log" 2>&1 &
      local pid=$!
      sleep 1
      local out
      out=$(timeout 40 ./gotls dtls-client 127.0.0.1:$port root.pem "$v" 2>&1 | tr '\n' ' ')
      kill $pid 2>/dev/null; wait $pid 2>/dev/null
      if [[ "$out" == ok*echo=* ]]; then
        report PASS "$name" "$out"
      elif [[ "$name" == known:* ]]; then
        report GAP "$name" "${out:-nothing}"
      else
        report FAIL "$name" "${out:-nothing} | peer: $(tail -2 "pc.$port.log" | tr '\n' ' ')"
      fi
    }
    pion_server_case "pion dtls 1.3 server: moontls client" 13 send=ping
    # DTLS 1.2 against pion: its server answers the second ClientHello — the one carrying the
    # HelloVerifyRequest's cookie — with illegal_parameter, and its client's key exchange goes
    # unanswered by this library's server. Both are the same hole the OpenSSL cases above show.
    pion_server_case "pion dtls 1.2 server: moontls client" 12 dtls12 send=ping
    pion_client_case "pion dtls 1.3 client: moontls server" 13
    pion_client_case "pion dtls 1.2 client: moontls server" 12 dtls12
  else
    report FAIL "go interop" "go build failed: $(head -c 200 go.log go.build.log 2>/dev/null | tr '\n' ' ')"
  fi
else
  echo "== Go and pion: skipped, no go on the path"
fi

# -------------------------------------------------------------------- Python
#
# The library's founding criterion names Python's `ssl` beside OpenSSL: same engine, different API,
# and a binding is where a protocol's sharp edges are usually sanded flat. A client and a server,
# one line each way.
python=${PYTHON:-}
if [ -z "$python" ]; then
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      python=$candidate
      break
    fi
  done
fi
if [ -n "$python" ]; then
  echo "== Python ssl"
  cat > py.py <<'PY'
import socket, ssl, sys


def serve(port, chain, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(chain, key)
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", int(port)))
    listener.listen(1)
    print("listening", flush=True)
    raw, _ = listener.accept()
    with ctx.wrap_socket(raw, server_side=True) as tls:
        data = tls.recv(512)
        tls.sendall(data)
        print("served", tls.version(), tls.cipher()[0], data, flush=True)


def dial(port, ca):
    ctx = ssl.create_default_context(cafile=ca)
    with socket.create_connection(("127.0.0.1", int(port)), timeout=20) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            tls.sendall(b"ping\n")
            got = tls.recv(512)
            print("ok version=%s suite=%s echo=%r" % (tls.version(), tls.cipher()[0], got), flush=True)


if sys.argv[1] == "server":
    serve(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    dial(sys.argv[2], sys.argv[3])
PY
  # A Python server, this library as the client.
  port=$((port + 1))
  "$python" py.py server $port ec256.pem ec256.key > "py.$port.log" 2>&1 &
  pid=$!
  # No port probe: this server accepts one connection, and a probe would be that connection.
  sleep 1
  if kill -0 $pid 2>/dev/null; then
    out=$(timeout 30 "$peer" client 127.0.0.1 $port root.pem sni=localhost send=ping 2>&1 | tail -1)
    [[ "$out" == ok*"version=1.3"* ]] && report PASS "python ssl server: moontls client" "$out" ||
      report FAIL "python ssl server: moontls client" "$out"
  else
    report FAIL "python ssl server: moontls client" "did not start: $(head -c 200 "py.$port.log")"
  fi
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  # This library as the server, a Python client.
  port=$((port + 1))
  "$peer" server $port ec256.pem ec256.key alpn=h2,http/1.1 > "pyq.$port.log" 2>&1 &
  pid=$!
  sleep 1
  out=$(timeout 30 "$python" py.py client $port root.pem 2>&1 | tail -1)
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  [[ "$out" == ok*"version=TLSv1.3"* ]] && report PASS "moontls server: python ssl client" "$out" ||
    report FAIL "moontls server: python ssl client" "$out"
else
  echo "== Python ssl: skipped, no python on the path"
fi

# RFC 5054 against an SRP implementation other than OpenSSL's, both ways (scripts/tlslite_srp.py).
tlslite_py=${TLSLITE_PY:-python3}
if "$tlslite_py" -c 'import tlslite' 2>/dev/null; then
  echo "== tlslite-ng: SRP"
  while read -r code kx key; do
    [ -n "$code" ] || continue
    if [ "$key" = none ]; then files=(); chain=ec256; else files=("$key.pem" "$key.key"); chain=$key; fi
    port=$((port + 1))
    "$tlslite_py" "$here/tlslite_srp.py" server $port $kx "${files[@]}" > "t.$port.log" 2>&1 &
    pid=$!
    wait_port $port
    out=$(timeout 30 "$peer" client 127.0.0.1 $port root.pem sni=localhost suites12=$code srp=alice:password123 send=ping 2>&1 | tail -1)
    sleep 0.5; kill $pid 2>/dev/null; wait $pid 2>/dev/null
    if [[ "$out" == ok*"suite=$code"* ]]; then report PASS "client 1.2: tlslite-ng SRP $code" "$out"
    else report FAIL "client 1.2: tlslite-ng SRP $code" "$out | tlslite: $(tail -1 "t.$port.log")"; fi
    port=$((port + 1))
    "$peer" server $port "$chain.pem" "$chain.key" suites12=$code srp=alice:password123 > "p.$port.log" 2>&1 &
    pid=$!
    wait_port $port
    out=$(timeout 30 "$tlslite_py" "$here/tlslite_srp.py" client $port $kx 2>&1 | tail -1)
    kill $pid 2>/dev/null; wait $pid 2>/dev/null
    if [[ "$out" == OK* ]]; then report PASS "server 1.2: tlslite-ng SRP $code" "$out"
    else report FAIL "server 1.2: tlslite-ng SRP $code" "$out | peer: $(tail -1 "p.$port.log")"; fi
  done <<'SRP'
c01d srp_sha none
c01e srp_sha_rsa rsa2048
SRP
else
  echo "== tlslite-ng: skipped, not importable"
fi

echo
echo "$pass passed, $fail failed, $gap known"
# A known gap is a result this run reports and CI accepts; a case that did something else is a
# failure, and the exit status says so — otherwise the job only checks that the script ran.
[ $fail -eq 0 ]
