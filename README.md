<p align="right">
  <a href="https://moonbitstack.github.io/moontls/">home</a> &nbsp;·&nbsp;
  <a href="https://moonbitstack.github.io/moontls/guide.html">guide</a> &nbsp;·&nbsp;
  <a href="https://moonbitstack.github.io/moontls/demo.html">demo</a> &nbsp;·&nbsp;
  <a href="https://moonbitstack.github.io/moontls/api.html">api</a> &nbsp;·&nbsp;
  <a href="https://mooncakes.io/docs/moonbitstack/moontls">mooncakes</a>
</p>

# moontls

TLS for MoonBit — 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) and 1.2 ([RFC 5246](https://www.rfc-editor.org/rfc/rfc5246)), client and server, with 1.1 and 1.0 ([RFC 2246](https://www.rfc-editor.org/rfc/rfc2246)) on request — and DTLS 1.3 ([RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)) and DTLS 1.2 ([RFC 6347](https://www.rfc-editor.org/rfc/rfc6347)) over datagrams, client and server. Ciphertext in, ciphertext and plaintext out. No sockets, and not one line of cryptography of its own: the algorithms are [`mooncrypt`](https://github.com/moonbitstack/mooncrypt)'s and certificate validation is [`mooncred`](https://github.com/moonbitstack/mooncred)'s.

<!-- nocheck -->
```moonbit
// A client: put what the socket gives into `receive`, send what `take` gives.
let config = @tls.Client::new(@roots.mozilla(), alpn=["h2", "http/1.1"])
let conn = @tls.Conn::client(config, "example.com", rand~, now~)
socket.write(conn.take())                     // the ClientHello
while !conn.is_connected() {
  conn.receive(socket.read()[:])
  socket.write(conn.take())
}
conn.alpn()                                   // Some("h2")
conn.write(request[:])

// A server: the same three calls. The key is any PEM file `openssl` writes.
let chain = @x509.pems(cert_pem)                              // leaf first
let config = @tls.Server::new(chain, @x509.PrivateKey::pem(key_pem), alpn=["h2"])
let server = @tls.Conn::server(config, rand~)
```

The key schedule of [RFC 8446 §7.1](https://www.rfc-editor.org/rfc/rfc8446#section-7.1) is a ladder
of calls, each one taking the secret above it and saying what it is for:

```mbt check
test {
  let early = @keys.early()                       // no PSK: the zero secret
  let shared = b"\x8b\xd4\x05\x4f\xb5\x5b\x9d\x63\xfd\xfb\xac\xf9\xf0\x4b\x9f\x0d\x35\xe6\xd6\x3f\x53\x75\x63\xef\xd4\x62\x72\x90\x0f\x89\x49\x2d"
  let handshake = @keys.handshake(early[:], shared[:])   // salted by the key exchange
  let transcript = @keys.Transcript::new()
  transcript.add(b"\x01\x00\x00\x00"[:])              // a ClientHello, for the shape of it
  let secret = @keys.client_handshake(handshake[:], transcript.hash()[:])
  assert_eq(
    @base16.encode(secret[:]),
    "ab4fc9e2370723165814c074381ab62cbb2c32fd421b15db6910f5df5b1756a3",
  )
}
```

A record is the same idea one layer down: the traffic secret, a suite, and the record's own sequence
number, which the AEAD's nonce is built from.

```mbt check
test {
  let suite = @record.Aes128Gcm
  let secret = @base16.decode("ab4fc9e2370723165814c074381ab62cbb2c32fd421b15db6910f5df5b1756a3")
  let writer = @record.Cipher::new(secret[:], suite~)
  let record = writer.seal(@record.Handshake, b"hello"[:])
  assert_eq(@base16.encode(record[:]), "1703030016ea041db0127f9d1812962e71632919c00bfbe245872d")
  // The same secret on the other side opens it: the content type moved inside, and came back.
  let reader = @record.Cipher::new(secret[:], suite~)
  let (kind, content) = reader.open(record[:])
  assert_eq(kind, @record.Handshake)
  assert_eq(content, b"hello")
}
```

<!-- nocheck -->
```moonbit
// A DTLS 1.3 client: datagrams in and out, and a clock you supply.
let conn = @dtls.Conn13::client(config, "example.com", rand~, now~, wall~)
socket.send(conn.take())
while !conn.is_connected() {
  conn.receive(socket.recv()[:], now~=monotonic_ms())
  socket.send(conn.take())
  if conn.deadline() is Some(due) && monotonic_ms() >= due {
    conn.tick(now~=monotonic_ms())
  }
}
```

Run `moon run src/examples/tour` for the whole surface in one go.

## Packages

|  | Specification | State |
|:--:|:--|:--:|
| `wire` | [§3](https://www.rfc-editor.org/rfc/rfc8446#section-3) integer widths, the frozen `legacy_version`, `Reader`, the cursor every decoder reads through, and `Refused`, what a decoder raises when the octets are not the structure their own lengths describe | **0.3.0** |
| `alert` | [§6](https://www.rfc-editor.org/rfc/rfc8446#section-6) the alert protocol | **0.2.0** |
| `keys` | [§7.1](https://www.rfc-editor.org/rfc/rfc8446#section-7.1) key schedule, [§4.4.1](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.1) transcript hash, [§4.4.4](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.4) Finished | **0.1.0** |
| `record` | [§5](https://www.rfc-editor.org/rfc/rfc8446#section-5) record layer under any of the three suites, [§7.3](https://www.rfc-editor.org/rfc/rfc8446#section-7.3) traffic keys; TLS 1.2's suite table and record protection | **0.3.0** |
| `ext` | [§4.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.2) extensions: server_name, supported_versions, supported_groups, signature_algorithms, key_share, ALPN, cookie, use_srtp | **0.4.0** |
| `msg` | [§4](https://www.rfc-editor.org/rfc/rfc8446#section-4) the handshake messages: ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished | **0.4.0** |
| `hs` | [Appendix A](https://www.rfc-editor.org/rfc/rfc8446#appendix-A) the state machine, §4.1.1 negotiation, §4.1.4 HelloRetryRequest, and the driver | **0.5.0** |
| `dtls` | [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147) what datagrams change — both record shapes, record number encryption, the replay window, fragmentation and reassembly, the ACK message and the flight driver — and `Conn13` and `Conn12`, the two connections over it, with [RFC 6347](https://www.rfc-editor.org/rfc/rfc6347)'s DTLS 1.2 record layer beside 1.3's | **0.3.0** |
| `tls` | The connection: client and server, X25519MLKEM768, X25519, P-256, P-384, P-521 and X448, and SecP256r1MLKEM768, SecP384r1MLKEM1024, ML-KEM alone and the RFC 7919 groups on request, the three suites, ECDSA, RSA, RSASSA-PSS, Ed25519 and ML-DSA certificates and more than one per server, HelloRetryRequest, SNI, ALPN, KeyUpdate, close_notify, middlebox compatibility mode, declined 0-RTT data read past; pre-shared keys a caller supplies, in either PSK mode; certificate compression under zlib, brotli or zstd, either direction; TLS 1.2 beside 1.3 and the session resumption, client certificates, renegotiation and stapling that come with them; the server's chain judged by `mooncred` | **0.1.0** |
| `srtp` | [RFC 5764](https://www.rfc-editor.org/rfc/rfc5764) the SRTP protection profiles a DTLS handshake negotiates, and the keying material it exports for them | **0.1.0** |

`msg` is formats only. Which message may arrive next, and which parameters to pick, is the state machine's — that seam is what lets a tool read a ClientHello (an SNI router, a fingerprinter) without linking a handshake or a record layer.

`ext` says what is on the wire and nothing about what to pick from it: which group, which scheme, which version is the handshake's decision and lives in `hs`. `quic_transport_parameters` has a type code there and no codec — the payload is QUIC's ([RFC 9000 §18](https://www.rfc-editor.org/rfc/rfc9000#section-18)), and reading somebody else's structure would be this library claiming to know it.

`dtls` derives its keys under `dtls13`, not `tls13 ` ([§5.9](https://www.rfc-editor.org/rfc/rfc9147#section-5.9)). Up to 0.9.0 it used the TLS prefix, which round-trips against itself and interoperates with nobody; pion/dtls's vectors caught it, and `dtls/pion_wbtest.mbt` now holds them.

`dtls` is everything a datagram forces and nothing else: the handshake messages, the key schedule and the extensions are unchanged, because DTLS 1.3 runs the TLS 1.3 handshake verbatim. `Conn13` and `Conn12` are that handshake bound to a datagram record layer; `tls.Handshake` is the same handshake with the record layer taken out, and `tls.Layer` is the seam a third transport implements.

Neither connection reads a clock. Every call takes `now`, in milliseconds on the caller's own monotonic clock; `deadline` says when the next `tick` is due, and `tick` retransmits what is overdue. `wall` is the separate wall clock, in seconds, a certificate is judged at. DTLS 1.3 acknowledges records and retransmits the fragments no ACK named ([§7](https://www.rfc-editor.org/rfc/rfc9147#section-7)); DTLS 1.2 has no ACK and resends a whole flight, which its answer is what acknowledges ([RFC 6347 §4.2.4](https://www.rfc-editor.org/rfc/rfc6347#section-4.2.4)). A record that does not deprotect — a duplicate caught by the replay window, a forgery — is dropped and the association goes on.

DTLS 1.2 keeps its own record layer, not 1.3's: a 13-octet header with an explicit epoch and a 48-bit sequence number, a nonce built from that sequence number, and the frozen `0xfefd` version in the header and the associated data alike. `dtls.Cipher12` frames the record and hands the octets to `record.Cipher`, because an epoch and a sequence number are exactly the eight octets a TLS 1.2 record already covers — so every suite the table holds travels: AES-GCM, ChaCha20-Poly1305, AES-CCM with a 16- or 8-octet tag, and AES-CBC with the MAC before or after the encryption, its padding checked in constant time.

A DTLS server can refuse to keep state for a ClientHello until the address it came from has proved it can receive. Over DTLS 1.3 that is a `cookie` extension in a HelloRetryRequest ([RFC 9147 §5.1](https://www.rfc-editor.org/rfc/rfc9147#section-5.1)), and the retry asks for no key share: the client comes back with the shares it already sent, unchanged ([§4.1.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2)), which is what `@dtls.Cookie::Key` does. What the cookie carries is what makes the exchange worth anything — the retry's transcript is `message_hash(first ClientHello)` and then the retry itself, so the cookie carries the hash of that first hello and the group the retry asked for, and an instance that kept nothing can write the retry again octet for octet and seed the transcript. The handshake then completes even when the second ClientHello reaches a different server process, which is the point of a stateless cookie. A cookie this server did not give ends the handshake with `illegal_parameter` rather than earning a second retry.

A DTLS 1.2 server asks the same question the older way. Pass `cookie=@dtls.Key(key)` — or `@dtls.Key(b"")` for one drawn from the server's own randomness — and the first hello is answered with a HelloVerifyRequest, and the handshake starts only on the ClientHello that echoes the cookie back. The cookie is an HMAC of the address under that key and nothing else is kept, so a forged source buys one small packet and no flight; a cookie replayed from another address is answered with a request of its own. `receive` takes the peer's address, `peer=`, because that is what the cookie is an answer about.

The key exchange is post-quantum by default. `groups` puts X25519MLKEM768 first, as Chrome, Firefox, Go, OpenSSL 3.5 and rustls do, and `shares` sends a key share for the first two, so a server without the hybrid takes the X25519 share at once instead of asking again. The hybrid's share is 1,216 bytes against X25519's 32; a client that cannot afford it passes `shares=1` or its own `groups`. SecP256r1MLKEM768, SecP384r1MLKEM1024 and ML-KEM alone (`@ext.mlkem512` to `@ext.mlkem1024`) are there to be named. ML-KEM is `mooncrypt`'s, and `Conn::group` says which group ran. RFC 7027's three brainpool groups are a TLS 1.2 option (`@tls.brainpool`); TLS 1.3 names the same curves by RFC 8734's code points (`@ext.brainpool_p256_tls13` and the two after it), which a caller puts in `groups` like any other, and RFC 8734's three ECDSA schemes are offered so a brainpool certificate can prove its key to a TLS 1.3 peer. TLS 1.3 retired the groups of earlier versions (§4.2.7): a ClientHello offering 1.3 alone that lists one is refused with `illegal_parameter`, and one that also offers TLS 1.2 may have listed it for 1.2, so 1.3 passes over it.

`tls` speaks TLS 1.2 beside 1.3, both on by default through `versions`, and `Conn::version` says which was settled. TLS 1.1 and 1.0 are implemented and left out of that preset, as RFC 8996 asks: a caller that needs them names them, and the PRF over MD5 and SHA-1, the implicit CBC IV and the signature without a scheme come with them. TLS 1.2 has a table of its own in `record`, one row a suite: ECDHE, DHE and RSA key exchange under AES-GCM, AES-CCM, ChaCha20-Poly1305 and AES-CBC, 39 in all. `suites12`, the default, is the six with ECDHE and an AEAD; `@record.all12` is everything, and asking for it is a decision, because RSA key exchange has no forward secrecy and CBC has a history. Beside the suites come extended master secret (RFC 7627), encrypt-then-MAC (RFC 7366), secure renegotiation indication (RFC 5746), the downgrade sentinel and `TLS_FALLBACK_SCSV`; a request to renegotiate is declined with a warning and the connection goes on.

The old suites keep their countermeasures: a CBC record does the same work whatever is wrong with it, which is Lucky Thirteen's fix, and a wrapped premaster that fails to unwrap becomes a random secret and fails at Finished, which is Bleichenbacher's. A client refuses a DHE prime under `dh_bits`, 2048 by default. `schemes12` is the same bargain for signatures: SHA-2, PSS and Ed25519 by default, and `all_schemes12` adds SHA-1, which is what a TLS 1.2 client that sends no signature_algorithms is taken to mean. It governs TLS 1.2 only: 1.0 and 1.1 have no scheme to negotiate, and their hash comes with naming the version.

A PSK need not come from a ticket. `Psk` is an identity, a secret and the hash that binds it, and `Server::new` or `Client::new` takes a list of them: the handshake then authenticates with the secret instead of a certificate, and no chain travels either way. `psk_modes` says how the key may be used — `psk_dhe_ke`, where the key exchange still contributes to the secret, or `@ext.psk_ke`, where the secret keys the handshake on its own and forward secrecy is what it costs. The default is the first alone.

A session can be resumed instead of re-authenticated. In TLS 1.3 a server hands out `NewSessionTicket`s sealed under its ticket keys — the ticket carries its state, so the server keeps nothing — and a client offers one back as a pre_shared_key with a binder over the truncated ClientHello; with `Tickets::early` and a client that asks, 0-RTT data travels under the early traffic secret and is closed by EndOfEarlyData, and data a server declines is sent again as ordinary data. A ticket's age is compared across two clocks, and `Tickets::drift` says how far apart they may read, in milliseconds: 10 seconds by default, OpenSSL's allowance. A wider gap costs the early data and nothing else (RFC 8446 §8.3). Tickets hold their own state, so the server has no record of which have been used, and 0-RTT data can be replayed by whoever recorded it: that is RFC 8446 §8, and `early` is 0 until a server decides otherwise. In TLS 1.2 the same `Tickets` hands out RFC 5077 tickets, and a `Sessions` cache resumes by session id; both run the abbreviated handshake, which skips the certificate and the key exchange.

Client certificates work in both versions: a server that sets `client_auth` asks, a client with `cert` answers, and the chain is judged to the server's own anchors with the client usage. A request after the handshake (`Conn::request_certificate`) is the same exchange over the application traffic secret, and `Conn::post_handshake` says whether the client offered to answer one. Renegotiation is there for TLS 1.2 and refused unless both ends set `renegotiation`; when they do, the new handshake names the previous one's two Finished values, which is what RFC 5746 is for. OCSP stapling (`ocsp`), `record_size_limit` (RFC 8449) and certificate compression (RFC 8879 — zlib, brotli or zstd through `moonzip`, in either direction, whenever the peer named an algorithm this end speaks) sit beside them, and a heartbeat record is refused rather than answered.

An ML-DSA certificate works in TLS 1.3 under the `mldsa44`, `mldsa65` and `mldsa87` schemes (draft-ietf-tls-mldsa); TLS 1.2 has no scheme for one, so a server holding only that has nothing to offer there.

An RSASSA-PSS certificate (RFC 4055) signs under the `rsa_pss_pss_*` schemes and never under `rsa_pss_rsae_*`, and only under the digest its parameters hold the key to when they name one (RFC 8446 §4.2.3). TLS 1.2 takes the same three schemes, as RFC 8446 §1.3 allows, never encrypts a premaster to such a key, and never has it sign PKCS#1 v1.5. A client offering TLS 1.2 alone offers `schemes12` and nothing else, so it is never shown a scheme it then refuses.

A server can hold more than one certificate. `alternatives` is a list of `Credential`s, each a chain, its key and an optional OCSP response, tried after `chain` and `key` in order: the first whose key the client's signature algorithms allow, whose suites and curve a TLS 1.2 client accepts, and whose leaf is for the host the client named goes out, and the server then answers `server_name` empty, as RFC 6066 §3 asks. With none fitting, `chain` goes out and the handshake ends as it would have with one certificate. That is an ECDSA and an RSA certificate side by side, or several hosts behind one address.

`tls` also runs the handshake for QUIC ([RFC 9001 §4](https://www.rfc-editor.org/rfc/rfc9001#section-4)). `Conn::quic_server` and `Conn::quic_client` take CRYPTO bytes through `crypto` and give back, through `steps`, what to send at which level and when each level has keys: no records, no change_cipher_spec, no alerts on the wire. A resumed client with `early=true` gets its early traffic secret as an `Early` step before its hello goes out, and a server gets the same step when it takes the offer. Over QUIC no EndOfEarlyData is sent, and a ticket that allows anything but 0xffffffff bytes of early data is refused (RFC 9001 §4.6.1, §8.3).

`srtp` stops where TLS stops. `use_srtp` is negotiated on both DTLS versions — EncryptedExtensions for 1.3, the ServerHello for 1.2 — with the profile the server prefers among the client's offer, and the four keys and salts are exported from the 1.3 exporter master or from RFC 5705's PRF exporter in 1.2. The RFC 3711 transform that encrypts an RTP packet is [`moonrtc`](https://github.com/moonbitstack/moonrtc)'s, because RTP is not TLS's business.

Every decoder reads through `@wire.Reader`, which checks each length it relies on: a vector that runs past its end, is shorter than its minimum, is not a whole number of elements, or leaves octets over is `Malformed`, and the handshake answers it with decode_error. None of them shortens a list to what fits.

`alert` has no dependencies at all, on purpose: QUIC needs TLS's alerts without needing TLS's record layer, because [RFC 9001 §5](https://www.rfc-editor.org/rfc/rfc9001#section-5) replaces the record layer with QUIC's own packet protection.

## The digest is a parameter

RFC 8446 writes the whole ladder over `Hash`, the hash the negotiated cipher suite names. So every function here takes `digest`, and every output length follows from it:

<!-- nocheck -->
```moonbit
@keys.early()                  // SHA-256, the suite RFC 8446 §9.1 makes mandatory
@keys.early(digest=Sha384)     // 48 octets instead of 32, all the way down
```

`@keys.digest` is the preset, and it is `Sha256` because `TLS_AES_128_GCM_SHA256` is the one implementation is required to provide.

## What is not here

Sockets — those are `moonnet`'s. Cryptographic algorithms — those are `mooncrypt`'s. QUIC's transport layer — that is [`moonquic`](https://github.com/moonbitstack/moonquic), which borrows this handshake and reuses this key schedule verbatim ([RFC 9001 §5.2](https://www.rfc-editor.org/rfc/rfc9001#section-5.2)). Not here: DTLS 1.0, which RFC 8996 retires; and a constant-time modular exponentiation for RSA key exchange, which is `mooncrypt`'s to provide — the padding is checked without a branch and a bad block becomes a random premaster secret that fails at Finished, but the exponentiation itself takes the time it takes.

## Verification

The key schedule is checked against RFC 8446 §7.1 written out over Python's own HMAC — an implementation sharing no code with this one. The Early Secret for a zero PSK comes out `33ad0a1c…f170f92a`, which is the value [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448) publishes, so the ladder is anchored to the RFC's trace and not only to our own arithmetic.

The record layer is checked the same way, and one matching ciphertext covers the whole chain at once: the key and IV §7.3 derives, the nonce §5.3 builds from the sequence number, the trailing content type and padding of §5.2's inner plaintext, the five header octets chosen as the AEAD's additional data, and the AEAD itself.

DTLS has no RFC 8448 of its own — RFC 9147 publishes no traces — so its records are checked against the same kind of independent implementation, and one matching record again covers everything at once: the unified header's bits, the header as additional data, the nonce, and the AES-ECB mask that hides the sequence number.

TLS 1.0's and 1.1's PRF is a different construction rather than a different hash, and it is checked against OpenSSL's own `TLS1-PRF` with `digest:MD5-SHA1`: three vectors, one of them with an odd secret length, which is where the two halves of the secret overlap by an octet.

## Conformance

Two external tools judge this library, and [`scripts/tls_interop.sh`](scripts/tls_interop.sh) and
[`scripts/tls_fuzz.sh`](scripts/tls_fuzz.sh) run them. Both are in this repository rather than in a
consumer's, because both need a peer program: `integration/src/peer`, a module of its own, so that
the library's dependencies stay what the library needs — a server that echoes a line or answers an
HTTP request and a client that makes one, over TCP or UDP. A workspace (`moon.work`) resolves
`moonbitstack/moontls` to this checkout, so the peer exercises the source under test and not the
last release.

### Interop

`scripts/tls_interop.sh` runs 145 cases in both directions — this client against a server written
somewhere else, and this server against a client written somewhere else — against five
implementations: OpenSSL 3.5, BoringSSL built from source, Go's `crypto/tls`, Python's `ssl`, and
[`pion/dtls`](https://github.com/pion/dtls) v4 for the datagram. 143 pass and two are the known
gaps below. Between them they cover every TLS 1.3 key type against every suite, every group
including the post-quantum hybrid, HelloRetryRequest, ALPN, SNI, KeyUpdate from either side, records
of 512 octets and a megabyte both ways, session resumption, an external pre-shared key in both
directions — the binder included, which a key the server does not hold fails — client certificates
both ways, OCSP stapling, RFC 8879 certificate compression with the `CompressedCertificate` message
named in the log of the end that sent it, an ML-DSA certificate, TLS 1.0 and 1.1 in both
directions, the sixteen TLS 1.2 suites the table in the script names, DTLS 1.3 from both ends, DTLS
1.2 from both ends with and without a HelloVerifyRequest cookie, and 0-RTT accepted by this
server.

BoringSSL is worth the source build because it reads RFC 8446 more strictly than OpenSSL does, and
pion is the only external peer for DTLS 1.3 — no OpenSSL release speaks it. Between them they have
found the defects no two ends of this library could see in each other:

- **DTLS 1.3's version numbers.** `supported_versions` named 1.3 as `0x0304`, which is TLS 1.3's
  number; RFC 9147 §5.3 gives DTLS its own, `0xfefc`. Any conforming datagram peer refused the
  handshake, and because this library was on both ends of every DTLS test it had, it never noticed.
  The same applies to 1.2 and below (`0xfefd` down to `0xfeff`), to the frozen `legacy_version`
  field, and to `legacy_session_id`, which DTLS must leave empty and never echo.
- **The handshake `CertificateRequest`'s context.** RFC 8446 §4.3.2 requires it to be empty in the
  handshake and non-empty after it; it was 32 random octets either way. BoringSSL refuses to parse
  the message; OpenSSL does not.
- **DTLS 1.2's `ServerHello` version.** It said `0x0303` over a datagram; RFC 6347 §4.2.1 says
  `0xfefd`. pion's client refuses it, OpenSSL's does not.
- **TLS 1.0 and 1.1 as the client.** The RSA premaster secret repeated `0x0303` — the frozen
  `legacy_version` — where RFC 5246 §7.4.7.1 asks for the version the hello offered. OpenSSL reads
  a higher number there as a rollback attempt and substitutes a random secret, so the first
  protected record failed `bad_record_mac`. Both versions now complete, and
  `tls/legacy_exchange_test.mbt` holds the pair of cases that go red without the fix.
- **`record_size_limit` on the client.** A limit was enforced against every record, including the
  ones a peer sends before it has agreed to anything: OpenSSL's server, which never advertises one,
  kept sending its 16 KiB records and the connection ended with `record_overflow`. RFC 8449 §4
  makes the limit part of a negotiation, and the check now binds only a peer that named a limit of
  its own. Unprotected records — a ServerHello carrying a post-quantum share is the one that does
  not fit — stay outside the limit, as the section says.

- **DTLS 1.2's transcript.** RFC 6347 §4.2.2 puts every handshake message under a twelve-octet
  header that numbers it, and the transcript — EMS's session hash, the certificate verify, every
  Finished — is taken over the message as it went on the wire. This library hashed the body under
  TLS's four-octet header, and because both ends read it that way the handshake completed with
  itself and never with anyone else. OpenSSL's keylog is what pinned it: its master secret for a
  handshake matches only when the message number, the fragment offset and the fragment length are
  part of what is hashed. `Handshake::number12` is the transport saying so.
- **DTLS 1.2's AEAD nonce.** RFC 6347 §4.1.2.4 borrows RFC 5288's GCM suites unchanged, so the
  eight-octet `nonce_explicit` TLS 1.2 writes at the front of the body is there in a datagram too.
  This library read the record number off the header instead: AES-GCM records failed with
  `bad_record_mac` while ChaCha20-Poly1305, which has no explicit nonce (RFC 7905 §2), worked.
- **The ClientHello that answers a HelloVerifyRequest.** RFC 6347 §4.2.1 asks for the hello *again*
  with a cookie in it, and pion compares the octets either side of the cookie field, refusing a
  retry that moved anything else. The retry was rebuilt from the configuration, which drew a new
  random number and a new key share, so pion answered `illegal_parameter`. The entropy the first
  hello drew is now kept and replayed, and the second hello is the first one with a cookie in it.

What remains, and is where the next round should start:

| Case | What happens |
|:--|:--|
| TLS 1.2 renegotiation, server side | The server's `HelloRequest` is answered and the second handshake starts, but OpenSSL rejects the first record sealed under the new keys — `bad record mac`, or a provider error with ChaCha20. The two ends of this library agree with each other, which is why nothing noticed. A client cannot start one at all: `Conn::renegotiate` is the server's HelloRequest. |
| 0-RTT, this library as the client | The early traffic secret is not the problem and neither is the record: against `s_server -early_data -max_early_data 4096`, OpenSSL's own `CLIENT_EARLY_TRAFFIC_SECRET` for the connection is the same 32 octets this client derives, and the early record decrypts under it with `AAD = 17 03 03 || length` in an independent check. What OpenSSL does is decline the ticket before it gets that far: with `-max_early_data` it issues its anti-replay tickets, which are a 32-octet session id kept on the server, and this client's resumption is refused under those whether or not it carries early data — a full handshake, `resumed=0`, and no early secret derived at all. The same client resumes the 192-octet stateless ticket that a server without `-max_early_data` hands out. The other direction is in the matrix: `s_client -sess_in -early_data` against this server answers `Reused` and `Early data was accepted`. |
| 0-RTT, this library as the server | Covered: the `server: 0-RTT accepted` case, OpenSSL's client against this server, `s_client -sess_in … -early_data`. The client's own half of the same handshake is refused by OpenSSL's anti-replay tickets, above. |

### tlsfuzzer

`scripts/tls_fuzz.sh` runs [tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer)'s TLS 1.3 scripts
against the peer's server, all 57 of them, and the `fuzz` job in `.github/workflows/ci.yml` runs
that script on every push. tlsfuzzer is a test tool rather than a dependency, so the job fetches the
project's master and its own `tlslite-ng`: the release on PyPI predates the signature schemes the
newest scripts name, and a script that stops at `SignatureScheme has no attribute mldsa87` never
reaches a server at all.

Thirteen servers are started, because the scripts differ in what they need of the server and not
only in what they send it:

| # | Server | Scripts it is for |
|:--|:--|:--|
| 0 | an RSA certificate and every group | the general one, `ecdhe-brainpool-curves`, `obsolete-curves` |
| 1 | an ECDSA P-256 certificate, and one on each of P-384, P-521 and the three brainpool curves | `minerva`, `ecdsa-support` |
| 2 | an Ed25519 certificate | `eddsa` |
| 3 | an RSA certificate that asks for a client certificate, under a root this run issues | the six that answer a handshake CertificateRequest, handed `-c`/`-k` and `-s` |
| 4 | every TLS version and every TLS 1.2 suite | `symetric-ciphers`, `non-support`, `version-negotiation`, `0rtt-garbage` |
| 5 | a server that sends the first KeyUpdate, for the request that names it | `keyupdate-from-server` |
| 7 | an RSASSA-PSS certificate | `rsapss-signatures` |
| 8 | a server that asks for a client certificate once the connection is open | `post-handshake-auth` |
| 9 | a server that accepts one external pre-shared key, in either PSK mode | `psk_ke`, `psk_dhe_ke` |
| 10 | a server that hands out tickets and takes one back under either mode | `session-resumption` |
| 11 | the five groups a script is told about, and no others | `no-unknown-groups` |
| 12 | a server that compresses its Certificate | `certificate-compression` |
| 13 | the same, and a request for a client certificate, which may come compressed too | `client-certificate-compression` |

All thirteen come up. A peer that will not start is reported as unrouted rather than as a
failure, because it says nothing about a handshake.

`scripts/tls_fuzz.expected` is the table this repository is judged by: one line per script, saying
whether it passes today. A script recorded as passing that no longer does fails the job; one
recorded as failing that starts passing is reported and fails nothing, because a table that has to
be edited before a fix can land would be edited wrongly.

44 of the 57 pass in full, 12 run and answer something wrongly, and 1 does not finish inside the
five minutes a script is given. `dhe-shared-secret-padding` used to sit on the
boundary — the run before the one quoted caught it there — and now passes.

| Scripts | What fails |
|:--|:--|
| `certificate-compression` | 24 of its 31 conversations pass. Six send a `compress_certificate` whose payload is not the list §3 describes — an empty list, an odd length, a padded payload, an unassigned code point — and expect `decode_error`; this library reads such a payload as naming no algorithm and sends the certificate uncompressed, because `large-number-of-extensions` sends the same shapes and expects the handshake to go on, and a whole script of 22 conversations is the better side of that trade. The seventh offers brotli and nothing else: the certificate does arrive compressed, and tlsfuzzer's own decompression raises `TypeError: 'NoneType' object is not subscriptable`. |
| `client-certificate-compression` | 39 of its 42 conversations pass. Two expect the CertificateRequest to carry `signature_algorithms` and `compress_certificate` and nothing else; this server also names the authorities it will accept, which §4.4.2.2 makes optional, and OpenSSL 3.5 fails both probes with the same words (`Server sent unexpected extension(s): 47`). The third wants `compress_certificate` named to a client that never offered it, where this server names the algorithms only to a client that did. |
| `certificate-request` | One probe of five requires the CertificateRequest to carry `signature_algorithms` and nothing else. RFC 8446 §4.4.2.2 makes `certificate_authorities` optional, and this server names its anchors because a client with more than one chain has nothing else to choose by. |
| `connection-abort` | Ten probes of 150 read `ApplicationData(len=64)` where the script has stopped reading: the peer echoes the request it was given. |
| `ecdsa-support` | Five probes of ten want a server holding an RSASSA-PSS certificate to sign with `rsa_pss_pss_*`; it answers `handshake_failure`, as `rsapss-signatures` does. |
| `rsapss-signatures` | None of its 8 conversations passes: with an RSASSA-PSS certificate the server does not offer the `rsa_pss_pss_*` schemes (RFC 8446 §4.2.3), so five end in `handshake_failure` and three see a ServerHello where the probe expected a refusal. |
| `ecdhe-brainpool-curves`, `obsolete-curves` | 0 of 23 and 54 of 171 pass. A key share for a group the client did not list, or one TLS 1.3 retired, is answered `handshake_failure` where the scripts want `illegal_parameter` (§4.2.8); the five positive probes of the first want the RFC 8734 brainpool groups negotiated, which the server does not offer. |
| `ecdsa-brainpool-in-certificate-verify` | `tlslite-ng` cannot read a brainpool certificate (`SyntaxError: Unknown curve`), so no conversation reaches a server. |
| `mlkem` | The script builds its own hybrid hello with kyber-py: 99 of its 402 probes pass. The other 303 want `illegal_parameter` for a malformed or unlisted share and get `handshake_failure`, the same answer as in the two rows above. |
| `symetric-ciphers` | TLS 1.2 suites: 32 conversations of 102 end with `handshake_failure`. The script offers suites this library does not implement — DSA, static DH, SRP, PSK, Camellia, ARIA, SEED, IDEA, 3DES in the preset it drives — and a server that speaks a subset is what the alert says. |
| `non-support` | Written against a server that refuses a hello with no `supported_versions` by closing the connection; this one negotiates TLS 1.2 where it can, which is what its preset says to do, and what the script reports depends on how long the peer's socket stays open rather than on what was answered. |
| `lengths` | The script's own conversation runs past the five minutes it is given. |

None of those is a script passing by accident: a conversation that gets an alert the RFC does not
owe fails the script, and that is what the gap rows report.

What this round fixed, all of it found by these scripts or by the peer they drive:

- **A CertificateVerify that names a scheme the certificate's key cannot use** is a contradiction
  between two messages, and §4.4.3 answers it with `illegal_parameter`; the signature alone was
  checked, so every such probe counted as a `decrypt_error` (24 probes across three scripts).
- **`signature_algorithms` is not owed by a handshake that authenticates with a ticket**
  (RFC 8446 §9.2), and the server demanded it of every ClientHello.
- **`schemes12` was the TLS 1.3 offer verbatim**, so a TLS 1.2 CertificateRequest named RFC 8734's
  brainpool schemes and the ML-DSA ones — names that version cannot express (§4.2.3).
- **A TLS 1.2 `session_ticket` answer was a vector of length zero** where RFC 5077 §3.2 asks for an
  empty extension, and the ticket went out after the server's Finished rather than before its
  change_cipher_spec (§3.5), so no client that expected a ticket ever got one.
- **`psk_key_exchange_modes` was written as `psk_dhe_ke` whatever the configuration said**, and a
  client with a ticket but no external key never wrote it at all.
- **A KeyUpdate during a post-handshake authentication** was an `unexpected_message`, where §4.6.3
  allows one at any point after the handshake.
- **A server updated its keys for every request** rather than for the one that asks for it, and
  asked for a client certificate without checking that the client offered to answer one (§4.2.6).
- **A compressed Certificate that would not unpack was `decode_error`**, where RFC 8879 §4 names
  `bad_certificate` twice — once for a message that cannot be decompressed and once for a length
  that does not match. The client's offer was also read while the server's flight was being built,
  so a hello whose extension did not decode was answered with a ServerHello first.
- **`close_notify` was never answered.** RFC 8446 §6.1 owes one back, and a peer that waits for it
  cannot tell the shutdown it asked for from a truncated stream; ten of
  `certificate-compression`'s conversations and two of `client-certificate-compression`'s read an
  abrupt close where an alert was owed.
- **A certificate that compressed to more octets than it started with was sent uncompressed**,
  which answers a `compress_certificate` offer with a message the peer did not ask for (§4).

The client's side of the same rules is pinned by tests that play a forged server: a flight without
CertificateVerify, a Certificate before EncryptedExtensions or twice, a message sharing the
ServerHello's record, an extension the client never offered. A pre-shared key has its own file:
`tls/psk_test.mbt` runs a handshake on a configured secret, on a wrong one, under `psk_ke`, and
against a server that does not take that mode.

The gate is `moon clean` → `moon fmt` → `moon check --target all --deny-warn` → `moon build --target all` → `moon test --target all`, across `wasm`, `wasm-gc`, `js` and `native`.

## License

Apache-2.0.
