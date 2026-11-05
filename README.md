# moontls

TLS for MoonBit — 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) and 1.2 ([RFC 5246](https://www.rfc-editor.org/rfc/rfc5246)), client and server, with 1.1 and 1.0 ([RFC 2246](https://www.rfc-editor.org/rfc/rfc2246)) on request — and DTLS 1.3 ([RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)) and DTLS 1.2 ([RFC 6347](https://www.rfc-editor.org/rfc/rfc6347)) over datagrams, client and server. Ciphertext in, ciphertext and plaintext out. No sockets, and not one line of cryptography of its own: the algorithms are [`mooncrypt`](https://github.com/moonbitstack/mooncrypt)'s and certificate validation is [`mooncred`](https://github.com/moonbitstack/mooncred)'s.

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

```moonbit
// The key schedule of RFC 8446 §7.1, one step at a time.
let early = @keys.early()                                  // no PSK
let handshake = @keys.handshake(early[:], ecdhe[:])        // salted by ECDHE
let master = @keys.master(handshake[:])

let transcript = @keys.Transcript::new()
transcript.add(client_hello[:])
transcript.add(server_hello[:])

let secret = @keys.client_handshake(handshake[:], transcript.hash()[:])
let ok = @keys.finished_ok(secret[:], transcript.hash()[:], verify_data[:])
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
| `tls` | The connection: client and server, X25519MLKEM768, X25519, P-256, P-384, P-521 and X448, and SecP256r1MLKEM768, SecP384r1MLKEM1024, ML-KEM alone and the RFC 7919 groups on request, the three suites, ECDSA, RSA-PSS and Ed25519 certificates, HelloRetryRequest, SNI, ALPN, KeyUpdate, close_notify, middlebox compatibility mode, declined 0-RTT data read past; TLS 1.2 beside 1.3 and the session resumption, client certificates, renegotiation and stapling that come with them; the server's chain judged by `mooncred` | **0.1.0** |
| `srtp` | [RFC 5764](https://www.rfc-editor.org/rfc/rfc5764) the SRTP protection profiles a DTLS handshake negotiates, and the keying material it exports for them | **0.1.0** |

`msg` is formats only. Which message may arrive next, and which parameters to pick, is the state machine's — that seam is what lets a tool read a ClientHello (an SNI router, a fingerprinter) without linking a handshake or a record layer.

`ext` says what is on the wire and nothing about what to pick from it: which group, which scheme, which version is the handshake's decision and lives in `hs`. `quic_transport_parameters` has a type code there and no codec — the payload is QUIC's ([RFC 9000 §18](https://www.rfc-editor.org/rfc/rfc9000#section-18)), and reading somebody else's structure would be this library claiming to know it.

`dtls` derives its keys under `dtls13`, not `tls13 ` ([§5.9](https://www.rfc-editor.org/rfc/rfc9147#section-5.9)). Up to 0.9.0 it used the TLS prefix, which round-trips against itself and interoperates with nobody; pion/dtls's vectors caught it, and `dtls/pion_wbtest.mbt` now holds them.

`dtls` is everything a datagram forces and nothing else: the handshake messages, the key schedule and the extensions are unchanged, because DTLS 1.3 runs the TLS 1.3 handshake verbatim. `Conn13` and `Conn12` are that handshake bound to a datagram record layer; `tls.Handshake` is the same handshake with the record layer taken out, and `tls.Layer` is the seam a third transport implements.

Neither connection reads a clock. Every call takes `now`, in milliseconds on the caller's own monotonic clock; `deadline` says when the next `tick` is due, and `tick` retransmits what is overdue. `wall` is the separate wall clock, in seconds, a certificate is judged at. DTLS 1.3 acknowledges records and retransmits the fragments no ACK named ([§7](https://www.rfc-editor.org/rfc/rfc9147#section-7)); DTLS 1.2 has no ACK and resends a whole flight, which its answer is what acknowledges ([RFC 6347 §4.2.4](https://www.rfc-editor.org/rfc/rfc6347#section-4.2.4)). A record that does not deprotect — a duplicate caught by the replay window, a forgery — is dropped and the association goes on.

DTLS 1.2 keeps its own record layer, not 1.3's: a 13-octet header with an explicit epoch and a 48-bit sequence number, a nonce built from that sequence number, and the frozen `0xfefd` version in the header and the associated data alike. `dtls.Cipher12` frames the record and hands the octets to `record.Cipher`, because an epoch and a sequence number are exactly the eight octets a TLS 1.2 record already covers — so every suite the table holds travels: AES-GCM, ChaCha20-Poly1305, AES-CCM with a 16- or 8-octet tag, and AES-CBC with the MAC before or after the encryption, its padding checked in constant time.

A DTLS 1.2 server can refuse to keep state for a ClientHello until the address it came from has proved it can receive. Pass `cookie=@dtls.Key(key)` — or `@dtls.Key(b"")` for one drawn from the server's own randomness — and the first hello is answered with a HelloVerifyRequest, and the handshake starts only on the ClientHello that echoes the cookie back. The cookie is an HMAC of the address under that key and nothing else is kept, so a forged source buys one small packet and no flight; a cookie replayed from another address is answered with a request of its own. `receive` takes the peer's address, `peer=`, because that is what the cookie is an answer about.

The key exchange is post-quantum by default. `groups` puts X25519MLKEM768 first, as Chrome, Firefox, Go, OpenSSL 3.5 and rustls do, and `shares` sends a key share for the first two, so a server without the hybrid takes the X25519 share at once instead of asking again. The hybrid's share is 1,216 bytes against X25519's 32; a client that cannot afford it passes `shares=1` or its own `groups`. SecP256r1MLKEM768, SecP384r1MLKEM1024 and ML-KEM alone (`@ext.mlkem512` to `@ext.mlkem1024`) are there to be named. ML-KEM is `mooncrypt`'s, and `Conn::group` says which group ran. RFC 7027's three brainpool groups are a TLS 1.2 option (`@tls.brainpool`), and RFC 8734's three ECDSA schemes are offered so a brainpool certificate can prove its key to a TLS 1.3 peer.

`tls` speaks TLS 1.2 beside 1.3, both on by default through `versions`, and `Conn::version` says which was settled. TLS 1.1 and 1.0 are implemented and left out of that preset, as RFC 8996 asks: a caller that needs them names them, and the PRF over MD5 and SHA-1, the implicit CBC IV and the signature without a scheme come with them. TLS 1.2 has a table of its own in `record`, one row a suite: ECDHE, DHE and RSA key exchange under AES-GCM, AES-CCM, ChaCha20-Poly1305 and AES-CBC, 39 in all. `suites12`, the default, is the six with ECDHE and an AEAD; `@record.all12` is everything, and asking for it is a decision, because RSA key exchange has no forward secrecy and CBC has a history. Beside the suites come extended master secret (RFC 7627), encrypt-then-MAC (RFC 7366), secure renegotiation indication (RFC 5746), the downgrade sentinel and `TLS_FALLBACK_SCSV`; a request to renegotiate is declined with a warning and the connection goes on.

The old suites keep their countermeasures: a CBC record does the same work whatever is wrong with it, which is Lucky Thirteen's fix, and a wrapped premaster that fails to unwrap becomes a random secret and fails at Finished, which is Bleichenbacher's. A client refuses a DHE prime under `dh_bits`, 2048 by default. `schemes12` is the same bargain for signatures: SHA-2, PSS and Ed25519 by default, and `all_schemes12` adds SHA-1, which is what a TLS 1.2 client that sends no signature_algorithms is taken to mean. It governs TLS 1.2 only: 1.0 and 1.1 have no scheme to negotiate, and their hash comes with naming the version.

A session can be resumed instead of re-authenticated. In TLS 1.3 a server hands out `NewSessionTicket`s sealed under its ticket keys — the ticket carries its state, so the server keeps nothing — and a client offers one back as a pre_shared_key with a binder over the truncated ClientHello; with `Tickets::early` and a client that asks, 0-RTT data travels under the early traffic secret and is closed by EndOfEarlyData, and data a server declines is sent again as ordinary data. A ticket's age is compared across two clocks, and `Tickets::drift` says how far apart they may read, in milliseconds: 10 seconds by default, OpenSSL's allowance. A wider gap costs the early data and nothing else (RFC 8446 §8.3). Tickets hold their own state, so the server has no record of which have been used, and 0-RTT data can be replayed by whoever recorded it: that is RFC 8446 §8, and `early` is 0 until a server decides otherwise. In TLS 1.2 the same `Tickets` hands out RFC 5077 tickets, and a `Sessions` cache resumes by session id; both run the abbreviated handshake, which skips the certificate and the key exchange.

Client certificates work in both versions: a server that sets `client_auth` asks, a client with `cert` answers, and the chain is judged to the server's own anchors with the client usage. A request after the handshake (`Conn::request_certificate`) is the same exchange over the application traffic secret. Renegotiation is there for TLS 1.2 and refused unless both ends set `renegotiation`; when they do, the new handshake names the previous one's two Finished values, which is what RFC 5746 is for. OCSP stapling (`ocsp`), `record_size_limit` (RFC 8449) and certificate compression (RFC 8879, zlib through `moonzip`, used only when it actually makes the message shorter) sit beside them, and a heartbeat record is refused rather than answered.

An ML-DSA certificate works in TLS 1.3 under the `mldsa44`, `mldsa65` and `mldsa87` schemes (draft-ietf-tls-mldsa); TLS 1.2 has no scheme for one, so a server holding only that has nothing to offer there.

`tls` also runs the handshake for QUIC ([RFC 9001 §4](https://www.rfc-editor.org/rfc/rfc9001#section-4)). `Conn::quic_server` and `Conn::quic_client` take CRYPTO bytes through `crypto` and give back, through `steps`, what to send at which level and when each level has keys: no records, no change_cipher_spec, no alerts on the wire. A resumed client with `early=true` gets its early traffic secret as an `Early` step before its hello goes out, and a server gets the same step when it takes the offer. Over QUIC no EndOfEarlyData is sent, and a ticket that allows anything but 0xffffffff bytes of early data is refused (RFC 9001 §4.6.1, §8.3).

`srtp` stops where TLS stops. `use_srtp` is negotiated on both DTLS versions — EncryptedExtensions for 1.3, the ServerHello for 1.2 — with the profile the server prefers among the client's offer, and the four keys and salts are exported from the 1.3 exporter master or from RFC 5705's PRF exporter in 1.2. The RFC 3711 transform that encrypts an RTP packet is [`moonrtc`](https://github.com/moonbitstack/moonrtc)'s, because RTP is not TLS's business.

Every decoder reads through `@wire.Reader`, which checks each length it relies on: a vector that runs past its end, is shorter than its minimum, is not a whole number of elements, or leaves octets over is `Malformed`, and the handshake answers it with decode_error. None of them shortens a list to what fits.

`alert` has no dependencies at all, on purpose: QUIC needs TLS's alerts without needing TLS's record layer, because [RFC 9001 §5](https://www.rfc-editor.org/rfc/rfc9001#section-5) replaces the record layer with QUIC's own packet protection.

## The digest is a parameter

RFC 8446 writes the whole ladder over `Hash`, the hash the negotiated cipher suite names. So every function here takes `digest`, and every output length follows from it:

```moonbit
@keys.early()                  // SHA-256, the suite RFC 8446 §9.1 makes mandatory
@keys.early(digest=Sha384)     // 48 octets instead of 32, all the way down
```

`@keys.digest` is the preset, and it is `Sha256` because `TLS_AES_128_GCM_SHA256` is the one implementation is required to provide.

## What is not here

Sockets — those are `moonnet`'s. Cryptographic algorithms — those are `mooncrypt`'s. QUIC's transport layer — that is [`moonquic`](https://github.com/moonbitstack/moonquic), which borrows this handshake and reuses this key schedule verbatim ([RFC 9001 §5.2](https://www.rfc-editor.org/rfc/rfc9001#section-5.2)). Not here: DTLS 1.0, which RFC 8996 retires; the cookie over DTLS 1.3, which travels in a HelloRetryRequest the handshake does not yet send for that reason alone; and a constant-time modular exponentiation for RSA key exchange, which is `mooncrypt`'s to provide — the padding is checked without a branch and a bad block becomes a random premaster secret that fails at Finished, but the exponentiation itself takes the time it takes.

## Verification

The key schedule is checked against RFC 8446 §7.1 written out over Python's own HMAC — an implementation sharing no code with this one. The Early Secret for a zero PSK comes out `33ad0a1c…f170f92a`, which is the value [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448) publishes, so the ladder is anchored to the RFC's trace and not only to our own arithmetic.

The record layer is checked the same way, and one matching ciphertext covers the whole chain at once: the key and IV §7.3 derives, the nonce §5.3 builds from the sequence number, the trailing content type and padding of §5.2's inner plaintext, the five header octets chosen as the AEAD's additional data, and the AEAD itself.

DTLS has no RFC 8448 of its own — RFC 9147 publishes no traces — so its records are checked against the same kind of independent implementation, and one matching record again covers everything at once: the unified header's bits, the header as additional data, the nonce, and the AES-ECB mask that hides the sequence number.

TLS 1.0's and 1.1's PRF is a different construction rather than a different hash, and it is checked against OpenSSL's own `TLS1-PRF` with `digest:MD5-SHA1`: three vectors, one of them with an odd secret length, which is where the two halves of the secret overlap by an octet.

The connection is checked against OpenSSL 3.5 both ways by [`moonnet`](https://github.com/moonbitstack/moonnet)'s `scripts/tls_interop.sh`: this client against `openssl s_server` under every key type, suite and group, record sizes, padding, tickets, KeyUpdate, ALPN, SNI, and the chains it must refuse (an intermediate not sent, an untrusted root, a forged signature, a wrong host, an expired or not yet valid leaf, a leaf for client authentication or acting as a CA); and `openssl s_client` against this server under every key type and suite, OpenSSL's default ML-KEM-first ClientHello, HelloRetryRequest, KeyUpdate from either side, and the ClientHellos it must refuse. Every one of the 39 TLS 1.2 suites runs in both directions, and the CBC ones run both with encrypt-then-MAC and with the MAC first.

The server is also run through [tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer)'s TLS 1.3 scripts, which probe every message for wrong lengths, wrong order, wrong values and the alert each one is owed. What failed there when this round began, and is now implemented, was session resumption, client certificates and post-handshake authentication; what is still missing is Ed448 and RSASSA-PSS keys. Its TLS 1.2 scripts run against every suite turned on, and the ones that fuzz MACs, padding, ciphertext, CCM, GCM nonces and RSA key exchange messages all pass.

The client's side of the same rules is pinned by tests that play a forged server: a flight without CertificateVerify, a Certificate before EncryptedExtensions or twice, a message sharing the ServerHello's record, an extension the client never offered.

The gate is `moon clean` → `moon fmt` → `moon check --target all --deny-warn` → `moon build --target all` → `moon test --target all`, across `wasm`, `wasm-gc`, `js` and `native`.

## License

Apache-2.0.
