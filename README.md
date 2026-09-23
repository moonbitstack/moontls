# moontls

The TLS 1.3 protocol state machine for MoonBit ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)), and DTLS 1.3 ([RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)) for when it runs over datagrams — bytes in, events out. No sockets, and not one line of cryptography of its own: the algorithms are [`mooncrypt`](https://github.com/moonbitstack/mooncrypt)'s and certificate reading is [`mooncred`](https://github.com/moonbitstack/mooncred)'s.

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

Run `moon run examples/tour` for the whole surface in one go.

## Packages

|  | Specification | State |
|:--:|:--|:--:|
| `wire` | [§3](https://www.rfc-editor.org/rfc/rfc8446#section-3) integer widths and the frozen `legacy_version` | **0.2.0** |
| `alert` | [§6](https://www.rfc-editor.org/rfc/rfc8446#section-6) the alert protocol | **0.2.0** |
| `keys` | [§7.1](https://www.rfc-editor.org/rfc/rfc8446#section-7.1) key schedule, [§4.4.1](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.1) transcript hash, [§4.4.4](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.4) Finished | **0.1.0** |
| `record` | [§5](https://www.rfc-editor.org/rfc/rfc8446#section-5) record layer, [§7.3](https://www.rfc-editor.org/rfc/rfc8446#section-7.3) traffic keys | **0.2.0** |
| `ext` | [§4.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.2) extensions: supported_versions, supported_groups, signature_algorithms, key_share, ALPN | **0.3.0** |
| `msg` | [§4](https://www.rfc-editor.org/rfc/rfc8446#section-4) the handshake messages: ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished | **0.4.0** |
| `hs` | [Appendix A](https://www.rfc-editor.org/rfc/rfc8446#appendix-A) the state machine, §4.1.1 negotiation, §4.1.4 HelloRetryRequest, and the driver | **0.5.0** |
| `dtls` | [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147) what datagrams change: both record shapes, record number encryption, the replay window, handshake fragmentation and reassembly, the ACK message | **0.1.0** |
| `srtp` | [RFC 5764](https://www.rfc-editor.org/rfc/rfc5764) the SRTP protection profiles a DTLS handshake negotiates, and the keying material it exports for them | **0.1.0** |

`msg` is formats only. Which message may arrive next, and which parameters to pick, is the state machine's — that seam is what lets a tool read a ClientHello (an SNI router, a fingerprinter) without linking a handshake or a record layer.

`ext` says what is on the wire and nothing about what to pick from it: which group, which scheme, which version is the handshake's decision and lives in `hs`. `quic_transport_parameters` has a type code there and no codec — the payload is QUIC's ([RFC 9000 §18](https://www.rfc-editor.org/rfc/rfc9000#section-18)), and reading somebody else's structure would be this library claiming to know it.

`dtls` is everything a datagram forces and nothing else: the handshake messages, the key schedule and the extensions are unchanged, so they come from the packages beside it. It has no clock — it reports what arrived and what is still missing, and the caller decides when to resend ([§5.8](https://www.rfc-editor.org/rfc/rfc9147#section-5.8)'s timers are a policy, not a format).

`srtp` stops where TLS stops. It negotiates the profile and exports the keys; the RFC 3711 transform that encrypts an RTP packet is [`moonrtc`](https://github.com/moonbitstack/moonrtc)'s, because RTP is not TLS's business.

`alert` has no dependencies at all, on purpose: QUIC needs TLS's alerts without needing TLS's record layer, because [RFC 9001 §5](https://www.rfc-editor.org/rfc/rfc9001#section-5) replaces the record layer with QUIC's own packet protection.

## The digest is a parameter

RFC 8446 writes the whole ladder over `Hash`, the hash the negotiated cipher suite names. So every function here takes `digest`, and every output length follows from it:

```moonbit
@keys.early()                  // SHA-256, the suite RFC 8446 §9.1 makes mandatory
@keys.early(digest=Sha384)     // 48 octets instead of 32, all the way down
```

`@keys.digest` is the preset, and it is `Sha256` because `TLS_AES_128_GCM_SHA256` is the one implementation is required to provide.

## What is not here

Sockets. DTLS 1.2 — this is a TLS 1.3 library, and DTLS 1.2 is TLS 1.2 over datagrams, a different protocol with a different key schedule. Certificate chain validation — that is `mooncred`. Cryptographic algorithms — those are `mooncrypt`. QUIC's transport layer — that is [`moonquic`](https://github.com/moonbitstack/moonquic), which borrows this handshake and reuses this key schedule verbatim ([RFC 9001 §5.2](https://www.rfc-editor.org/rfc/rfc9001#section-5.2)). Session resumption, 0-RTT and client certificates are not implemented yet.

## Verification

The key schedule is checked against RFC 8446 §7.1 written out over Python's own HMAC — an implementation sharing no code with this one. The Early Secret for a zero PSK comes out `33ad0a1c…f170f92a`, which is the value [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448) publishes, so the ladder is anchored to the RFC's trace and not only to our own arithmetic.

The record layer is checked the same way, and one matching ciphertext covers the whole chain at once: the key and IV §7.3 derives, the nonce §5.3 builds from the sequence number, the trailing content type and padding of §5.2's inner plaintext, the five header octets chosen as the AEAD's additional data, and the AEAD itself.

DTLS has no RFC 8448 of its own — RFC 9147 publishes no traces — so its records are checked against the same kind of independent implementation, and one matching record again covers everything at once: the unified header's bits, the header as additional data, the nonce, and the AES-ECB mask that hides the sequence number.

The gate is `moon clean` → `moon fmt` → `moon check --target all --deny-warn` → `moon build --target all` → `moon test --target all`, across `wasm`, `wasm-gc`, `js` and `native`.

## License

Apache-2.0.
