# moontls

The TLS 1.3 protocol state machine for MoonBit ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) — bytes in, events out. No sockets, and not one line of cryptography of its own: the algorithms are [`mooncrypt`](https://github.com/moonbitstack/mooncrypt)'s and certificate reading is [`mooncred`](https://github.com/moonbitstack/mooncred)'s.

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
| `ext` | [§4.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.2) extensions: ALPN, SNI, key_share, supported_versions | next |
| `hs` | [§4](https://www.rfc-editor.org/rfc/rfc8446#section-4) handshake state machine, ClientHello to Finished | after that |

`alert` has no dependencies at all, on purpose: QUIC needs TLS's alerts without needing TLS's record layer, because [RFC 9001 §5](https://www.rfc-editor.org/rfc/rfc9001#section-5) replaces the record layer with QUIC's own packet protection.

## The digest is a parameter

RFC 8446 writes the whole ladder over `Hash`, the hash the negotiated cipher suite names. So every function here takes `digest`, and every output length follows from it:

```moonbit
@keys.early()                  // SHA-256, the suite RFC 8446 §9.1 makes mandatory
@keys.early(digest=Sha384)     // 48 octets instead of 32, all the way down
```

`@keys.digest` is the preset, and it is `Sha256` because `TLS_AES_128_GCM_SHA256` is the one implementation is required to provide.

## What is not here

Sockets. Certificate chain validation — that is `mooncred`. Cryptographic algorithms — those are `mooncrypt`. QUIC's transport layer — that is [`moonquic`](https://github.com/moonbitstack/moonquic), which borrows this handshake and reuses this key schedule verbatim ([RFC 9001 §5.2](https://www.rfc-editor.org/rfc/rfc9001#section-5.2)). Session resumption, 0-RTT and client certificates are not implemented yet.

## Verification

The key schedule is checked against RFC 8446 §7.1 written out over Python's own HMAC — an implementation sharing no code with this one. The Early Secret for a zero PSK comes out `33ad0a1c…f170f92a`, which is the value [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448) publishes, so the ladder is anchored to the RFC's trace and not only to our own arithmetic.

The record layer is checked the same way, and one matching ciphertext covers the whole chain at once: the key and IV §7.3 derives, the nonce §5.3 builds from the sequence number, the trailing content type and padding of §5.2's inner plaintext, the five header octets chosen as the AEAD's additional data, and the AEAD itself.

The gate is `moon clean` → `moon fmt` → `moon check --target all --deny-warn` → `moon build --target all` → `moon test --target all`, across `wasm`, `wasm-gc`, `js` and `native`.

## License

Apache-2.0.
