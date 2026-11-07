---
name: moontls
description: "TLS 1.3 and 1.2 and DTLS 1.3 and 1.2 as protocol state machines: ciphertext in, ciphertext and plaintext out, over a transport you already have. Use it to speak TLS over a socket, QUIC CRYPTO stream or datagram loop you own, or to read a ClientHello without a handshake."
---

# moontls

`moon add moonbitstack/moontls`, then import the packages you need: `moonbitstack/moontls/tls` for a
connection, `moonbitstack/moontls/dtls` for the datagram ones, `moonbitstack/moontls/msg` and
`moonbitstack/moontls/ext` to read messages without a handshake.

There is no socket in this library and no clock. A connection takes the octets your transport read,
gives back the octets to write, and hands you the plaintext. Randomness is a `(Int32) -> Bytes` you
supply; the time is an `Int64` you supply, in seconds for certificates and in milliseconds for the
datagram timers.

## Speak TLS over a transport you own

A client is `take` until it is empty, then `receive` what arrived, then `take` again. The first
`take` is the ClientHello.

```mbt check
test {
  let config = @tls.Client::new(@x509.Roots::new(certs=[]), alpn=["h2", "http/1.1"])
  let conn = @tls.Conn::client(
    config,
    "example.com",
    rand=fn(n) { Bytes::make(n, b'\x00') },
    now=1767225600L,
  )
  let hello = conn.take()
  assert_true(hello.length() > 0)
}
```

`conn.is_connected()` is when the handshake is done, `conn.read()` empties the plaintext that
arrived, `conn.write(bytes)` queues plaintext to send, and `conn.alpn()` is what ALPN settled on.
A server is `@tls.Conn::server(config, ...)` with the same four calls; `@tls.Server::new` takes the
chain (DER, leaf first) and a `@x509.PrivateKey`, and refuses a key that is not the leaf's.

## A record, and the key that protects it

The record layer is usable on its own, which is what a QUIC implementation or a test wants: one
traffic secret, one suite, and a cipher each way.

```mbt check
test {
  let secret = @base16.decode("ab4fc9e2370723165814c074381ab62cbb2c32fd421b15db6910f5df5b1756a3")
  let suite = @record.Aes128Gcm
  let writer = @record.Cipher::new(secret[:], suite~)
  let record = writer.seal(@record.Handshake, b"hello"[:])
  let reader = @record.Cipher::new(secret[:], suite~)
  let (kind, content) = reader.open(record[:])
  assert_eq(kind, @record.Handshake)
  assert_eq(content, b"hello")
}
```

The key schedule under it is `@keys`: `early`, `handshake`, `master`, then `client_handshake` and
`server_handshake` over the transcript hash. Every step takes `digest`, so a SHA-384 suite's
outputs are 48 octets without any other change.

## Datagrams

`@dtls.Conn13` and `@dtls.Conn12` take one datagram at a time and give back one at a time, because
that is what a socket sends. They need three things a stream does not: `now` in milliseconds on
your monotonic clock, `tick` when `deadline` says so, and — on a server that wants to keep nothing
until the peer proves it can receive — the peer's address in `receive`, which is what its cookie is
sealed over.

What a datagram forces is the framing, and it is a function of its own: cut a handshake message to
what one datagram holds, and read it back.

```mbt check
test {
  let message = @msg.frame(@msg.Kind::Finished, Bytes::make(32, b'\x00')[:])
  let cut = @dtls.pieces(message, seq=0, room=1200)
  assert_eq(cut.length(), 1)                 // 36 octets fit one datagram
  assert_eq(cut[0].total, 32)
  assert_eq(cut[0].seq, 0)
}
```

## Rules that catch people out

- `receive` raises `@alert.Alert`; the alert has already been queued for the peer by then, so drain
  `take` before closing, or the peer sees a closed socket instead of a reason.
- A whole handshake message may arrive in pieces and a flight may arrive out of order; `@dtls`
  reassembles and reports, but a stream transport must hand `receive` whole records, not a byte at a
  time cut anywhere.
- The certificate chain is `mooncred`'s to judge. There is no switch that turns checking off: a
  self-signed server is trusted by putting its certificate in the roots, or by a `Custom` judge.
- `versions` decides what is offered. TLS 1.1 and 1.0 are implemented and left out of the preset,
  as RFC 8996 asks; name them if a peer needs them.
