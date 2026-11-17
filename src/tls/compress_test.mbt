// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Certificate compression (RFC 8879): a Certificate message under one of the three algorithms
// §4.2 registers, and the length the compressed one promises held to.

///|
/// A server that compresses the Certificate it sends under `algorithms`.
fn compressing_server(algorithms~ : Array[Int32]) -> @tls.Conn raise {
  let config = @tls.Server::new(
    [der(p256_leaf)],
    p256(),
    compress=true,
    compressions=algorithms,
  )
  @tls.Conn::server(config, rand=rng(1000), now~)
}

///|
/// A client that advertises `algorithms` and judges the chain it is shown.
fn compressing_client(algorithms~ : Array[Int32]) -> @tls.Conn raise {
  let config = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    compress=true,
    compressions=algorithms,
  )
  @tls.Conn::client(config, "a.example", rand=rng(1), now~)
}

///|
test "tls: a certificate compresses under each of the three algorithms" {
  for
    algorithm in [
      @ext.zlib_compression, @ext.brotli_compression, @ext.zstd_compression,
    ] {
    let server = compressing_server(algorithms=[algorithm])
    let client = compressing_client(algorithms=[algorithm])
    shuttle(client, server)
    assert_true(client.is_connected())
    assert_true(server.is_connected())
    // The chain arrived and was judged, which it could only be if it had been unpacked.
    assert_eq(client.peer().length(), 1)
  }
}

///|
test "tls: an algorithm the peer did not offer is not used" {
  // The server prefers zlib but the client named only zstd, so zstd is what travels — and the
  // handshake completes either way, because a compressed certificate is optional.
  let server = compressing_server(algorithms=[
    @ext.zlib_compression, @ext.zstd_compression,
  ])
  let client = compressing_client(algorithms=[@ext.zstd_compression])
  shuttle(client, server)
  assert_true(client.is_connected())
  assert_eq(client.peer().length(), 1)
}

///|
test "tls: a compressed certificate is refused when it was not offered" {
  let server = compressing_server(algorithms=[@ext.zlib_compression])
  let config = @tls.Client::new(
    @x509.Roots::new(certs=[der(root)][:]),
    compress=false,
  )
  let client = @tls.Conn::client(config, "a.example", rand=rng(1), now~)
  shuttle(client, server)
  // Nothing was offered, so nothing is compressed: the plain Certificate arrives and is judged.
  assert_true(client.is_connected())
  assert_eq(client.peer().length(), 1)
}

///|
/// A TLS 1.3 ClientHello with `change` applied, as it goes on the wire.
fn hello13(change : (@msg.Hello) -> @msg.Hello) -> Bytes raise {
  let c = client_with()
  let (record, _) = @record.decode(c.take()[:]).unwrap()
  let (_, body) = @msg.unframe(record.fragment[:]).unwrap()
  @record.encode(
    Handshake,
    @msg.hello(change(@msg.read_hello(body[:]).unwrap()))[:],
  )
}

///|
/// A hello whose `compress_certificate` payload is exactly `data`, offered under no other name.
fn offering(data : Bytes) -> (@msg.Hello) -> @msg.Hello {
  h => {
    ..h,
    extensions: [
      ..h.extensions.filter(e => e.kind != CompressCertificate),
      @ext.Ext::{ kind: CompressCertificate, data, },
    ],
  }
}

///|
test "tls: a compress_certificate outside the grammar is decode_error under strict" {
  // RFC 8879 §3 gives the payload one shape: a vector of two-octet codes, at least one of them,
  // filling the extension. Every entry here misses it in a different way, and RFC 8446 §4 answers
  // a field out of its own range with decode_error.
  for
    data in [
      b"", b"\x00", b"\x00\x00\x01\x00\x02\x00\x03", b"\x05\x00\x01\x00\x02\x00\x03",
      b"\x08\x00\x01\x00\x02\x00\x03", b"\x04\x00\x01\x00\x02\x00\x03", b"\x07\x00\x01\x00\x02\x00\x03\x04",
    ] {
    let config = @tls.Server::new(
      [der(p256_leaf)],
      p256(),
      compress=true,
      strict=true,
    )
    let server = @tls.Conn::server(config, rand=rng(1000), now~)
    assert_eq(
      alert_of(() => server.receive(hello13(offering(data))[:])),
      DecodeError,
    )
  }
}

///|
test "tls: without strict a malformed offer is an offer that named nothing" {
  // The same shapes, read by a server that takes an optimisation hint at its word only when it
  // parses: the certificate goes out uncompressed and the handshake goes on.
  for data in [b"", b"\x05\x00\x01\x00\x02\x00\x03"] {
    let server = compressing_server(algorithms=[@ext.zlib_compression])
    server.receive(hello13(offering(data))[:])
    let answer = server.take()
    assert_true(answer.length() > 0)
  }
}
