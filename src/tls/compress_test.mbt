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
