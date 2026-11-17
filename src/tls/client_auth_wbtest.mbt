// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The CertificateRequest this library sends (RFC 8446 §4.4.2.2): which extensions it carries, and
// when it carries them. The credential is this file's own, because a white-box test is a package of
// its own and cannot see the certificates the black-box tests hold.

///|
let wbtest_cert : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIBljCCATygAwIBAgIUMdu8C+RO/LEaOCc+ERT8iNk1cEEwCgYIKoZIzj0EAwIw
  #|FTETMBEGA1UEAwwKb25lLndidGVzdDAeFw0yNjExMTcxMTEyMTdaFw00NjExMTIx
  #|MTEyMTdaMBUxEzARBgNVBAMMCm9uZS53YnRlc3QwWTATBgcqhkjOPQIBBggqhkjO
  #|PQMBBwNCAAQ6evmAcN4YICjmMnZuDJES5GWPxop2ATThydYGEdOSpT3M2PtYLb4U
  #|AIAgVeg5dzJ4fv1UQPRB/LxjNAG2zImVo2owaDAdBgNVHQ4EFgQUS+xCDpfAkJLC
  #|HrZRlGIDJGdT1hgwHwYDVR0jBBgwFoAUS+xCDpfAkJLCHrZRlGIDJGdT1hgwDwYD
  #|VR0TAQH/BAUwAwEB/zAVBgNVHREEDjAMggpvbmUud2J0ZXN0MAoGCCqGSM49BAMC
  #|A0gAMEUCIQCIAboa8NPO/SLqErCfpDQPvk/rFoZpiIDL3L/1Pm3/sQIgfJI/iT/c
  #|763ZMPa7luId4IzqbUdlh+j+p3kWrze0BE8=
  #|-----END CERTIFICATE-----

///|
let wbtest_other : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIBljCCATygAwIBAgIUbAMQjDiIqOfyN2JUuIuhRzk4Z6EwCgYIKoZIzj0EAwIw
  #|FTETMBEGA1UEAwwKdHdvLndidGVzdDAeFw0yNjExMTcxMTEyMTdaFw00NjExMTIx
  #|MTEyMTdaMBUxEzARBgNVBAMMCnR3by53YnRlc3QwWTATBgcqhkjOPQIBBggqhkjO
  #|PQMBBwNCAAR8qGw2pMs/MPmKgRi6QPDo2YGH6j3TQNb4AMw68++Llz/UfuaDiyCA
  #|FeRfUYQVhYp6azB7hSd9ann14ECiYB4Vo2owaDAdBgNVHQ4EFgQUN2Y9yhOysJWT
  #|Mjfd8MFiNdNJFzIwHwYDVR0jBBgwFoAUN2Y9yhOysJWTMjfd8MFiNdNJFzIwDwYD
  #|VR0TAQH/BAUwAwEB/zAVBgNVHREEDjAMggp0d28ud2J0ZXN0MAoGCCqGSM49BAMC
  #|A0gAMEUCIEXkdFb2Z/Nslom2ApU1M5QqdvAnWcXQckudXyi3PUr9AiEA9ajVEwMy
  #|siMwsV/PIVvC3KGPNgJZF93eLybjI15hz0Y=
  #|-----END CERTIFICATE-----

///|
/// The extensions a request carries, for the anchors it is given and the compression it is set to.
fn request_for(
  anchors : Array[String],
  compress~ : Bool = true,
) -> Array[@ext.Ext] raise {
  request_extensions(
    ClientAuth::new(
      mode=Requested,
      roots=@x509.Roots::new(certs=anchors.map(@x509.pem)[:]),
    ),
    compress~,
    compressions=[@ext.zlib_compression],
  )
}

///|
test "client auth: the request takes compressed certificates whether or not the client offered" {
  // RFC 8879 §3: the extension in a CertificateRequest is what the server can decompress, and it is
  // independent of the client's own offer — a client that never asked to receive a compressed
  // Certificate may still send one.
  guard @ext.find(request_for([])[:], CompressCertificate) is Some(e) else {
    fail("the request named no algorithm")
  }
  assert_eq(@ext.read_compression_algorithms(e.data[:]), Some([1]))
}

///|
test "client auth: one anchor is not a choice, so the request does not name it" {
  // §4.4.2.2 makes the acceptable authorities optional, and a single anchor decides nothing: a
  // client either chains to it or does not.
  assert_true(
    @ext.find(request_for([wbtest_cert])[:], CertificateAuthorities) is None,
  )
}

///|
test "client auth: two anchors are named, so a client with several chains can pick" {
  guard @ext.find(
      request_for([wbtest_cert, wbtest_other])[:],
      CertificateAuthorities,
    )
    is Some(e) else {
    fail("the request named no authority")
  }
  assert_eq(@ext.read_authorities(e.data[:]).unwrap().length(), 2)
}
