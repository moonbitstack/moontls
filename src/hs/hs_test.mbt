// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The state machine, the negotiation and the driver. Every refusal asserts the
// alert RFC 8446 §6 names for it, because which alert a peer gets is the only
// diagnostic it has.

///|
fn random() -> Bytes {
  Bytes::make(32, b'\x11')
}

///|
fn key() -> Bytes {
  Bytes::from_array(Array::makei(32, fn(i) { i.to_byte() }))
}

///|
/// A ClientHello offering everything this build runs.
fn good_hello() -> @msg.Hello {
  {
    random: random(),
    session_id: b"",
    suites: [0x1301],
    extensions: [
      { kind: SupportedVersions, data: @ext.versions([@ext.version_13][:]), },
      { kind: SupportedGroups, data: @ext.groups([@ext.x25519][:]), },
      {
        kind: SignatureAlgorithms,
        data: @ext.schemes([@ext.ecdsa_secp256r1_sha256][:]),
      },
      { kind: KeyShare, data: @ext.shares([(@ext.x25519, key())][:]), },
    ],
  }
}

///|
/// The same, with one extension replaced or dropped.
fn hello_without(kind : @ext.Kind) -> @msg.Hello {
  let ch = good_hello()
  { ..ch, extensions: ch.extensions.filter(fn(e) { e.kind != kind }), }
}

///|
fn hello_with(kind : @ext.Kind, data : Bytes) -> @msg.Hello {
  let ch = hello_without(kind)
  ch.extensions.push({ kind, data, })
  ch
}

///|
/// The alert a thunk raises, or `CloseNotify` if it does not raise at all.
fn refusal(run : () -> Unit raise @alert.Alert) -> @alert.Kind {
  try {
    run()
    @alert.Kind::CloseNotify
  } catch {
    Alert(kind~, ..) => kind
  }
}

///|
test "a client walks A.1 and refuses anything out of order" {
  let start = @hs.Client::new()
  assert_eq(start, @hs.Client::WaitServerHello)
  let after_sh = start.recv(ServerHello)
  assert_eq(after_sh, @hs.Client::WaitEncryptedExtensions)
  let after_ee = after_sh.recv(EncryptedExtensions)
  assert_eq(after_ee, @hs.Client::WaitCertOrRequest)
  // Straight to the server's Certificate.
  let after_cert = after_ee.recv(Certificate)
  assert_eq(after_cert, @hs.Client::WaitCertVerify)
  let after_cv = after_cert.recv(CertificateVerify)
  assert_eq(after_cv, @hs.Client::WaitFinished)
  assert_eq(after_cv.recv(Finished), @hs.Client::Connected)
  // Or through a CertificateRequest first.
  assert_eq(after_ee.recv(CertificateRequest), @hs.Client::WaitCert)
  assert_eq(
    after_ee.recv(CertificateRequest).recv(Certificate),
    @hs.Client::WaitCertVerify,
  )
}

///|
test "a message out of order is unexpected_message, not silence" {
  assert_eq(
    refusal(() => @hs.Client::new().recv(Finished) |> ignore),
    @alert.Kind::UnexpectedMessage,
  )
  assert_eq(
    refusal(() => @hs.Client::new().recv(ClientHello) |> ignore),
    @alert.Kind::UnexpectedMessage,
  )
  // Connected accepts nothing more through this transition.
  assert_eq(
    refusal(() => @hs.Client::Connected.recv(Finished) |> ignore),
    @alert.Kind::UnexpectedMessage,
  )
  // A type with no codec is as out of order as any other.
  assert_eq(
    refusal(() => @hs.Client::new().recv(Other(99)) |> ignore),
    @alert.Kind::UnexpectedMessage,
  )
}

///|
test "a server walks A.2, and its own flight is its own move" {
  let start = @hs.Server::new()
  assert_eq(start, @hs.Server::Start)
  let got_hello = start.recv(ClientHello)
  assert_eq(got_hello, @hs.Server::RecvdClientHello)
  // Without asking for a client certificate it waits for Finished.
  assert_eq(got_hello.sent_flight(), @hs.Server::WaitFinished)
  assert_eq(got_hello.sent_flight().recv(Finished), @hs.Server::Connected)
  // Asking for one adds the client's Certificate and CertificateVerify.
  let asked = got_hello.sent_flight(client_cert=true)
  assert_eq(asked, @hs.Server::WaitCert)
  assert_eq(asked.recv(Certificate), @hs.Server::WaitCertVerify)
  assert_eq(
    asked.recv(Certificate).recv(CertificateVerify),
    @hs.Server::WaitFinished,
  )
}

///|
/// Sending the flight in the wrong state is this endpoint's bug, so it blames
/// itself with internal_error rather than the peer.
test "sending the flight too early is internal_error" {
  assert_eq(
    refusal(() => @hs.Server::new().sent_flight() |> ignore),
    @alert.Kind::InternalError,
  )
  assert_eq(
    refusal(() => @hs.Server::Connected.sent_flight() |> ignore),
    @alert.Kind::InternalError,
  )
}

///|
test "a well-formed ClientHello negotiates to a group, a key and a scheme" {
  guard @hs.negotiate(good_hello()) is Chosen(group~, key=shared, scheme~) else {
    fail("a complete ClientHello should negotiate")
  }
  assert_eq(group, @ext.x25519)
  assert_eq(shared, key())
  assert_eq(scheme, @ext.ecdsa_secp256r1_sha256)
}

///|
/// RFC 8446 §9.2: four extensions are mandatory, and one missing means this was
/// never a 1.3 handshake.
test "each mandatory extension missing is missing_extension" {
  for
    kind in [
      @ext.Kind::SupportedVersions,
      @ext.Kind::SupportedGroups,
      @ext.Kind::SignatureAlgorithms,
      @ext.Kind::KeyShare,
    ] {
    assert_eq(
      refusal(() => @hs.negotiate(hello_without(kind)) |> ignore),
      @alert.Kind::MissingExtension,
    )
  }
}

///|
test "a client that does not offer 1.3 is protocol_version" {
  assert_eq(
    refusal(() => {
      @hs.negotiate(hello_with(SupportedVersions, @ext.versions([0x0303][:])))
      |> ignore
    }),
    @alert.Kind::ProtocolVersion,
  )
}

///|
test "nothing in common is handshake_failure" {
  // A group this build does not run.
  assert_eq(
    refusal(() => {
      @hs.negotiate(hello_with(SupportedGroups, @ext.groups([0x0017][:])))
      |> ignore
    }),
    @alert.Kind::HandshakeFailure,
  )
  // A signature scheme it cannot verify.
  assert_eq(
    refusal(() => {
      @hs.negotiate(hello_with(SignatureAlgorithms, @ext.schemes([0x0804][:])))
      |> ignore
    }),
    @alert.Kind::HandshakeFailure,
  )
}

///|
/// §4.2.8: a share for a group the client never listed contradicts its own
/// offer, and a server that notices must say so rather than quietly use it.
test "a key share for an unoffered group is illegal_parameter" {
  assert_eq(
    refusal(() => {
      @hs.negotiate(hello_with(KeyShare, @ext.shares([(0x0017, key())][:])))
      |> ignore
    }),
    @alert.Kind::IllegalParameter,
  )
  // An x25519 share that is not 32 octets is not an x25519 share.
  assert_eq(
    refusal(() => {
      @hs.negotiate(
        hello_with(KeyShare, @ext.shares([(@ext.x25519, b"short")][:])),
      )
      |> ignore
    }),
    @alert.Kind::IllegalParameter,
  )
}

///|
/// §4.1.4: the group is usable and only the share is missing — one more round
/// trip, not a failure.
test "a usable group with no share asks for a retry" {
  let ch = hello_with(KeyShare, @ext.shares([][:]))
  guard @hs.negotiate(ch) is Retry(group) else {
    fail("a missing share for a usable group should retry")
  }
  assert_eq(group, @ext.x25519)
}

///|
/// The endpoint's own capabilities are parameters: a build that runs another
/// group says so and negotiates it.
test "groups and schemes are parameters" {
  let ch = hello_with(SupportedGroups, @ext.groups([0x0017, @ext.x25519][:]))
  // With only P-256 on our side, that is what gets chosen — and it has no
  // share, so it retries.
  guard @hs.negotiate(ch, groups=[0x0017][:]) is Retry(group) else {
    fail("P-256 was offered first")
  }
  assert_eq(group, 0x0017)
  // With our default list it picks x25519, which does have a share.
  guard @hs.negotiate(ch) is Chosen(group=chosen, ..) else {
    fail("x25519 was offered and shared")
  }
  assert_eq(chosen, @ext.x25519)
}

///|
test "a raw ClientHello message negotiates, and anything else does not" {
  let message = @msg.hello(good_hello())
  guard @hs.negotiate_message(message[:]) is Chosen(..) else {
    fail("the message should negotiate")
  }
  // A ServerHello is not a ClientHello.
  let sh = @msg.server_hello({
    random: random(),
    session_id: b"",
    suite: 0x1301,
    extensions: [],
  })
  assert_eq(
    refusal(() => @hs.negotiate_message(sh[:]) |> ignore),
    @alert.Kind::UnexpectedMessage,
  )
  // Nothing at all, or a truncated message, is a decode_error.
  assert_eq(
    refusal(() => @hs.negotiate_message(b""[:]) |> ignore),
    @alert.Kind::DecodeError,
  )
  assert_eq(
    refusal(() => @hs.negotiate_message(message[0:10]) |> ignore),
    @alert.Kind::DecodeError,
  )
}

///|
test "a ServerHello answers with the negotiated version in the extension" {
  let sh = @hs.server_hello(random()[:], b"sid"[:], 0x1301)
  assert_eq(sh.suite, 0x1301)
  assert_eq(sh.session_id, b"sid")
  guard @ext.find(sh.extensions[:], SupportedVersions) is Some(v) else {
    fail("§4.1.3 puts the negotiated version in the extension")
  }
  assert_eq(@ext.read_selected_version(v.data[:]), Some(@ext.version_13))
}

///|
/// A HelloRetryRequest is a ServerHello with a sentinel random, so a receiver
/// that does not compare against it will run a key exchange against a key_share
/// carrying no key.
test "a HelloRetryRequest is a ServerHello with the sentinel random" {
  let hrr = @hs.retry(b"sid"[:], 0x1301, @ext.x25519)
  assert_eq(@hs.is_retry(hrr), true)
  assert_eq(@hs.retry_group(hrr), Some(@ext.x25519))
  assert_eq(hrr.random, @hs.retry_random)
  assert_eq(hrr.random.length(), 32)
  // Its key_share names a group and carries no key.
  guard @ext.find(hrr.extensions[:], KeyShare) is Some(ks) else {
    fail("a HelloRetryRequest names the group it wants")
  }
  assert_eq(ks.data.length(), 2)
  assert_eq(@hs.read_retry_share(ks.data[:]), Some(@ext.x25519))
  // An ordinary ServerHello is not one.
  let plain = @hs.server_hello(random()[:], b"sid"[:], 0x1301)
  assert_eq(@hs.is_retry(plain), false)
  assert_eq(@hs.retry_group(plain), None)
}

///|
test "the driver splits messages, keeps the transcript and advances the state" {
  let hs = @hs.Handshake::new()
  assert_eq(hs.state(), @hs.Server::Start)
  assert_eq(hs.is_connected(), false)
  assert_eq(hs.hello(), b"")
  let message = @msg.hello(good_hello())
  let seen = hs.feed(message[:])
  assert_eq(seen, [@msg.Kind::ClientHello])
  assert_eq(hs.state(), @hs.Server::RecvdClientHello)
  assert_eq(hs.hello(), message)
  // The transcript is the hash of the messages in order.
  assert_eq(hs.transcript(), @keys.digest.hash(message[:]))
  // And it negotiates what it received.
  guard hs.negotiate() is Chosen(group~, ..) else {
    fail("it should negotiate")
  }
  assert_eq(group, @ext.x25519)
}

///|
/// A message split across feeds is one message, not two halves discarded.
test "a partial message is buffered until the rest arrives" {
  let hs = @hs.Handshake::new()
  let message = @msg.hello(good_hello())
  let half = message.length() / 2
  assert_eq(hs.feed(message[0:half]), [])
  assert_eq(hs.state(), @hs.Server::Start)
  assert_eq(hs.feed(message[half:]), [@msg.Kind::ClientHello])
  assert_eq(hs.state(), @hs.Server::RecvdClientHello)
  assert_eq(hs.hello(), message)
  assert_eq(hs.transcript(), @keys.digest.hash(message[:]))
}

///|
test "the server's own flight folds into the transcript in order" {
  let hs = @hs.Handshake::new()
  let ch = @msg.hello(good_hello())
  let _ = hs.feed(ch[:])
  let sh = @msg.server_hello({
    random: random(),
    session_id: b"",
    suite: 0x1301,
    extensions: [],
  })
  hs.sent(sh[:])
  let both = Buffer()
  both.write_bytes(ch)
  both.write_bytes(sh)
  assert_eq(hs.transcript(), @keys.digest.hash(both.to_bytes()[:]))
  hs.sent_flight()
  assert_eq(hs.state(), @hs.Server::WaitFinished)
  let fin = @msg.frame(Finished, b"verify"[:])
  assert_eq(hs.feed(fin[:]), [@msg.Kind::Finished])
  assert_eq(hs.is_connected(), true)
}

///|
test "two messages in one feed are both processed, in order" {
  let hs = @hs.Handshake::new()
  let ch = @msg.hello(good_hello())
  let _ = hs.feed(ch[:])
  hs.sent_flight()
  // The client's Finished arrives glued to nothing else it may send.
  let joined = Buffer()
  joined.write_bytes(@msg.frame(Finished, b"verify"[:]))
  assert_eq(hs.feed(joined.to_bytes()[:]), [@msg.Kind::Finished])
  assert_eq(hs.state(), @hs.Server::Connected)
}
