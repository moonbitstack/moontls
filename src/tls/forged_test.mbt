///|
/// A server played by hand, so a test can send the client a flight the real server never would.
/// The certificate is not checked (`Custom` accepts anything), which leaves the handshake's own
/// rules as the only thing standing between the client and a forged flight.
struct Forged {
  client : @tls.Conn
  transcript : @keys.Transcript
  secret : Bytes
  writer : @record.Cipher
}

///|
/// A client that has read a genuine ServerHello for X25519 and AES-128-GCM, waiting for the
/// encrypted flight. `after` is put in the same record as the ServerHello, and `tweak` changes
/// the ServerHello before it is sent.
fn forged(
  after? : Bytes,
  tweak? : (@msg.Server) -> @msg.Server,
) -> Forged raise {
  let config = @tls.Client::new(
    @x509.Roots::new(),
    suites=[Aes128Gcm],
    groups=[@ext.x25519],
    verify=Custom((_, _) => ()),
  )
  let client = @tls.Conn::client(config, "a.example", rand=rng(7), now~)
  let ch = client.take()[5:].to_owned()
  guard @msg.read_hello(ch[4:]) is Some(hello) &&
    @ext.find(hello.extensions[:], KeyShare) is Some(ks) &&
    @ext.read_shares(ks.data[:]) is Some([(_, peer), ..]) else {
    fail("no X25519 share in the ClientHello")
  }
  let mine = Bytes::make(32, b'\x42')
  let public = @x25519.public(mine[:])
  let genuine = @hs.server_hello(
    Bytes::make(32, b'\x01')[:],
    hello.session_id[:],
    @record.Suite::Aes128Gcm.code(),
    extensions=[
        @ext.Ext::{
          kind: KeyShare,
          data: @ext.selected_share(@ext.x25519, public[:]),
        },
      ][:],
  )
  let sh = @msg.server_hello(
    match tweak {
      Some(f) => f(genuine)
      None => genuine
    },
  )
  let transcript = @keys.Transcript::new(digest=Sha256)
  transcript.add(ch[:])
  transcript.add(sh[:])
  let shared = @x25519.shared(mine[:], peer[:])
  let hs = @keys.handshake(
    @keys.early(digest=Sha256)[:],
    shared[:],
    digest=Sha256,
  )
  let secret = @keys.server_handshake(
    hs[:],
    transcript.hash()[:],
    digest=Sha256,
  )
  let first = match after {
    Some(more) => sh + more
    None => sh
  }
  client.receive(@record.encode(Handshake, first[:])[:])
  {
    client,
    transcript,
    secret,
    writer: @record.Cipher::new(secret[:], suite=Aes128Gcm),
  }
}

///|
/// Seal one handshake message to the client, adding it to the transcript.
fn Forged::send(self : Forged, message : Bytes) -> Unit raise {
  self.transcript.add(message[:])
  self.client.receive(self.writer.seal(Handshake, message[:])[:])
}

///|
/// A correct server Finished over the transcript so far.
fn Forged::finished(self : Forged) -> Bytes {
  @msg.frame(
    Finished,
    @keys.finished(self.secret[:], self.transcript.hash()[:], digest=Sha256)[:],
  )
}

///|
fn ee() -> Bytes {
  @msg.frame(EncryptedExtensions, @msg.encrypted_extensions([][:])[:])
}

///|
fn cert() -> Bytes {
  @msg.frame(Certificate, @msg.certificate([b"\x30\x00"][:])[:])
}

///|
fn request() -> Bytes {
  @msg.frame(CertificateRequest, b"\x00\x00\x00"[:])
}

///|
/// The alert `steps` end in; fails when they go through.
fn alert_of(steps : () -> Unit raise) -> @alert.Kind raise {
  try steps() catch {
    @alert.Alert(kind~, ..) => kind
    e => raise e
  } noraise {
    _ => fail("the client went along with a forged flight")
  }
}

///|
test "forged: a flight without CertificateVerify is refused" {
  let f = forged()
  let kind = alert_of(() => {
    f.send(ee())
    f.send(cert())
    f.send(f.finished())
  })
  assert_eq(kind, UnexpectedMessage)
  assert_false(f.client.is_connected())
}

///|
test "forged: a Certificate before EncryptedExtensions is refused" {
  let f = forged()
  assert_eq(alert_of(() => f.send(cert())), UnexpectedMessage)
}

///|
test "forged: a Finished with no certificate at all is refused" {
  let f = forged()
  let kind = alert_of(() => {
    f.send(ee())
    f.send(f.finished())
  })
  assert_eq(kind, UnexpectedMessage)
}

///|
test "forged: a second Certificate is refused" {
  let f = forged()
  let kind = alert_of(() => {
    f.send(ee())
    f.send(cert())
    f.send(cert())
  })
  assert_eq(kind, UnexpectedMessage)
}

///|
test "forged: a CertificateRequest after the Certificate is refused" {
  let f = forged()
  let kind = alert_of(() => {
    f.send(ee())
    f.send(cert())
    f.send(request())
  })
  assert_eq(kind, UnexpectedMessage)
}

///|
test "forged: a second EncryptedExtensions is refused" {
  let f = forged()
  let kind = alert_of(() => {
    f.send(ee())
    f.send(ee())
  })
  assert_eq(kind, UnexpectedMessage)
}

///|
test "forged: a message sharing the ServerHello's record is refused" {
  // RFC 8446 §5.1: handshake messages may not span a key change, and the ServerHello is one.
  assert_eq(alert_of(() => forged(after=ee()) |> ignore), UnexpectedMessage)
}

///|
test "forged: a change_cipher_spec that is not the single octet 1 is refused" {
  let f = forged()
  let bad = @record.encode(ChangeCipherSpec, b"\x02"[:])
  assert_eq(alert_of(() => f.client.receive(bad[:])), UnexpectedMessage)
  let g = forged()
  let ccs = @record.encode(ChangeCipherSpec, b"\x01"[:])
  g.client.receive(ccs[:])
  g.send(ee())
  assert_eq(alert_of(() => g.client.receive(ccs[:])), UnexpectedMessage)
}

///|
fn with_ext(sh : @msg.Server, kind : @ext.Kind, data : Bytes) -> @msg.Server {
  { ..sh, extensions: sh.extensions + [{ kind, data, }], }
}

///|
fn ee_with(exts : Array[@ext.Ext]) -> Bytes {
  @msg.frame(EncryptedExtensions, @msg.encrypted_extensions(exts[:])[:])
}

///|
test "forged: a ServerHello with a compression method or another legacy_version is refused" {
  let bad = [
    (sh : @msg.Server) => { ..sh, compression: 1, },
    (sh : @msg.Server) => { ..sh, version: 0x0304, },
  ]
  for tweak in bad {
    assert_eq(alert_of(() => forged(tweak~) |> ignore), IllegalParameter)
  }
}

///|
test "forged: an extension the client never offered, or offered for another message" {
  let psk = (sh : @msg.Server) => with_ext(sh, Other(41), b"\x00\x00")
  assert_eq(alert_of(() => forged(tweak=psk) |> ignore), UnsupportedExtension)
  let alpn = (sh : @msg.Server) => with_ext(sh, Alpn, @ext.protocols(["h2"][:]))
  assert_eq(alert_of(() => forged(tweak=alpn) |> ignore), IllegalParameter)
  let f = forged()
  let share = @ext.Ext::{ kind: KeyShare, data: b"\x00\x1d\x00\x01\x01", }
  assert_eq(alert_of(() => f.send(ee_with([share]))), IllegalParameter)
  let g = forged()
  let unknown = @ext.Ext::{ kind: Other(0xfafa), data: b"", }
  assert_eq(alert_of(() => g.send(ee_with([unknown]))), UnsupportedExtension)
}

///|
test "forged: an extension twice in EncryptedExtensions is a decode_error" {
  let f = forged()
  let groups = @ext.Ext::{
    kind: SupportedGroups,
    data: @ext.groups([0x001d][:]),
  }
  assert_eq(alert_of(() => f.send(ee_with([groups, groups]))), DecodeError)
}

///|
test "forged: a Certificate with a request context is refused" {
  let f = forged()
  let kind = alert_of(() => {
    f.send(ee())
    f.send(
      @msg.frame(
        Certificate,
        @msg.certificate([b"\x30\x00"][:], context=b"\x01"[:])[:],
      ),
    )
  })
  assert_eq(kind, IllegalParameter)
}

///|
test "forged: a CertificateVerify under a scheme the client did not offer" {
  let f = forged()
  let kind = alert_of(() => {
    f.send(ee())
    f.send(cert())
    f.send(
      @msg.frame(
        CertificateVerify,
        @msg.certificate_verify(b"\x00"[:], 0x0201)[:],
      ),
    )
  })
  assert_eq(kind, IllegalParameter)
}
