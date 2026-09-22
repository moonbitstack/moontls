// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A client's handshake state (RFC 8446 Appendix A.1), after the ClientHello
/// has been sent.
///
/// Sending the ClientHello is the client's own action, not a received message,
/// so `START` is not a state here — a client that has not sent one has no
/// handshake to be in.
pub(all) enum Client {
  WaitServerHello
  WaitEncryptedExtensions
  WaitCertOrRequest
  WaitCert
  WaitCertVerify
  WaitFinished
  Connected
} derive(Eq, Debug)

///|
pub extend Client with Eq::{equal, not_equal}

///|
pub extend Client with Debug::{to_repr}

///|
/// The state a client is in having just sent its ClientHello.
pub fn Client::new() -> Client {
  WaitServerHello
}

///|
/// The next client state on receiving a message of `kind` (RFC 8446 A.1).
///
/// A message that does not belong in the current state raises
/// `UnexpectedMessage` (§6.2) — which is what the peer is owed, rather than
/// being ignored into an ambiguous state.
pub fn Client::recv(
  self : Client,
  kind : @msg.Kind,
) -> Client raise @alert.Alert {
  match (self, kind) {
    (WaitServerHello, ServerHello) => WaitEncryptedExtensions
    (WaitEncryptedExtensions, EncryptedExtensions) => WaitCertOrRequest
    // After EncryptedExtensions the server may ask for a client certificate,
    // or send its own straight away.
    (WaitCertOrRequest, CertificateRequest) => WaitCert
    (WaitCertOrRequest, Certificate) => WaitCertVerify
    (WaitCert, Certificate) => WaitCertVerify
    (WaitCertVerify, CertificateVerify) => WaitFinished
    (WaitFinished, Finished) => Connected
    _ => raise @alert.fatal(UnexpectedMessage)
  }
}

///|
/// A server's handshake state (RFC 8446 Appendix A.2).
pub(all) enum Server {
  Start
  RecvdClientHello
  WaitCert
  WaitCertVerify
  WaitFinished
  Connected
} derive(Eq, Debug)

///|
pub extend Server with Eq::{equal, not_equal}

///|
pub extend Server with Debug::{to_repr}

///|
/// The state a server is in awaiting the ClientHello.
pub fn Server::new() -> Server {
  Start
}

///|
/// The next server state on receiving a message of `kind` (RFC 8446 A.2): the
/// ClientHello that opens the handshake, then the client's second flight.
pub fn Server::recv(
  self : Server,
  kind : @msg.Kind,
) -> Server raise @alert.Alert {
  match (self, kind) {
    (Start, ClientHello) => RecvdClientHello
    (WaitCert, Certificate) => WaitCertVerify
    (WaitCertVerify, CertificateVerify) => WaitFinished
    (WaitFinished, Finished) => Connected
    _ => raise @alert.fatal(UnexpectedMessage)
  }
}

///|
/// The server's own move after the ClientHello: it negotiates and sends its
/// whole flight, then waits for the client's Certificate when one was asked
/// for, or straight for the client's Finished.
///
/// Sending the flight in any other state is this endpoint's bug and not the
/// peer's, so it raises `InternalError` rather than an alert that blames the
/// other side.
pub fn Server::sent_flight(
  self : Server,
  client_cert? : Bool = false,
) -> Server raise @alert.Alert {
  match self {
    RecvdClientHello => if client_cert { WaitCert } else { WaitFinished }
    _ => raise @alert.fatal(InternalError)
  }
}

// ----------------------------------------------------------------- negotiation

///|
/// The named groups this build can run a key exchange for.
///
/// x25519 alone: offering a group the key exchange cannot honour would be a lie
/// the handshake discovers too late. It is a parameter on [`negotiate`] rather
/// than a fixed list, so a build with more groups says so.
pub let groups : Array[Int] = [@ext.x25519]

///|
/// The signature schemes this build can verify a CertificateVerify under.
pub let schemes : Array[Int] = [@ext.ecdsa_secp256r1_sha256]

///|
/// The x25519 public key length (RFC 7748 §5): a Montgomery-u coordinate.
let x25519_size : Int = 32

///|
/// What a server settled on after reading a ClientHello.
pub(all) enum Choice {
  /// The client offered a group this build runs and a key share for it: the
  /// group, the client's public key, and the scheme its CertificateVerify will
  /// be signed under.
  Chosen(group~ : Int, key~ : Bytes, scheme~ : Int)
  /// The client offered a group this build runs but no key share for it, so it
  /// has to send the ClientHello again with one (RFC 8446 §4.1.4).
  Retry(Int)
} derive(Eq, Debug)

///|
pub extend Choice with Eq::{equal, not_equal}

///|
pub extend Choice with Debug::{to_repr}

///|
/// The first of `offered` that also appears in `ours`, honouring the client's
/// preference order as RFC 8446 §4.2.7 allows a server to.
fn first_common(offered : ArrayView[Int], ours : ArrayView[Int]) -> Int? {
  offered.iter().find_first(fn(v) { ours.iter().any(fn(o) { o == v }) })
}

///|
/// Negotiate a decoded ClientHello (RFC 8446 §4.1.1).
///
/// Checks it offers TLS 1.3, picks the first group and signature scheme it
/// lists that this build runs, and takes its key share for the chosen group.
/// Raises the alert §6 names for each way that fails — a missing mandatory
/// extension, a client that does not speak 1.3, nothing in common, or a key
/// share contradicting the rest of the message — and answers `Retry` when the
/// chosen group is one the client offered but sent no share for.
///
/// `groups` and `schemes` are what this endpoint can do; they default to what
/// this build implements.
pub fn negotiate(
  ch : @msg.Hello,
  groups? : ArrayView[Int] = groups[:],
  schemes? : ArrayView[Int] = schemes[:],
) -> Choice raise @alert.Alert {
  // §9.2: a ClientHello missing any of these cannot be a 1.3 handshake at all.
  for
    required in [
      @ext.Kind::SupportedVersions,
      @ext.Kind::SupportedGroups,
      @ext.Kind::SignatureAlgorithms,
      @ext.Kind::KeyShare,
    ] {
    guard @ext.find(ch.extensions[:], required) is Some(_) else {
      raise @alert.fatal(MissingExtension)
    }
  }
  guard @ext.find(ch.extensions[:], SupportedVersions) is Some(versions) else {
    raise @alert.fatal(MissingExtension)
  }
  if !@ext.read_versions(versions.data[:]).contains(@ext.version_13) {
    raise @alert.fatal(ProtocolVersion)
  }
  guard @ext.find(ch.extensions[:], SupportedGroups) is Some(offered) else {
    raise @alert.fatal(MissingExtension)
  }
  let offered_groups = @ext.read_groups(offered.data[:])
  guard first_common(offered_groups[:], groups) is Some(group) else {
    raise @alert.fatal(HandshakeFailure)
  }
  guard @ext.find(ch.extensions[:], SignatureAlgorithms) is Some(sig) else {
    raise @alert.fatal(MissingExtension)
  }
  guard first_common(@ext.read_schemes(sig.data[:])[:], schemes) is Some(scheme) else {
    raise @alert.fatal(HandshakeFailure)
  }
  guard @ext.find(ch.extensions[:], KeyShare) is Some(shares_ext) else {
    raise @alert.fatal(MissingExtension)
  }
  let shares = @ext.read_shares(shares_ext.data[:])
  // §4.2.8: a share for a group the client did not list in supported_groups
  // contradicts its own offer, and a server that notices must say so rather
  // than quietly use it.
  for s in shares {
    if !offered_groups.contains(s.0) {
      raise @alert.fatal(IllegalParameter)
    }
  }
  match shares.iter().find_first(fn(s) { s.0 == group }) {
    Some((_, key)) => {
      if group == @ext.x25519 && key.length() != x25519_size {
        raise @alert.fatal(IllegalParameter)
      }
      Chosen(group~, key~, scheme~)
    }
    // §4.1.4: the group is usable and only the share is missing — worth one
    // more round trip.
    None => Retry(group)
  }
}

///|
/// Negotiate a raw ClientHello handshake message: unframe it, decode it, and
/// run [`negotiate`].
///
/// A message that is not a well-formed ClientHello raises `DecodeError` (§6.2)
/// rather than vanishing into a `None`.
pub fn negotiate_message(
  message : BytesView,
  groups? : ArrayView[Int] = groups[:],
  schemes? : ArrayView[Int] = schemes[:],
) -> Choice raise @alert.Alert {
  guard @msg.unframe(message) is Some((kind, body)) else {
    raise @alert.fatal(DecodeError)
  }
  if kind != ClientHello {
    raise @alert.fatal(UnexpectedMessage)
  }
  guard @msg.read_hello(body[:]) is Some(ch) else {
    raise @alert.fatal(DecodeError)
  }
  negotiate(ch, groups~, schemes~)
}

///|
/// A ServerHello answering a negotiated ClientHello (RFC 8446 §4.1.3).
///
/// The `supported_versions` extension naming TLS 1.3 is prepended, because
/// §4.1.3 puts the negotiated version there rather than in the message's frozen
/// `legacy_version`.
pub fn server_hello(
  random : BytesView,
  session_id : BytesView,
  suite : Int,
  extensions? : ArrayView[@ext.Ext] = [][:],
) -> @msg.Server {
  let exts : Array[@ext.Ext] = [
    { kind: SupportedVersions, data: @ext.selected_version(@ext.version_13), },
  ]
  for e in extensions {
    exts.push(e)
  }
  {
    random: random.to_owned(),
    session_id: session_id.to_owned(),
    suite,
    extensions: exts,
  }
}

// ------------------------------------------------------------- hello retry

///|
/// The `ServerHello.random` that marks a HelloRetryRequest (RFC 8446 §4.1.3):
/// the SHA-256 of `"HelloRetryRequest"`.
///
/// A HelloRetryRequest travels as a ServerHello — same type, same framing —
/// distinguished only by this sentinel, so a receiver must compare against it
/// before reading the message as a real ServerHello. One that does not will try
/// a key exchange against a `key_share` carrying no key.
pub let retry_random : Bytes = b"\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c"

///|
/// A HelloRetryRequest's `key_share` payload (RFC 8446 §4.2.8): the selected
/// group alone. There is no key — asking for one is the whole point.
pub fn retry_share(group : Int) -> Bytes {
  let out = Buffer()
  @wire.u16(out, group)
  out.to_bytes()
}

///|
/// The group such a payload names, or `None` if it is not two octets.
pub fn read_retry_share(view : BytesView) -> Int? {
  if view.length() != 2 {
    return None
  }
  Some(@wire.read_u16(view, 0))
}

///|
/// A HelloRetryRequest asking the client to come back with a key share for
/// `group` (RFC 8446 §4.1.4): the sentinel random, the client's `session_id`
/// echoed back untouched, the chosen suite, `supported_versions`, and the
/// group.
///
/// It encodes through `@msg.server_hello` like any other ServerHello.
pub fn retry(session_id : BytesView, suite : Int, group : Int) -> @msg.Server {
  let share : @ext.Ext = { kind: KeyShare, data: retry_share(group), }
  server_hello(retry_random[:], session_id, suite, extensions=[share][:])
}

///|
/// Whether a ServerHello is really a HelloRetryRequest.
pub fn is_retry(sh : @msg.Server) -> Bool {
  sh.random == retry_random
}

///|
/// The group a HelloRetryRequest asks for a share of, or `None` if the message
/// is an ordinary ServerHello or carries no `key_share`.
pub fn retry_group(sh : @msg.Server) -> Int? {
  if !is_retry(sh) {
    return None
  }
  match @ext.find(sh.extensions[:], KeyShare) {
    Some(e) => read_retry_share(e.data[:])
    None => None
  }
}

// ------------------------------------------------------------------ the driver

///|
/// A server-side handshake in progress.
///
/// It drives the state machine over a byte stream: [`Handshake::feed`] appends
/// received octets, splits off every complete message, adds each to the running
/// transcript and advances the state, buffering a trailing partial message for
/// the next feed. The server's own flight folds in through
/// [`Handshake::sent`], so the transcript stays in message order.
///
/// A pure core: no keys and no socket. Whoever has those wraps it.
pub struct Handshake {
  mut state : Server
  transcript : @keys.Transcript
  mut buffered : Bytes
  mut hello : Bytes
}

///|
/// A fresh handshake, awaiting the ClientHello.
pub fn Handshake::new(digest? : @keys.Digest = @keys.digest) -> Handshake {
  {
    state: Start,
    transcript: @keys.Transcript::new(digest~),
    buffered: b"",
    hello: b"",
  }
}

///|
/// The state the handshake is in.
pub fn Handshake::state(self : Handshake) -> Server {
  self.state
}

///|
/// Whether the handshake has completed.
pub fn Handshake::is_connected(self : Handshake) -> Bool {
  self.state == Connected
}

///|
/// The transcript hash over every message seen so far, in order.
pub fn Handshake::transcript(self : Handshake) -> Bytes {
  self.transcript.hash()
}

///|
/// The raw ClientHello the handshake received, empty until one arrives.
///
/// A server needs it to pull the client's `key_share` and run the ECDHE the
/// handshake secrets come from.
pub fn Handshake::hello(self : Handshake) -> Bytes {
  self.hello
}

///|
/// Negotiate the ClientHello this handshake received.
///
/// Raises `DecodeError` before one has arrived at all, which is what an empty
/// message decodes to.
pub fn Handshake::negotiate(
  self : Handshake,
  groups? : ArrayView[Int] = groups[:],
  schemes? : ArrayView[Int] = schemes[:],
) -> Choice raise @alert.Alert {
  negotiate_message(self.hello[:], groups~, schemes~)
}

///|
/// Feed received octets: process every complete handshake message now
/// available — add it to the transcript and advance the state — buffering any
/// trailing partial message. Answers the message types processed, in order.
pub fn Handshake::feed(
  self : Handshake,
  octets : BytesView,
) -> Array[@msg.Kind] raise @alert.Alert {
  let joined = Buffer()
  joined.write_bytes(self.buffered)
  joined.write_bytesview(octets)
  let all = joined.to_bytes()
  let processed : Array[@msg.Kind] = []
  let mut at = 0
  for ;; {
    match @msg.unframe(all[at:]) {
      Some((kind, body)) => {
        let used = 4 + body.length()
        let message = all[at:at + used].to_owned()
        if kind == ClientHello {
          self.hello = message
        }
        self.transcript.add(message[:])
        self.state = self.state.recv(kind)
        processed.push(kind)
        at = at + used
      }
      None => break
    }
  }
  self.buffered = all[at:].to_owned()
  processed
}

///|
/// Fold a message the server sends — ServerHello, EncryptedExtensions,
/// Certificate and the rest — into the transcript, keeping message order.
pub fn Handshake::sent(self : Handshake, message : BytesView) -> Unit {
  self.transcript.add(message)
}

///|
/// Advance the state past the server's own flight, waiting for a client
/// certificate when one was asked for.
pub fn Handshake::sent_flight(
  self : Handshake,
  client_cert? : Bool = false,
) -> Unit raise @alert.Alert {
  self.state = self.state.sent_flight(client_cert~)
}
