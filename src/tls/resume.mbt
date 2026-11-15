// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// TLS 1.3 resumption (RFC 8446 §4.6.1, §4.2.11, §4.5): a ticket a server hands out, a
// pre_shared_key a client offers back, the binder that ties the two to this handshake, and the
// 0-RTT data a resumption may carry before the handshake completes.

///|
/// The session this client would offer for `host`, out of the store its configuration names.
fn Conn::pick_session(
  self : Conn,
  config : Client,
  host : String,
  version : Version,
) -> Session? {
  match config.sessions {
    Some(store) => store.get(host~, version~, now=self.now)
    None => None
  }
}

///|
/// One identity a client offers in `pre_shared_key` (RFC 8446 §4.2.11.1): what names it, the age
/// it reports, the secret behind it, and the suite whose hash binds it.
struct Offer {
  identity : Bytes
  age : Int32
  key : Bytes
  suite : Int32
  /// Whether the secret was configured rather than resuming a ticket, which is what tells the two
  /// binder labels of §7.1 apart.
  external : Bool
  /// How much 0-RTT data the identity allows, negative for the unbounded figure a QUIC ticket
  /// carries. A configured key allows none: what it permits is the caller's to say, and TLS has
  /// no field for it.
  early : Int32
}

///|
/// The offers a ClientHello carries, or empty when there is nothing to offer: the configured
/// pre-shared keys, then a ticket the session store holds.
///
/// One ClientHello names one hash, because the binder offsets are measured against a single binder
/// length, so a PSK under another hash is left out rather than offered and refused. A ticket is
/// offered after the keys the caller configured, and only under the same hash.
fn Conn::psk_offers(
  self : Conn,
  config : Client,
  session : Session?,
) -> Array[Offer] {
  let offers : Array[Offer] = []
  let base = match
    config.psk
    .iter()
    .find_first(p => config.suites.iter().any(s => s.digest() == p.digest)) {
    Some(first) => first.digest
    None =>
      match session {
        Some(s) =>
          match @record.Suite::of(s.suite) {
            Some(suite) => suite.digest()
            None => return offers
          }
        None => return offers
      }
  }
  for psk in config.psk {
    if psk.digest == base {
      match config.suites.iter().find_first(s => s.digest() == base) {
        Some(suite) =>
          offers.push({
            identity: psk.identity,
            age: 0,
            key: psk.key,
            suite: suite.code(),
            external: true,
            early: 0,
          })
        None => ()
      }
    }
  }
  match session {
    Some(s) =>
      match @record.Suite::of(s.suite) {
        Some(suite) =>
          if suite.digest() == base {
            // §4.2.11.1: the age is the ticket's own age plus its age_add, both taken modulo
            // 2^32, so the server learns how long a client held a ticket without learning when
            // it connected.
            let age = (((self.now - s.born) * 1000L) & 0xffff_ffffL).to_int() +
              s.age_add
            offers.push({
              identity: s.ticket,
              age,
              key: s.secret,
              suite: s.suite,
              external: false,
              early: s.early,
            })
          }
        None => ()
      }
    None => ()
  }
  offers
}

///|
/// The ClientHello with a `pre_shared_key` offer appended and its binders computed
/// (RFC 8446 §4.2.11.2).
///
/// A binder is a Finished-style MAC over the ClientHello truncated at the binders, so the message
/// has to exist twice: once with binder-shaped holes, which is what is hashed, and once with the
/// answers in them, which is what goes out. After a HelloRetryRequest both earlier messages come
/// before the truncated ClientHello in the same hash, which is why `hrr` is read here.
fn Conn::hello_with_offers(
  self : Conn,
  base : @msg.Hello,
  offers : Array[Offer],
) -> Bytes raise @alert.Alert {
  let first = offers[0]
  let d = match @record.Suite::of(first.suite) {
    Some(suite) => suite.digest()
    None => raise @alert.fatal(InternalError)
  }
  let identities : Array[@ext.Identity] = offers.map(o => {
    identity: o.identity,
    age: o.age,
  })
  let holes : Array[Bytes] = offers.map(_ => Bytes::make(d.size(), b'\x00'))
  let hole = @ext.pre_shared_key(identities[:], holes[:])
  let probe = @msg.hello(
    {
      ..base,
      extensions: base.extensions + [{ kind: PreSharedKey, data: hole, }],
    },
    cookie=self.legacy_datagram,
  )
  let offset = match @ext.binder_offset(probe[:], d.size(), n=offers.length()) {
    Some(at) => at
    None => raise @alert.fatal(InternalError)
  }
  let hash = if self.hrr.length() > 0 {
    let joined = Buffer()
    joined.write_bytes(self.first_hello)
    joined.write_bytes(self.hrr)
    joined.write_bytesview(probe[0:offset])
    d.hash(joined.to_bytes()[:])
  } else {
    d.hash(probe[0:offset])
  }
  let binders : Array[Bytes] = offers.map(o => {
    let binder_key = @keys.binder_key(
      @keys.early(psk=o.key[:], digest=d),
      external=o.external,
      digest=d,
    )
    @keys.finished(binder_key[:], hash[:], digest=d)
  })
  self.psk = first.key
  self.psk_suite = first.suite
  self.offered = offers
  // §4.2.10: the ticket said how much 0-RTT data it allows, which is what the client is held to.
  self.early_left = if first.early < 0 { 0x7fffffff } else { first.early }
  self.offered_early = base.extensions.iter().any(e => e.kind is EarlyData)
  let body = @ext.pre_shared_key(identities[:], binders[:])
  @msg.hello(
    {
      ..base,
      extensions: base.extensions + [{ kind: PreSharedKey, data: body, }],
    },
    cookie=self.legacy_datagram,
  )
}

///|
/// Whether a server's ServerHello accepted the PSK this client offered (RFC 8446 §4.2.11): the
/// extension carries the index of the identity it took, and the key behind that identity is what
/// the handshake runs on.
fn Conn::accept_resumption(
  self : Conn,
  sh : @msg.Server,
) -> Unit raise @alert.Alert {
  match @ext.find(sh.extensions[:], PreSharedKey) {
    Some(e) => {
      if self.offered.length() == 0 {
        // Nothing was offered, so nothing could have been chosen.
        raise @alert.fatal(UnsupportedExtension)
      }
      if e.data.length() != 2 {
        raise @alert.fatal(DecodeError)
      }
      let picked = @wire.read_u16(e.data, 0)
      guard picked < self.offered.length() else {
        raise @alert.fatal(IllegalParameter)
      }
      let offer = self.offered[picked]
      self.psk = offer.key
      self.psk_suite = offer.suite
      self.resumed = true
    }
    None => self.resumed = false
  }
}

// ------------------------------------------------------------------ the client

///|
/// Remember a ticket a server sent (RFC 8446 §4.6.1).
///
/// The PSK is `Derive-Secret(Resumption Master Secret, "resumption", ticket_nonce)`, so the ticket
/// itself needs no key of its own on the client side — the nonce is what tells two tickets from one
/// connection apart. A ticket whose lifetime has run out, or one for a host this connection is not
/// to, is dropped rather than stored.
fn Conn::on_ticket(
  self : Conn,
  config : Client,
  host : String,
  body : Bytes,
) -> Unit raise @alert.Alert {
  guard @msg.read_new_session_ticket(body[:]) is Some(t) else {
    raise @alert.fatal(DecodeError)
  }
  guard self.suite is Some(suite) else { return }
  // §4.6.1: a lifetime past 604800 seconds is to be read as exactly that.
  let lifetime = if t.lifetime > 604800 {
    604800L
  } else {
    t.lifetime.to_int64()
  }
  if lifetime == 0L || self.resumption.length() == 0 {
    return
  }
  let early = match @ext.find(t.extensions[:], EarlyData) {
    Some(e) => {
      let size = @ext.read_max_early_data(e.data[:]).unwrap_or(0)
      // RFC 9001 §4.6.1: over QUIC anything but 0xffffffff is a protocol violation.
      if self.quic is Some(_) && size != -1 {
        raise @alert.fatal(IllegalParameter)
      }
      size
    }
    None => 0
  }
  let psk = @keys.resumption(
    self.resumption[:],
    t.nonce[:],
    digest=suite.digest(),
  )
  match config.sessions {
    Some(store) =>
      store.put({
        host,
        version: Tls13,
        kind: Psk,
        suite: suite.code(),
        ticket: t.ticket,
        secret: psk,
        lifetime,
        born: self.now,
        early,
        age_add: t.age_add,
      })
    None => ()
  }
}

///|
/// The resumption master secret, which every ticket this connection hands out stands for
/// (RFC 8446 §7.1): `Derive-Secret(Master Secret, "res master", ClientHello..client Finished)`.
fn Conn::close_transcript(self : Conn) -> Unit {
  if self.master13.length() == 0 {
    return
  }
  let d = self.digest()
  self.resumption = @keys.resumption_master(
    self.master13[:],
    self.th()[:],
    digest=d,
  )
}

///|
/// Queue 0-RTT data under the client's early traffic secret (RFC 8446 §4.2.10, §7.1).
///
/// Only a client that offered early_data in its ClientHello may, and only before the server has
/// answered: once the handshake has a key schedule of its own, 0-RTT is over. Whether the server
/// took it is `early_accepted`; data it declined is sent again, as ordinary data, when the
/// handshake opens — so a caller that writes early and then writes normally sees its bytes arrive
/// once, in order, either way.
pub fn Conn::write_early(
  self : Conn,
  data : BytesView,
) -> Unit raise @alert.Alert {
  guard self.phase is Expect(@hs.Client::WaitServerHello) else {
    raise @alert.fatal(InternalError)
  }
  guard self.early_writer is Some(w) else { raise @alert.fatal(InternalError) }
  if self.early_sent.length() + data.length() > self.early_left {
    raise @alert.fatal(InternalError)
  }
  let mut at = 0
  while at < data.length() {
    let end = @cmp.minimum(at + @record.max_fragment, data.length())
    self.outbox.write_bytes(w.seal(ApplicationData, data[at:end]))
    at = end
  }
  let joined = Buffer()
  joined.write_bytes(self.early_sent)
  joined.write_bytesview(data)
  self.early_sent = joined.to_bytes()
}

///|
/// Whether the server accepted the 0-RTT data this client sent.
pub fn Conn::early_accepted(self : Conn) -> Bool {
  self.early_ok
}

///|
/// Whether this handshake resumed a session instead of authenticating a certificate (RFC 8446
/// §4.6.1). A resumed handshake is authenticated by the ticket, so `peer` is empty on both ends
/// unless a client certificate was asked for again.
pub fn Conn::is_resumed(self : Conn) -> Bool {
  self.resumed
}

// ------------------------------------------------------------------ the server

///|
/// Whether a ClientHello says it can resume with (EC)DHE (RFC 8446 §4.2.9).
///
/// A client that offers `pre_shared_key` without this extension is one a server must abort for
/// (same section); one that offers it with only `psk_ke` is asking for a mode this library does
/// not implement, and both ends are better off without a ticket that cannot be used.
fn declares_psk_dhe(hello : @msg.Hello) -> Bool {
  offers_mode(hello, @ext.psk_dhe_ke)
}

///|
/// Whether a ClientHello says it would let a PSK key the handshake on its own (RFC 8446 §4.2.9).
/// A server that has not been told to accept that mode must not read a hello without `key_share`
/// as anything but a missing extension.
fn declares_psk_ke(hello : @msg.Hello) -> Bool {
  offers_mode(hello, @ext.psk_ke)
}

///|
/// Whether a ClientHello's `psk_key_exchange_modes` names a mode.
fn offers_mode(hello : @msg.Hello, mode : Int32) -> Bool {
  match @ext.find(hello.extensions[:], PskKeyExchangeModes) {
    Some(e) =>
      match @ext.read_psk_modes(e.data[:]) {
        Some(modes) => modes.contains(mode)
        None => false
      }
    None => false
  }
}

///|
/// The mode a PSK would be used in for this ClientHello, or `None` when this handshake offers none
/// this endpoint will run (RFC 8446 §4.2.9): `psk_dhe_ke` when a key share is there to bind the
/// PSK to, `psk_ke` when the client sent none and both ends allow the PSK alone.
fn Conn::psk_mode(self : Conn, config : Server, hello : @msg.Hello) -> Int32? {
  let share = @ext.find(hello.extensions[:], KeyShare) is Some(_)
  if share && self.modes_dhe && config.psk_modes.contains(@ext.psk_dhe_ke) {
    return Some(@ext.psk_dhe_ke)
  }
  // A hello that asks for the PSK alone may still carry a key share: that one is for the full
  // handshake it would run if the PSK were refused, and §4.1.2 has a server that chose `psk_ke`
  // ignore it rather than answer it.
  if self.modes_ke && config.psk_modes.contains(@ext.psk_ke) {
    return Some(@ext.psk_ke)
  }
  None
}

///|
/// Look through a ClientHello's PSK offers for one this server knows, and verify the binder that
/// comes with it (RFC 8446 §4.2.11).
///
/// An identity is known either because this server issued it as a ticket or because the caller
/// supplied it as a pre-shared key. The first identity that opens and whose binder verifies is the
/// one taken; anything else leaves the handshake to run in full, which is what a client that
/// offered an unknown identity expects (§4.2.11: a server that does not accept one continues
/// without it).
fn Conn::accept_psk(
  self : Conn,
  config : Server,
  hello : @msg.Hello,
  raw : Bytes,
) -> Unit raise @alert.Alert {
  // §4.2.9: a hello naming none of the modes this endpoint runs has no PSK handshake to make
  // here, and the certificate the configuration holds is what authenticates it instead.
  if self.psk_mode(config, hello) is None {
    return
  }
  guard @ext.find(hello.extensions[:], PreSharedKey) is Some(e) else { return }
  // §4.2.11: pre_shared_key has to be the last extension, and the binder is found by measuring
  // back from the end of the message.
  match hello.extensions.rev().get(0) {
    Some(last) =>
      if !(last.kind is PreSharedKey) {
        raise @alert.fatal(IllegalParameter)
      }
    None => ()
  }
  guard @ext.read_pre_shared_key(e.data[:]) is Some((identities, binders)) else {
    raise @alert.fatal(DecodeError)
  }
  // §4.2.11.2: one binder per identity, in the same order.
  if binders.length() != identities.length() {
    raise @alert.fatal(DecodeError)
  }
  for i, identity in identities {
    if self.resumed {
      break
    }
    let binder = binders[i]
    // §4.2.11: an identity the caller supplied is matched by its octets alone; there is no state
    // behind it, and its age is not something either end can judge.
    match config.psk.iter().find_first(p => p.identity == identity.identity) {
      Some(psk) =>
        match
          external_psk(config, hello, psk, binder, raw, identities.length()) {
          Some(suite) => {
            self.psk = psk.key
            self.resumed = true
            self.suite = Some(suite)
            return
          }
          None => continue
        }
      // The `mode` a hello declared decides the key exchange, not whether a ticket is taken: a
      // ticket is as good a PSK under `psk_ke` as under `psk_dhe_ke`.
      None =>
        if self.ticket(
            config,
            hello,
            identity,
            binder,
            raw,
            identities.length(),
          ) {
          return
        } else {
          continue
        }
    }
  }
}

///|
/// The code of the first suite this server offers whose hash is `d`. A PSK is bound to one hash
/// (RFC 8446 §4.2.11), so this is the only suite it can be used with.
fn Server::suite_for(config : Server, d : @keys.Digest) -> Int32? {
  config.suites.iter().find_first(s => s.digest() == d).map(s => s.code())
}

///|
/// Whether a PSK the caller supplied proves this ClientHello: the suite it is bound to has to be
/// one the client offered, and the binder has to be that key's (RFC 8446 §4.2.11.2).
fn external_psk(
  config : Server,
  hello : @msg.Hello,
  psk : Psk,
  binder : Bytes,
  raw : Bytes,
  count : Int32,
) -> @record.Suite? raise @alert.Alert {
  let code = match Server::suite_for(config, psk.digest) {
    Some(code) => code
    None => return None
  }
  if !hello.suites.contains(code) {
    return None
  }
  let d = psk.digest
  let at = match @ext.binder_offset(raw[:], d.size(), n=count) {
    Some(at) => at
    None => raise @alert.fatal(DecodeError)
  }
  let binder_key = @keys.binder_key(
    @keys.early(psk=psk.key[:], digest=d),
    external=true,
    digest=d,
  )
  if !@keys.finished_ok(binder_key[:], d.hash(raw[0:at]), binder[:], digest=d) {
    return None
  }
  @record.Suite::of(code)
}

///|
/// Whether a ticket this server issued proves the ClientHello it came back in (RFC 8446 §4.6.1),
/// and whether its 0-RTT data may be read.
fn Conn::ticket(
  self : Conn,
  config : Server,
  hello : @msg.Hello,
  identity : @ext.Identity,
  binder : Bytes,
  raw : Bytes,
  count : Int32,
) -> Bool raise @alert.Alert {
  // With no clock (`now` left out) a ticket's lifetime cannot be judged, so none is taken.
  if !config.tickets.is_on() || self.now == 0L {
    return false
  }
  guard open_ticket(config.tickets, identity.identity) is Some(state) else {
    return false
  }
  guard @record.Suite::of(state.suite) is Some(suite) else { return false }
  if !hello.suites.contains(suite.code()) {
    return false
  }
  // §4.2.11.1 and §8.3: the reported age is the real one plus age_add, in milliseconds. The two
  // ends read different clocks at different moments, so a difference is no reason to refuse the
  // ticket; it only says this hello may be a replay, which is what 0-RTT cannot survive.
  let reported = (identity.age - state.age_add).to_int64() & 0xffff_ffffL
  let drift = (self.now - state.born) * 1000L - reported
  let fresh = drift.abs() <= config.tickets.drift
  if self.now - state.born > state.lifetime || self.now < state.born {
    return false
  }
  let d = suite.digest()
  let at = match @ext.binder_offset(raw[:], d.size(), n=count) {
    Some(at) => at
    None => raise @alert.fatal(DecodeError)
  }
  let binder_key = @keys.binder_key(
    @keys.early(psk=state.psk[:], digest=d),
    digest=d,
  )
  if !@keys.finished_ok(binder_key[:], d.hash(raw[0:at]), binder[:], digest=d) {
    return false
  }
  self.psk = state.psk
  self.resumed = true
  self.suite = Some(suite)
  // §4.2.10: 0-RTT only under a ticket that allows it, and only when the application said so.
  if fresh &&
    @ext.find(hello.extensions[:], EarlyData) is Some(_) &&
    state.early > 0 &&
    config.tickets.early > 0 {
    self.early_ok = true
    self.early_left = @cmp.minimum(state.early, config.tickets.early)
  }
  true
}

///|
/// Start the client's early read keys and window once the ClientHello has settled which PSK this
/// handshake uses (RFC 8446 §7.1).
fn Conn::open_early(self : Conn, first_hello : Bytes) -> Unit {
  if !self.early_ok {
    return
  }
  guard self.suite is Some(suite) else { return }
  let d = suite.digest()
  self.early_secret = @keys.early(psk=self.psk[:], digest=d)
  let secret = @keys.client_early(
    self.early_secret[:],
    d.hash(first_hello),
    digest=d,
  )
  self.early_reader = Some(@record.Cipher::new(secret[:], suite~))
  if self.quic is Some(q) {
    q.steps.push(Early(secret~, suite~))
  }
}

///|
/// Hand out `count` tickets once the handshake is over (RFC 8446 §4.6.1): each carries the server's
/// state, sealed under the newest ticket key, and a nonce of its own so that no two tickets stand
/// for the same PSK.
fn Conn::issue_tickets(self : Conn, config : Server) -> Unit raise @alert.Alert {
  guard config.tickets.is_on() && self.resumption.length() > 0 && self.now != 0L else {
    return
  }
  // §4.2.9: "Servers SHOULD NOT send NewSessionTicket with tickets that are not compatible with
  // the advertised modes". A ticket is compatible when this server would take it back under a mode
  // the client named — with a key exchange, or alone where both ends allow that.
  let usable = (self.modes_dhe && config.psk_modes.contains(@ext.psk_dhe_ke)) ||
    (self.modes_ke && config.psk_modes.contains(@ext.psk_ke))
  if !usable {
    return
  }
  guard self.suite is Some(suite) else { return }
  let mut i = 0
  while i < config.tickets.count {
    let nonce = Bytes::from_array([
      ((i >> 8) & 0xff).to_byte(),
      (i & 0xff).to_byte(),
    ])
    let psk = @keys.resumption(
      self.resumption[:],
      nonce[:],
      digest=suite.digest(),
    )
    let raw_age = (self.rand)(4)
    let age_add = (raw_age[0].to_int() << 24) |
      (raw_age[1].to_int() << 16) |
      (raw_age[2].to_int() << 8) |
      raw_age[3].to_int()
    let ticket_bytes = seal_ticket(
      config.tickets,
      {
        suite: suite.code(),
        born: self.now,
        lifetime: config.tickets.lifetime,
        early: config.tickets.early,
        age_add,
        psk,
      },
      self.rand,
    )
    let extensions : Array[@ext.Ext] = if config.tickets.early > 0 {
      // RFC 9001 §4.6.1: QUIC has its own flow control, and the field is fixed at 0xffffffff.
      let size = if self.quic is Some(_) { -1 } else { config.tickets.early }
      [{ kind: EarlyData, data: @ext.max_early_data(size), }]
    } else {
      []
    }
    let message = @msg.new_session_ticket({
      lifetime: config.tickets.lifetime.to_int(),
      age_add,
      nonce,
      ticket: ticket_bytes,
      extensions,
    })
    self.send_handshake(message)
    i = i + 1
  }
}
