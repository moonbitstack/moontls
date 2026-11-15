// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A certificate chain (DER, leaf first), the leaf's private key and the OCSP response stapled to
/// the leaf: everything a server presents once it has chosen what to present.
pub(all) struct Credential {
  chain : Array[Bytes]
  key : @x509.PrivateKey
  ocsp : Bytes?
}

///|
/// Refuses an empty chain and a key that is not the leaf's, as `Server::new` does.
pub fn Credential::new(
  chain : Array[Bytes],
  key : @x509.PrivateKey,
  ocsp? : Bytes,
) -> Credential raise @asn1.Refused {
  owned(chain, key)
  { chain, key, ocsp, }
}

///|
fn owned(
  chain : Array[Bytes],
  key : @x509.PrivateKey,
) -> Unit raise @asn1.Refused {
  guard chain is [leaf, ..] else {
    raise @asn1.Malformed("empty certificate chain")
  }
  if @x509.parse(leaf[:]).spki.key() != key.public() {
    raise @asn1.Malformed("private key is not the leaf certificate's")
  }
}

///|
/// This configuration presenting its `index`-th credential, 0 being `chain` and `key` themselves,
/// with nothing left to choose between.
fn Server::serving(self : Server, index : Int32) -> Server {
  guard index > 0 else { return { ..self, alternatives: [], } }
  let c = self.alternatives[index - 1]
  { ..self, chain: c.chain, key: c.key, ocsp: c.ocsp, alternatives: [], }
}

///|
/// Whether the leaf of a chain is for `host`. A chain that does not parse is for no host.
fn for_host(chain : Array[Bytes], host : String) -> Bool {
  guard chain is [leaf, ..] else { return false }
  let cert = @x509.parse(leaf[:]) catch { _ => return false }
  cert.matches(host)
}

///|
/// Settles which credential this connection presents (RFC 8446 §4.4.2.2): the first, `chain`
/// before `alternatives`, that `fits` the hello and is for the host the client named. With none,
/// `chain` goes out and the handshake ends as it would have with no alternatives. The result
/// serves the rest of the connection, renegotiation included.
fn Conn::choose(
  self : Conn,
  config : Server,
  hello : @msg.Hello,
  fits : (Server) -> Bool,
) -> Server raise @alert.Alert {
  if config.alternatives.is_empty() {
    return config
  }
  self.note_server_name(hello)
  let named = (c : Server) => {
    match self.sni {
      Some(host) => for_host(c.chain, host)
      None => true
    }
  }
  let index = for i in 0..<=config.alternatives.length() {
    let c = config.serving(i)
    if fits(c) && named(c) {
      break i
    }
  } nobreak {
    0
  }
  let chosen = config.serving(index)
  // RFC 6066 §3: a server that let the name pick its certificate says so.
  self.by_name = self.sni is Some(_) && named(chosen)
  self.side = Server(chosen)
  chosen
}
