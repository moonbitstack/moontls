// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// What a handshake carries besides the certificate itself: the leaf's revocation status stapled to
// it (RFC 6066 §8, RFC 8446 §4.4.2.1) and the largest record either end will read (RFC 8449).
//
// Both are requests a client may make and a server may answer, and neither changes what is
// negotiated. A server that has no response to staple simply leaves the extension out, which the
// client sees as "no status" rather than as a failure.

///|
/// The OCSP response this connection was given, if one was stapled: the leaf's status as its
/// issuer signed it, in DER.
pub fn Conn::ocsp(self : Conn) -> Bytes? {
  self.ocsp
}

///|
/// Note what the peer's ClientHello asked about status and records, and what it will read.
fn Conn::note_requests(
  self : Conn,
  hello : @msg.Hello,
) -> Unit raise @alert.Alert {
  match @ext.find(hello.extensions[:], RecordSizeLimit) {
    Some(e) => {
      guard @ext.read_record_size_limit(e.data[:]) is Some(limit) else {
        raise @alert.fatal(DecodeError)
      }
      // §4: below 64 a record cannot carry anything, and the number has to be one this end can
      // honour.
      if limit < 64 || limit > @record.max_fragment + 1 {
        raise @alert.fatal(IllegalParameter)
      }
      self.peer_limit = limit
    }
    None => ()
  }
}

///|
/// The extensions a server answers a client's requests with, for a TLS 1.3
/// EncryptedExtensions: a record_size_limit of its own when it has one.
fn Conn::answered12(
  self : Conn,
  config : Server,
  exts : Array[@ext.Ext],
) -> Unit {
  if config.record_limit > 0 {
    exts.push({
      kind: RecordSizeLimit,
      data: @ext.record_size_limit(config.record_limit),
    })
    self.our_limit = config.record_limit
  }
}

///|
/// The OCSP response a client asked for, if this server has one to staple.
fn Conn::staple(self : Conn, config : Server) -> Bytes? {
  match config.ocsp {
    Some(response) => {
      self.ocsp = Some(response)
      Some(response)
    }
    None => None
  }
}
