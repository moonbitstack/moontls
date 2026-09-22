///|
/// The TLS 1.3 key schedule, one step at a time (RFC 8446 §7.1).
///
///     moon run examples/tour
#coverage.skip
fn main {
  // No PSK, so the Early Secret is the extract of two all-zero inputs — the
  // value RFC 8448 publishes.
  let early = @keys.early()
  println("early              " + hex(early))

  // A fixed ECDHE secret stands in for the one X25519 would produce.
  let ecdhe = Bytes::make(32, b'\x2a')
  let handshake = @keys.handshake(early[:], ecdhe[:])
  println("handshake          " + hex(handshake))
  let master = @keys.master(handshake[:])
  println("master             " + hex(master))

  // The transcript is the running hash of the handshake messages.
  let transcript = @keys.Transcript::new()
  transcript.add(b"ClientHello"[:])
  transcript.add(b"ServerHello"[:])
  let through_hello = transcript.hash()
  println("transcript         " + hex(through_hello))
  let client = @keys.client_handshake(handshake[:], through_hello[:])
  let server = @keys.server_handshake(handshake[:], through_hello[:])
  println("c hs traffic       " + hex(client))
  println("s hs traffic       " + hex(server))

  // A Finished MACs the transcript under a key derived from that secret.
  let verify = @keys.finished(client[:], through_hello[:])
  println("verify_data        " + hex(verify))
  println(
    "accepted           " +
    @keys.finished_ok(client[:], through_hello[:], verify[:]).to_string(),
  )
  let tampered = verify.to_array()
  tampered[0] = (tampered[0].to_int() ^ 1).to_byte()
  println(
    "one bit flipped    " +
    @keys.finished_ok(
      client[:],
      through_hello[:],
      Bytes::from_array(tampered)[:],
    ).to_string(),
  )

  // A SHA-384 suite runs the same ladder 48 octets wide.
  println("early (SHA-384)    " + hex(@keys.early(digest=Sha384)))
}

///|
fn hex(b : Bytes) -> String {
  @base16.encode(b[:])
}
