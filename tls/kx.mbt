// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// An ephemeral key share for `group`: the private scalar and the public value sent in key_share.
/// A NIST scalar drawn outside the curve order is drawn again.
fn share(
  group : Int32,
  rand : (Int32) -> Bytes,
) -> (Bytes, Bytes) raise @alert.Alert {
  for _ in 0..<8 {
    let secret = rand(scalar_size(group))
    let public = public_of(group, secret) catch { _ => continue }
    return (secret, public)
  }
  raise @alert.fatal(InternalError)
}

///|
fn scalar_size(group : Int32) -> Int32 {
  if group == @ext.secp384r1 {
    48
  } else {
    32
  }
}

///|
fn public_of(group : Int32, secret : Bytes) -> Bytes raise {
  match group {
    g if g == @ext.x25519 => @x25519.public(secret[:])
    g if g == @ext.secp256r1 => @ecdh.public(secret[:], curve=P256)
    g if g == @ext.secp384r1 => @ecdh.public(secret[:], curve=P384)
    _ => raise @alert.fatal(IllegalParameter)
  }
}

///|
/// The ECDHE shared secret (RFC 8446 §7.4); a peer share that is off the curve or of low order
/// is an `IllegalParameter`.
fn agree(
  group : Int32,
  secret : Bytes,
  peer : Bytes,
) -> Bytes raise @alert.Alert {
  shared_of(group, secret, peer) catch {
    _ => raise @alert.fatal(IllegalParameter)
  }
}

///|
fn shared_of(group : Int32, secret : Bytes, peer : Bytes) -> Bytes raise {
  match group {
    g if g == @ext.x25519 => @x25519.shared(secret[:], peer[:])
    g if g == @ext.secp256r1 => @ecdh.shared(secret[:], peer[:], curve=P256)
    g if g == @ext.secp384r1 => @ecdh.shared(secret[:], peer[:], curve=P384)
    _ => raise @alert.fatal(IllegalParameter)
  }
}
