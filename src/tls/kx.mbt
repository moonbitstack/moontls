// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The key exchange a named group runs (RFC 8446 §4.2.7): an X curve, a NIST curve, or a
/// finite-field group of RFC 7919.
priv enum Kx {
  X25519
  X448
  Nist(@curve.Curve)
  Finite(@dh.Group)
}

///|
fn kx_of(group : Int32) -> Kx raise @alert.Alert {
  match group {
    0x001d => X25519
    0x001e => X448
    0x0017 => Nist(P256)
    0x0018 => Nist(P384)
    0x0019 => Nist(P521)
    0x0100 => Finite(Ffdhe2048)
    0x0101 => Finite(Ffdhe3072)
    0x0102 => Finite(Ffdhe4096)
    0x0103 => Finite(Ffdhe6144)
    0x0104 => Finite(Ffdhe8192)
    _ => raise @alert.fatal(IllegalParameter)
  }
}

///|
/// The secret's length. A finite-field exponent is twice the group's security level and 32 bits
/// more, which meets the lengths RFC 7919 §5.2 recommends for each group.
fn Kx::secret_size(self : Kx) -> Int32 {
  match self {
    X25519 => 32
    X448 => 56
    Nist(c) => c.size()
    Finite(g) => (2 * g.security() + 32 + 7) / 8
  }
}

///|
/// An ephemeral key share for `group`: the secret and the public value sent in key_share. A
/// NIST scalar drawn outside the curve order is drawn again; P-521's top seven bits are cleared
/// first, or nearly every draw would be.
fn share(
  group : Int32,
  rand : (Int32) -> Bytes,
) -> (Bytes, Bytes) raise @alert.Alert {
  let kx = kx_of(group)
  for _ in 0..<8 {
    let secret = rand(kx.secret_size())
    let secret = if kx is Nist(P521) {
      let raw = secret.to_array()
      raw[0] = raw[0] & b'\x01'
      Bytes::from_array(raw)
    } else {
      secret
    }
    let public = public_of(kx, secret) catch { _ => continue }
    return (secret, public)
  }
  raise @alert.fatal(InternalError)
}

///|
fn public_of(kx : Kx, secret : Bytes) -> Bytes raise {
  match kx {
    X25519 => @x25519.public(secret[:])
    X448 => @x448.public(secret[:])
    Nist(curve) => @ecdh.public(secret[:], curve~)
    Finite(g) => @dh.public_key(g, secret[:])
  }
}

///|
/// The shared secret (RFC 8446 §7.4), a finite-field one left-padded to the prime's length; a
/// peer share that is the wrong size, off the curve, of low order, or outside [2, p-2] is an
/// `IllegalParameter`.
fn agree(
  group : Int32,
  secret : Bytes,
  peer : Bytes,
) -> Bytes raise @alert.Alert {
  let kx = kx_of(group)
  shared_of(kx, secret, peer) catch {
    _ => raise @alert.fatal(IllegalParameter)
  }
}

///|
fn shared_of(kx : Kx, secret : Bytes, peer : Bytes) -> Bytes raise {
  match kx {
    X25519 => @x25519.shared(secret[:], peer[:])
    X448 => @x448.shared(secret[:], peer[:])
    Nist(curve) => @ecdh.shared(secret[:], peer[:], curve~)
    Finite(g) => @dh.shared_secret(g, secret[:], peer[:])
  }
}
