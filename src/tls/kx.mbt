// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The key exchange a named group runs (RFC 8446 §4.2.7): an X curve, a NIST curve, a
/// finite-field group of RFC 7919, ML-KEM alone, or a classic exchange and ML-KEM in one share.
///
/// A Diffie-Hellman group and a KEM meet in the same three steps: the client `share`s, the server
/// `respond`s to that share, and the client `agree`s on the response. For a Diffie-Hellman group
/// the response is the server's own share; for a KEM it is a ciphertext sealed to the client's.
priv enum Kx {
  X25519
  X448
  Nist(@curve.Curve)
  Finite(@dh.Group)
  Kem(@mlkem.Kind)
  /// `kem_first` is the order of the two halves, on the wire and in the shared secret alike.
  Hybrid(Kx, @mlkem.Kind, kem_first~ : Bool)
}

///|
fn kx_of(group : Int32) -> Kx raise @alert.Alert {
  match group {
    0x001d => X25519
    0x001e => X448
    0x0017 => Nist(P256)
    0x0018 => Nist(P384)
    0x0019 => Nist(P521)
    0x001a => Nist(BrainpoolP256r1)
    0x001b => Nist(BrainpoolP384r1)
    0x001c => Nist(BrainpoolP512r1)
    0x0100 => Finite(Ffdhe2048)
    0x0101 => Finite(Ffdhe3072)
    0x0102 => Finite(Ffdhe4096)
    0x0103 => Finite(Ffdhe6144)
    0x0104 => Finite(Ffdhe8192)
    0x0200 => Kem(K512)
    0x0201 => Kem(K768)
    0x0202 => Kem(K1024)
    0x11ec => Hybrid(X25519, K768, kem_first=true)
    0x11eb => Hybrid(Nist(P256), K768, kem_first=false)
    0x11ed => Hybrid(Nist(P384), K1024, kem_first=false)
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
    Kem(kind) => kind.seeds()
    Hybrid(classic, kind, ..) => kind.seeds() + classic.secret_size()
  }
}

///|
/// The client's key share for `group`: the secret it keeps and the value it sends in key_share.
fn share(
  group : Int32,
  rand : (Int32) -> Bytes,
) -> (Bytes, Bytes) raise @alert.Alert {
  start(kx_of(group), rand)
}

///|
/// A NIST scalar drawn outside the curve order is drawn again; P-521's top seven bits are cleared
/// first, or nearly every draw would be. An ML-KEM secret is the seed the key is derived from,
/// which is 64 bytes against a decapsulation key of more than two thousand.
fn start(kx : Kx, rand : (Int32) -> Bytes) -> (Bytes, Bytes) raise @alert.Alert {
  match kx {
    Kem(kind) => {
      let seed = rand(kind.seeds())
      let key = @mlkem.PrivateKey::from_seed(kind~, seed[:]) catch {
        _ => raise @alert.fatal(InternalError)
      }
      (seed, key.encapsulation_key().bytes())
    }
    Hybrid(classic, kind, kem_first~) => {
      let (kem_secret, kem_public) = start(Kem(kind), rand)
      let (secret, public) = start(classic, rand)
      (
        kem_secret + secret,
        if kem_first {
          kem_public + public
        } else {
          public + kem_public
        },
      )
    }
    _ => {
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
  }
}

///|
fn public_of(kx : Kx, secret : Bytes) -> Bytes raise {
  match kx {
    X25519 => @x25519.public(secret[:])
    X448 => @x448.public(secret[:])
    Nist(curve) => @ecdh.public(secret[:], curve~)
    Finite(g) => @dh.public_key(g, secret[:])
    Kem(_) | Hybrid(_, _, ..) =>
      fail("a KEM's public value comes from its seed")
  }
}

///|
/// The server's answer to the client's share for `group`: the value it sends back in key_share and
/// the shared secret. A share of the wrong size or shape is an `IllegalParameter`.
fn respond(
  group : Int32,
  peer : Bytes,
  rand : (Int32) -> Bytes,
) -> (Bytes, Bytes) raise @alert.Alert {
  answer(kx_of(group), peer, rand)
}

///|
fn answer(
  kx : Kx,
  peer : Bytes,
  rand : (Int32) -> Bytes,
) -> (Bytes, Bytes) raise @alert.Alert {
  match kx {
    Kem(kind) => {
      let key = @mlkem.PublicKey::new(kind~, peer[:]) catch {
        _ => raise @alert.fatal(IllegalParameter)
      }
      let enc = key.encapsulate_with(rand(32)[:]) catch {
        _ => raise @alert.fatal(InternalError)
      }
      (enc.ciphertext, enc.secret)
    }
    Hybrid(classic, kind, kem_first~) => {
      let (kem_peer, peer) = halves(peer, kind.encapsulation(), kem_first~)
      let (kem_public, kem_shared) = answer(Kem(kind), kem_peer, rand)
      let (public, shared) = answer(classic, peer, rand)
      if kem_first {
        (kem_public + public, kem_shared + shared)
      } else {
        (public + kem_public, shared + kem_shared)
      }
    }
    _ => {
      let (secret, public) = start(kx, rand)
      (public, finish(kx, secret, peer))
    }
  }
}

///|
/// The shared secret (RFC 8446 §7.4) from the client's secret and the server's answer, a
/// finite-field one left-padded to the prime's length; a peer value that is the wrong size, off
/// the curve, of low order, or outside [2, p-2] is an `IllegalParameter`.
fn agree(
  group : Int32,
  secret : Bytes,
  peer : Bytes,
) -> Bytes raise @alert.Alert {
  finish(kx_of(group), secret, peer)
}

///|
fn finish(kx : Kx, secret : Bytes, peer : Bytes) -> Bytes raise @alert.Alert {
  match kx {
    Kem(kind) => {
      guard peer.length() == kind.ciphertext() else {
        raise @alert.fatal(IllegalParameter)
      }
      let key = @mlkem.PrivateKey::from_seed(kind~, secret[:]) catch {
        _ => raise @alert.fatal(InternalError)
      }
      key.decapsulate(peer[:]) catch {
        _ => raise @alert.fatal(IllegalParameter)
      }
    }
    Hybrid(classic, kind, kem_first~) => {
      let kem_secret = secret[:kind.seeds()].to_owned()
      let (kem_peer, peer) = halves(peer, kind.ciphertext(), kem_first~)
      let kem_shared = finish(Kem(kind), kem_secret, kem_peer)
      let shared = finish(classic, secret[kind.seeds():].to_owned(), peer)
      if kem_first {
        kem_shared + shared
      } else {
        shared + kem_shared
      }
    }
    _ =>
      shared_of(kx, secret, peer) catch {
        _ => raise @alert.fatal(IllegalParameter)
      }
  }
}

///|
/// A hybrid value split into its ML-KEM half, `size` bytes, and the classic half, in the order
/// the group puts them.
fn halves(
  value : Bytes,
  size : Int32,
  kem_first~ : Bool,
) -> (Bytes, Bytes) raise @alert.Alert {
  guard value.length() > size else { raise @alert.fatal(IllegalParameter) }
  let rest = value.length() - size
  if kem_first {
    (value[:size].to_owned(), value[size:].to_owned())
  } else {
    (value[rest:].to_owned(), value[:rest].to_owned())
  }
}

///|
fn shared_of(kx : Kx, secret : Bytes, peer : Bytes) -> Bytes raise {
  match kx {
    X25519 => @x25519.shared(secret[:], peer[:])
    X448 => @x448.shared(secret[:], peer[:])
    Nist(curve) => {
      // RFC 8422 §5.1.2 and RFC 8446 §4.2.8.2: uncompressed, whatever else a curve library reads.
      if peer.length() != 1 + 2 * curve.size() || peer[0] != b'\x04' {
        fail("not an uncompressed point")
      }
      @ecdh.shared(secret[:], peer[:], curve~)
    }
    Finite(g) => @dh.shared_secret(g, secret[:], peer[:])
    Kem(_) | Hybrid(_, _, ..) => fail("a KEM is not agreed by a shared secret")
  }
}
