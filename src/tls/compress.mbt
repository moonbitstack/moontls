// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Certificate compression (RFC 8879): a Certificate message, packed under one of the three
// algorithms §4.2 registers and carried in its place.

///|
/// `body` compressed under `algorithm`, or `None` for a code point this library does not speak —
/// which is what leaves the next offer a chance rather than ending the message.
fn pack(algorithm : Int32, body : BytesView) -> Bytes? {
  match algorithm {
    a if a == @ext.zlib_compression => Some(@zlib.zlib(body))
    a if a == @ext.brotli_compression => Some(@brotli.brotli(body))
    a if a == @ext.zstd_compression => Some(@zstd.zstd(body))
    _ => None
  }
}

///|
/// `body` unpacked, refusing to grow past the length the message promised: §4 says the
/// uncompressed length travels in front of the compressed one, and a decompression bomb is a peer
/// that lies about it.
///
/// A body that will not unpack, or that unpacks past the promised length, is `bad_certificate`:
/// §4 says so twice, once for a message that "cannot be decompressed" and once for a length that
/// does not match, which is the one alert this file does not choose for itself.
fn unpack(
  algorithm : Int32,
  body : BytesView,
  limit : Int32,
) -> Bytes raise @alert.Alert {
  match algorithm {
    a if a == @ext.zlib_compression =>
      @zlib.unzlib(body, limit~) catch {
        _ => raise @alert.fatal(BadCertificate)
      }
    a if a == @ext.brotli_compression =>
      @brotli.unbrotli(body, limit~) catch {
        _ => raise @alert.fatal(BadCertificate)
      }
    a if a == @ext.zstd_compression =>
      @zstd.unzstd(body, limit~) catch {
        _ => raise @alert.fatal(BadCertificate)
      }
    _ => raise @alert.fatal(IllegalParameter)
  }
}

///|
/// A Certificate message compressed under the first algorithm both ends named, or `None` when the
/// two lists have nothing in common.
///
/// It travels compressed even when the result is not smaller: §4 makes compression something a
/// peer asks for, and a server that answered a `compress_certificate` with a plain Certificate has
/// ignored the ask. Brotli on a chain of one small certificate is where the difference shows — the
/// compressed message is a few octets longer, and the peer that offered it expects the message it
/// asked for.
fn pack_for(
  body : BytesView,
  offered : ArrayView[Int32],
  ours : ArrayView[Int32],
) -> Bytes? {
  for algorithm in ours {
    guard offered.contains(algorithm) else { continue }
    guard pack(algorithm, body) is Some(packed) else { continue }
    return Some(
      @msg.frame(
        CompressedCertificate,
        @msg.compressed_certificate(algorithm, body.length(), packed[:])[:],
      ),
    )
  }
  None
}
