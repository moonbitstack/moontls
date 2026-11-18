#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Print one TLS 1.2 record per block cipher of `legacy12`, sealed outside this library.

Each record is the one `protect12_test.mbt`'s `cipher12` seals for "moontls" at sequence zero:
key octets 0x11, salt 0x22, MAC key 0x33, CBC IVs 0x44. The CBC records follow RFC 5246
§6.2.3.2 (MAC, then padding, then CBC) and the GCM ones RFC 5288 §3 (salt and an explicit
sequence number). Camellia, SEED, IDEA and triple DES come from Python's `cryptography`, ARIA from
OpenSSL's EVP, and GCM from the GHASH below, which is checked against `cryptography`'s AES-GCM
before anything is printed.

Usage:
    python scripts/gen_legacy_records.py
"""

from __future__ import annotations

import hashlib
import hmac
import subprocess

from cryptography.hazmat.decrepit.ciphers.algorithms import IDEA, SEED, Camellia, TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CONTENT = b"moontls"
HEADER = bytes([23, 3, 3])
SEQ = bytes(8)


def ecb(name: str, key: bytes, block: bytes) -> bytes:
    if name.startswith("aria"):
        out = subprocess.run(
            ["openssl", "enc", f"-aria-{len(key) * 8}-ecb", "-K", key.hex(), "-nopad", "-nosalt"],
            input=block,
            capture_output=True,
            check=True,
        )
        return out.stdout
    algo = {"camellia": Camellia, "seed": SEED, "idea": IDEA, "3des": TripleDES, "aes": algorithms.AES}[name]
    enc = Cipher(algo(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def cbc(name: str, key: bytes, iv: bytes, plain: bytes) -> bytes:
    out, prev, size = b"", iv, len(iv)
    for i in range(0, len(plain), size):
        prev = ecb(name, key, bytes(a ^ b for a, b in zip(plain[i : i + size], prev)))
        out += prev
    return out


def ghash(h: int, data: bytes) -> int:
    def mul(x: int, y: int) -> int:
        z, v = 0, y
        for i in range(127, -1, -1):
            if (x >> i) & 1:
                z ^= v
            v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
        return z

    y = 0
    for i in range(0, len(data), 16):
        y = mul(y ^ int.from_bytes(data[i : i + 16].ljust(16, b"\0"), "big"), h)
    return y


def gcm(name: str, key: bytes, nonce: bytes, plain: bytes, aad: bytes) -> bytes:
    h = int.from_bytes(ecb(name, key, bytes(16)), "big")
    counter = int.from_bytes(nonce + b"\0\0\0\1", "big")
    out = b""
    for i in range(0, len(plain), 16):
        counter += 1
        pad = ecb(name, key, counter.to_bytes(16, "big"))
        out += bytes(a ^ b for a, b in zip(plain[i : i + 16], pad))
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(out) * 8).to_bytes(8, "big")
    pad16 = lambda b: b + bytes(-len(b) % 16)
    s = ghash(h, pad16(aad) + pad16(out) + lengths)
    tag = int.from_bytes(ecb(name, key, nonce + b"\0\0\0\1"), "big") ^ s
    return out + tag.to_bytes(16, "big")


def aad(size: int) -> bytes:
    return SEQ + HEADER + size.to_bytes(2, "big")


def cbc_record(name: str, key_size: int, block: int, mac: str) -> str:
    key, iv, mac_key = b"\x11" * key_size, b"\x44" * block, b"\x33" * hashlib.new(mac).digest_size
    tag = hmac.new(mac_key, aad(len(CONTENT)) + CONTENT, mac).digest()
    plain = CONTENT + tag
    n = block - len(plain) % block
    body = iv + cbc(name, key, iv, plain + bytes([n - 1]) * n)
    return (HEADER + len(body).to_bytes(2, "big") + body).hex()


def gcm_record(name: str, key_size: int) -> str:
    key, salt = b"\x11" * key_size, b"\x22" * 4
    body = SEQ + gcm(name, key, salt + SEQ, CONTENT, aad(len(CONTENT)))
    return (HEADER + len(body).to_bytes(2, "big") + body).hex()


def main() -> None:
    key, nonce, data, extra = b"\x01" * 16, b"\x02" * 12, b"x" * 37, b"y" * 13
    assert gcm("aes", key, nonce, data, extra) == AESGCM(key).encrypt(nonce, data, extra)
    for code, name, key_size, block, mac in [
        (0x0041, "camellia", 16, 16, "sha1"),
        (0xC077, "camellia", 32, 16, "sha384"),
        (0xC03C, "aria", 16, 16, "sha256"),
        (0x0096, "seed", 16, 16, "sha1"),
        (0x0007, "idea", 16, 8, "sha1"),
        (0x000A, "3des", 24, 8, "sha1"),
    ]:
        print(f"0x{code:04x}", cbc_record(name, key_size, block, mac))
    for code, name, key_size in [(0xC07A, "camellia", 16), (0xC051, "aria", 32)]:
        print(f"0x{code:04x}", gcm_record(name, key_size))


if __name__ == "__main__":
    main()
