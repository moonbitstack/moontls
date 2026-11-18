#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""Write src/record/registry12.mbt, the TLS 1.2 suites beyond the AES and ChaCha20 rows written by hand.

The rows come from IANA's TLS Cipher Suites registry, not from memory: every suite whose name
parses into a key exchange this library runs and a record protection it has is emitted with the
code the registry gives it. A name is TLS_<exchange>_WITH_<bulk>_<hash>, and the hash is the MAC of
a CBC suite and, from SHA256 up, the PRF's; a CBC suite with SHA-1's MAC keeps TLS 1.2's SHA-256
PRF (RFC 5246 §5).

Usage:
    python scripts/gen_suites12.py [registry.csv] [--check]

Without a path the registry is fetched from iana.org.
"""

from __future__ import annotations

import argparse
import csv
import io
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "src" / "record" / "registry12.mbt"
REGISTRY = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"

# The key exchanges, by the registry's spelling, as (Exchange, Auth).
EXCHANGES = {
    "ECDHE_ECDSA": ("Ecdhe", "Ecdsa"),
    "ECDHE_RSA": ("Ecdhe", "Rsa"),
    "DHE_RSA": ("Dhe", "Rsa"),
    "DHE_DSS": ("Dhe", "Dss"),
    "DH_RSA": ("Dh", "Rsa"),
    "DH_DSS": ("Dh", "Dss"),
    "RSA": ("Rsa", "Rsa"),
    "PSK": ("Psk", "Shared"),
    "DHE_PSK": ("DhePsk", "Shared"),
    # RFC 6655 writes its two DHE_PSK CCM_8 suites the other way round.
    "PSK_DHE": ("DhePsk", "Shared"),
    "ECDHE_PSK": ("EcdhePsk", "Shared"),
    "RSA_PSK": ("RsaPsk", "Rsa"),
    "SRP_SHA": ("Srp", "Shared"),
    "SRP_SHA_RSA": ("Srp", "Rsa"),
    "SRP_SHA_DSS": ("Srp", "Dss"),
}

# The block ciphers, by the registry's spelling.
CIPHERS = {
    "AES_128": "Aes128",
    "AES_256": "Aes256",
    "CAMELLIA_128": "Camellia128",
    "CAMELLIA_256": "Camellia256",
    "ARIA_128": "Aria128",
    "ARIA_256": "Aria256",
    "SEED": "Seed",
    "IDEA": "Idea",
    "3DES_EDE": "TripleDes",
}

HASHES = {"SHA": "Sha1", "SHA256": "Sha256", "SHA384": "Sha384"}


def bulk_of(text: str) -> tuple[str, str] | None:
    """The `Bulk` and the PRF digest a suite name's tail stands for."""
    if text == "CHACHA20_POLY1305_SHA256":
        return "ChaCha20Poly1305", "Sha256"
    for name, cipher in CIPHERS.items():
        if not text.startswith(name + "_"):
            continue
        rest = text[len(name) + 1 :]
        if rest.startswith("GCM_") and rest[4:] in ("SHA256", "SHA384"):
            return f"Gcm({cipher})", HASHES[rest[4:]]
        # RFC 8442 spells its ECDHE_PSK CCM suites with the PRF's hash after the mode.
        if rest in ("CCM", "CCM_8", "CCM_SHA256", "CCM_8_SHA256"):
            return f"Ccm({cipher}, tag={8 if rest.startswith('CCM_8') else 16})", "Sha256"
        if rest.startswith("CBC_") and rest[4:] in HASHES:
            mac = HASHES[rest[4:]]
            return f"Cbc({cipher}, mac={mac})", "Sha384" if mac == "Sha384" else "Sha256"
    return None


def rows(registry: str) -> list[str]:
    out = []
    for record in csv.reader(io.StringIO(registry)):
        if len(record) < 2 or not record[1].startswith("TLS_") or "_WITH_" not in record[1]:
            continue
        name = record[1]
        exchange, tail = name[4:].split("_WITH_", 1)
        if exchange not in EXCHANGES:
            continue
        found = bulk_of(tail)
        if found is None:
            continue
        bulk, digest = found
        hi, lo = record[0].strip('"').split(",")
        code = (int(hi, 16) << 8) | int(lo, 16)
        kx, auth = EXCHANGES[exchange]
        out.append((code, f"  row(0x{code:04x}, {kx}, {auth}, {bulk}, {digest}),"))
    return [line for _, line in sorted(out)]


def render(registry: str, already: set[int]) -> str:
    body = [line for line in rows(registry) if int(line.split(",")[0][6:], 16) not in already]
    return (
        "// Copyright 2026 Leo Cheng\n"
        "// SPDX-License-Identifier: Apache-2.0\n"
        "\n"
        "// Written by scripts/gen_suites12.py from IANA's TLS Cipher Suites registry.\n"
        "\n"
        "///|\n"
        "/// The TLS 1.2 suites beyond `all12`'s first rows, by code: Camellia (RFC 5932, RFC 6367), ARIA\n"
        "/// (RFC 6209), SEED (RFC 4162), IDEA (RFC 5469) and triple DES; the pre-shared key exchanges\n"
        "/// (RFC 4279, RFC 5487, RFC 5489, RFC 8442), SRP (RFC 5054), DSS certificates and static\n"
        "/// Diffie-Hellman (RFC 5246). Off unless named.\n"
        "let registry12 : Array[Suite12] = [\n" + "\n".join(body) + "\n]\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("registry", nargs="?", help="a saved copy of the registry's CSV")
    parser.add_argument("--check", action="store_true", help="fail instead of writing")
    args = parser.parse_args()
    if args.registry:
        registry = pathlib.Path(args.registry).read_text(encoding="utf-8")
    else:
        with urllib.request.urlopen(REGISTRY) as response:
            registry = response.read().decode("utf-8")
    # The rows `suite12.mbt` writes by hand, which this file leaves out.
    table = (ROOT / "src" / "record" / "suite12.mbt").read_text(encoding="utf-8")
    already = {int(part.split(",")[0], 16) for part in table.split("row(0x")[1:]}
    page = render(registry, already)
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != page:
            print("src/record/registry12.mbt: stale; rerun scripts/gen_suites12.py", file=sys.stderr)
            return 1
        print("src/record/registry12.mbt: up to date")
        return 0
    OUT.write_text(page, encoding="utf-8", newline="\n")
    print(f"src/record/registry12.mbt: {page.count('row(')} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
