#!/usr/bin/env python3
# Copyright 2026 Leo Cheng
# SPDX-License-Identifier: Apache-2.0
"""The SRP end of the interop matrix (RFC 5054), on tlslite-ng.

OpenSSL 3's SRP is deprecated and broken in both roles: its s_server segfaults, and its s_client
derives a premaster that neither tlslite-ng nor this library agrees with. tlslite-ng is the
implementation the two directions are checked against.

    tlslite_srp.py client PORT KX
    tlslite_srp.py server PORT KX [CHAIN KEY]

KX is tlslite-ng's name for the key exchange: `srp_sha`, or `srp_sha_rsa` with a certificate.
The user is alice with password123 in RFC 5054's 2048-bit group, as `tls_interop.sh` configures
the other end. Prints `OK <cipher> <line>` when a line went across, `FAIL <reason>` otherwise.
"""

import socket
import sys

from tlslite.api import HandshakeSettings, TLSConnection, VerifierDB, X509CertChain, parsePEMKey

USER, PASSWORD = "alice", "password123"


def settings(kx: str) -> HandshakeSettings:
    s = HandshakeSettings()
    s.minVersion = (3, 3)
    s.maxVersion = (3, 3)
    s.cipherNames = ["aes128"]
    s.macNames = ["sha"]
    s.keyExchangeNames = [kx]
    return s


def client(port: int, kx: str) -> None:
    c = TLSConnection(socket.create_connection(("127.0.0.1", port), timeout=10))
    c.handshakeClientSRP(USER, PASSWORD, settings=settings(kx))
    c.write(b"ping\n")
    print("OK", c.getCipherName(), c.read(max=5), flush=True)


def server(port: int, kx: str, chain: str | None, key: str | None) -> None:
    db = VerifierDB()
    db.create()
    # The server looks a user up by the bytes the hello carried.
    db[USER.encode()] = VerifierDB.makeVerifier(USER, PASSWORD, 2048)
    extra = {}
    if chain and key:
        certs = X509CertChain()
        certs.parsePemList(open(chain, encoding="ascii").read())
        extra = {"certChain": certs, "privateKey": parsePEMKey(open(key, encoding="ascii").read(), private=True)}
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(4)
    print("listening", flush=True)
    # The script's readiness probe connects and leaves without a hello; the next connection is the case.
    for _ in range(4):
        conn, _ = listener.accept()
        c = TLSConnection(conn)
        try:
            c.handshakeServer(verifierDB=db, settings=settings(kx), **extra)
        except Exception as e:  # noqa: BLE001
            print("FAIL", type(e).__name__, e, flush=True)
            continue
        line = c.read(max=5)
        c.write(line)
        print("OK", c.getCipherName(), line, flush=True)
        return


def main() -> int:
    role, port, kx, *files = sys.argv[1:]
    try:
        if role == "client":
            client(int(port), kx)
        else:
            server(int(port), kx, *(files or [None, None]))
    except Exception as e:  # noqa: BLE001
        print("FAIL", type(e).__name__, e, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
