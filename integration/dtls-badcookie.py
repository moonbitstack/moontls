#!/usr/bin/env python3
"""Ask a DTLS 1.2 server for a cookie, then present a wrong one.

    dtls-badcookie.py <port>

The server is this library's DTLS 1.2 server with cookies demanded. The script is a hand-written
DTLS client because no peer here can be told to corrupt a cookie: OpenSSL always echoes the one it
was given, and the library's own client keeps its copy private.

Three datagrams:

1. a ClientHello with no cookie, which has to be answered with a HelloVerifyRequest;
2. the same ClientHello carrying that cookie with one octet flipped, which has to be answered with
   another HelloVerifyRequest (RFC 6347 §4.2.1 lets a server re-challenge) or with an alert —
   never with a ServerHello, which would mean the check did not happen;
3. nothing further: the case is over once the server has refused to move on.

Exit status is 0 when the wrong cookie was refused, 1 when the server went on, 2 when the server
never asked for a cookie at all.
"""

import os
import socket
import struct
import sys

HELLO_VERIFY_REQUEST = 3
SERVER_HELLO = 2
CLIENT_HELLO = 1
ALERT = 21


def client_hello(cookie: bytes) -> bytes:
    body = b"\xfe\xfd" + os.urandom(32) + b"\x00"
    body += bytes([len(cookie)]) + cookie
    body += struct.pack("!H", 2) + b"\xc0\x2b"
    body += b"\x01\x00"
    body += struct.pack("!H", 0)
    handshake = bytes([CLIENT_HELLO]) + struct.pack("!I", len(body))[1:]
    handshake += struct.pack("!H", 0) + struct.pack("!I", 0)[1:] + struct.pack("!I", len(body))[1:]
    return handshake + body


def record(payload: bytes, sequence: int) -> bytes:
    # Epoch (2) then sequence (6), then the length: thirteen octets of record header.
    header = bytes([22]) + b"\xfe\xfd" + struct.pack("!H", 0) + sequence.to_bytes(6, "big")
    return header + struct.pack("!H", len(payload)) + payload


def handshake_of(datagram: bytes):
    """The first handshake message in a datagram, or None for anything else."""
    if len(datagram) < 13:
        return None
    kind = datagram[0]
    if kind == ALERT:
        return ("alert", datagram[13:15])
    if kind != 22:
        return None
    at = 13
    while at + 12 <= len(datagram):
        message_seq = struct.unpack("!H", datagram[at + 4 : at + 6])[0]
        length = int.from_bytes(datagram[at + 9 : at + 12], "big")
        if datagram[at] == HELLO_VERIFY_REQUEST:
            cookie_len = datagram[at + 12 + 2]
            cookie = datagram[at + 12 + 3 : at + 12 + 3 + cookie_len]
            return ("verify", cookie, message_seq)
        if datagram[at] == SERVER_HELLO:
            return ("server", None, message_seq)
        at += 12 + length
    return None


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    port = int(sys.argv[1])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.connect(("127.0.0.1", port))

    sock.send(record(client_hello(b""), 0))
    first = handshake_of(sock.recvfrom(65535)[0])
    if not first or first[0] != "verify":
        print(f"expected a HelloVerifyRequest, got {first}", file=sys.stderr)
        return 2
    cookie = first[1]
    if not cookie:
        print("the HelloVerifyRequest carried no cookie", file=sys.stderr)
        return 2

    wrong = bytearray(cookie)
    wrong[0] ^= 0xFF
    sock.send(record(client_hello(bytes(wrong)), 1))
    second = handshake_of(sock.recvfrom(65535)[0])
    if second and second[0] == "server":
        print("a wrong cookie was accepted: ServerHello", file=sys.stderr)
        return 1
    if second and second[0] in ("verify", "alert"):
        print(f"refused, answered with {second[0]}")
        return 0
    print(f"neither a re-challenge nor an alert: {second}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
