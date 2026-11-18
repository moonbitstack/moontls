#!/usr/bin/env python3
"""Mangle a datagram stream between a DTLS client and a DTLS server.

    udp-mangle.py <listen-port> <target-port> <mode>

Modes, each of which is a thing a network does and a TLS handshake has to survive:

    drop-first   lose the client's first datagram, so the handshake can only finish if the client
                 retransmits and the server keeps no state it cannot rebuild from the second one
    duplicate    deliver every client datagram twice, which puts two copies of the same record
                 sequence number in front of the server's replay window
    reorder      hold the server's first two datagrams and deliver the second one first, which is
                 the smallest reordering that puts two distinct handshake messages in the other
                 order; a receiver that reassembles by record sequence number still gets them

A proxy rather than `tc netem` because the case has to run in CI, where there is no root and no
network namespace to shape. This is the same loss the RFC's own retransmission rules are written
for; what it does not do is delay, so a case that passes here has retransmitted, not waited.
"""

import select
import socket
import sys


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    listen_port, target_port, mode = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
    if mode not in ("drop-first", "duplicate", "reorder"):
        print(f"unknown mode {mode}", file=sys.stderr)
        return 2

    front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    front.bind(("127.0.0.1", listen_port))
    back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    back.connect(("127.0.0.1", target_port))

    client = None
    first = True
    held = []
    while True:
        readable, _, _ = select.select([front, back], [], [], 30)
        if not readable:
            return 1
        for sock in readable:
            data, addr = sock.recvfrom(65535)
            if sock is front:
                client = addr
                if mode == "drop-first" and first:
                    first = False
                    continue
                first = False
                if mode == "duplicate":
                    back.send(data)
                    back.send(data)
                else:
                    back.send(data)
            else:
                if client is None:
                    continue
                if mode == "reorder":
                    held.append(data)
                    if len(held) == 2:
                        front.sendto(held[1], client)
                        front.sendto(held[0], client)
                        held.clear()
                else:
                    front.sendto(data, client)


if __name__ == "__main__":
    sys.exit(main())
