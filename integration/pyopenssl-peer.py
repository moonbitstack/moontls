#!/usr/bin/env python3
"""A peer for the interop matrix, written against pyOpenSSL.

    pyopenssl-peer.py client <host> <port> <ca.pem> [sni=NAME] [alpn=a,b] [cert=PATH key=PATH]
    pyopenssl-peer.py server <port> <chain.pem> <key.pem> [alpn=a,b] [clientca=PATH]

Both sides speak lines: the server answers every line it reads with the same line, and the client
sends one, reads it back, and prints where the connection landed.

pyOpenSSL is a binding over OpenSSL rather than a second engine, so what these cases judge is the
binding's own defaults and API — the `ssl` module wraps the same library with a different set of
them — and the direction each peer plays is the one the `ssl` section does not cover.
"""

import select
import socket
import sys

from OpenSSL import SSL

HANDSHAKE_TIMEOUT = 20


def parse(argv):
    options = {"sni": "localhost", "alpn": [], "cert": None, "key": None, "clientca": None}
    for arg in argv:
        if "=" not in arg:
            sys.exit(f"unknown option: {arg}")
        name, value = arg.split("=", 1)
        if name == "sni":
            options["sni"] = value
        elif name == "alpn":
            options["alpn"] = [one.encode() for one in value.split(",") if one]
        elif name in ("cert", "key", "clientca"):
            options[name] = value
        else:
            sys.exit(f"unknown option: {arg}")
    return options


def text(value):
    """pyOpenSSL answers `str` for these in recent releases and `bytes` in older ones."""
    if value is None:
        return ""
    return value.decode() if isinstance(value, bytes) else str(value)


def read_line(conn, sock):
    """One line from `conn`, waiting on the socket when OpenSSL has nothing yet.

    A socket with a timeout is non-blocking underneath, and OpenSSL then answers every read with
    WantRead rather than blocking; the harness's own `timeout` bounds a case that never answers.
    """
    line = b""
    while not line.endswith(b"\n"):
        try:
            chunk = conn.recv(4096)
        except SSL.WantReadError:
            select.select([sock], [], [], HANDSHAKE_TIMEOUT)
            continue
        if not chunk:
            break
        line += chunk
    return line


def client(host, port, ca, options):
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
    ctx.load_verify_locations(ca)
    ctx.set_verify(SSL.VERIFY_PEER, lambda *_: True)
    if options["cert"]:
        ctx.use_certificate_chain_file(options["cert"])
        ctx.use_privatekey_file(options["key"])
    if options["alpn"]:
        ctx.set_alpn_protos(options["alpn"])

    # Blocking for the handshake: pyOpenSSL hands the socket to OpenSSL, and a socket with a
    # timeout is non-blocking underneath, which turns every read OpenSSL makes into WantRead.
    sock = socket.create_connection((host, port))
    conn = SSL.Connection(ctx, sock)
    conn.set_tlsext_host_name(options["sni"].encode())
    conn.set_connect_state()
    conn.do_handshake()
    conn.sendall(b"ping\n")
    line = read_line(conn, sock)
    version = text(conn.get_protocol_version_name()).replace("TLSv", "")
    suite = text(conn.get_cipher_name())
    alpn = conn.get_alpn_proto_negotiated()
    print(
        "ok version=%s suite=%s alpn=%s resumed=%d bytes=%d first=%s"
        % (
            version,
            suite,
            text(alpn) if alpn else "-",
            0,
            len(line.strip()),
            line.decode(errors="replace").strip(),
        )
    )
    return 0


def server(port, chain, key, options):
    ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
    ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
    ctx.use_certificate_chain_file(chain)
    ctx.use_privatekey_file(key)
    if options["clientca"]:
        ctx.load_verify_locations(options["clientca"])
        ctx.set_verify(
            SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, lambda *_: True
        )
    wanted = options["alpn"]
    if wanted:
        ctx.set_alpn_select_callback(
            lambda _conn, offered: next((one for one in wanted if one in offered), None)
        )

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", int(port)))
    listener.listen(8)
    print(f"listening on {port}", file=sys.stderr, flush=True)
    while True:
        raw, _ = listener.accept()
        try:
            conn = SSL.Connection(ctx, raw)
            conn.set_accept_state()
            conn.do_handshake()
            while True:
                line = read_line(conn, raw)
                if not line:
                    raise ConnectionError("closed")
                conn.sendall(line)
        except Exception:
            # One connection per case: a peer that failed is the case's answer, not the server's.
            pass
        finally:
            raw.close()


def main(argv):
    if not argv or argv[0] not in ("client", "server"):
        sys.exit("client|server")
    mode = argv[0]
    if len(argv) < 4:
        sys.exit("too few arguments")
    head = argv[1:4]
    options = parse(argv[4:])
    if mode == "client":
        return client(head[0], int(head[1]), head[2], options)
    return server(head[0], head[1], head[2], options)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) or 0)
