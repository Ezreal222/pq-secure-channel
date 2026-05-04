"""
Socket server for the PQ secure channel demo.

Usage:
    python -m src.server --kem kyber768 [--host 127.0.0.1] [--port 5050]
    python -m src.server --kem bike-l3

Behavior:
- Accept one client.
- Run the KEM handshake (sends KEM public key, receives KEM ciphertext).
- For each AES-GCM record received, decrypt, print, and echo back
  `b"echo: " + plaintext` as an encrypted record.
"""

from __future__ import annotations

import argparse
import socket
import sys

from src import channel as ch


def serve_one(conn: socket.socket, kem_cli_name: str) -> None:
    print("[server] running handshake...", flush=True)
    secure = ch.server_handshake(conn, kem_cli_name)
    print("[server] handshake OK", flush=True)

    while True:
        try:
            record = ch.recv_frame(conn)
        except (ConnectionError, OSError):
            print("[server] client disconnected", flush=True)
            return
        try:
            plaintext = secure.decrypt(record)
        except ch.ReplayError as e:
            print(f"[server] replay rejected: {e}", flush=True)
            continue
        except Exception as e:
            print(f"[server] decrypt failed ({type(e).__name__}): {e}",
                  flush=True)
            return
        print(f"[server] <- {plaintext!r}", flush=True)
        reply = b"echo: " + plaintext
        try:
            ch.send_frame(conn, secure.encrypt(reply))
        except OSError:
            return


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="PQ secure channel server")
    ap.add_argument("--kem", required=True, choices=sorted(ch.KEM_REGISTRY))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5050)
    args = ap.parse_args(argv)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.host, args.port))
        listener.listen(1)
        print(f"[server] listening on {args.host}:{args.port} "
              f"(KEM={args.kem})", flush=True)
        conn, addr = listener.accept()
        with conn:
            print(f"[server] connection from {addr}", flush=True)
            serve_one(conn, args.kem)
    return 0


if __name__ == "__main__":
    sys.exit(main())
