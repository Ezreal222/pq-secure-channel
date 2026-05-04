"""
Socket client for the PQ secure channel demo.

Usage:
    python -m src.client --kem kyber768 [--host 127.0.0.1] [--port 5050]
    python -m src.client --kem bike-l3

Behavior:
- Connect, run the KEM handshake.
- A reader thread prints every decrypted echo from the server.
- The main thread reads stdin lines, encrypts each as a record, and sends
  it. On EOF, closes the connection and exits.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading

from src import channel as ch


def reader_loop(sock: socket.socket, secure: ch.SecureChannel) -> None:
    while True:
        try:
            record = ch.recv_frame(sock)
        except (ConnectionError, OSError):
            return
        try:
            plaintext = secure.decrypt(record)
        except ch.ReplayError as e:
            print(f"[client] replay rejected: {e}", flush=True)
            continue
        except Exception as e:
            print(f"[client] decrypt failed ({type(e).__name__}): {e}",
                  flush=True)
            return
        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            text = repr(plaintext)
        print(f"[client] <- {text}", flush=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="PQ secure channel client")
    ap.add_argument("--kem", required=True, choices=sorted(ch.KEM_REGISTRY))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5050)
    args = ap.parse_args(argv)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((args.host, args.port))
        print(f"[client] connected to {args.host}:{args.port}; "
              f"running handshake (KEM={args.kem})...", flush=True)
        secure = ch.client_handshake(sock, args.kem)
        print("[client] handshake OK; type lines, Ctrl-D to quit", flush=True)

        t = threading.Thread(target=reader_loop, args=(sock, secure),
                             daemon=True)
        t.start()

        for line in sys.stdin:
            payload = line.rstrip("\n").encode("utf-8")
            if not payload:
                continue
            try:
                ch.send_frame(sock, secure.encrypt(payload))
            except OSError:
                break

        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
