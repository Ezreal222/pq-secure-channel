"""
Benchmark KEM operations and AES-GCM record throughput.

Usage:
    python -m src.bench --kem kyber768 --iters 1000
    python -m src.bench --kem bike-l3  --iters 1000

Prints:
- One-time sizes (public key, secret key, ciphertext, shared secret).
- Mean +/- stddev over `iters` runs for: KEM keygen, encap, decap,
  end-to-end KEM handshake (keygen + encap + decap, no socket overhead),
  AES-GCM encrypt and decrypt for a fixed-size record.

Notes on methodology:
- Handshake latency is measured as pure cryptographic work, with no socket
  in the loop, so the numbers reflect the algorithms themselves rather than
  loopback noise.
- A short warm-up phase is run and discarded before each timed loop to let
  caches/JITs settle.
- AES-GCM samples encrypt then decrypt N records of `--msg-size` bytes.
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from typing import Callable, List

import oqs

from src.channel import (
    KEM_REGISTRY,
    SENDER_ID_CLIENT,
    SENDER_ID_SERVER,
    SecureChannel,
    derive_aes_key,
    resolve_kem_name,
)


WARMUP_ITERS = 5


def time_n(fn: Callable[[], None], iters: int) -> List[float]:
    samples: List[float] = []
    for _ in range(iters):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return samples


def fmt_us(samples: List[float]) -> str:
    mean_us = statistics.mean(samples) * 1e6
    if len(samples) >= 2:
        stdev_us = statistics.stdev(samples) * 1e6
    else:
        stdev_us = 0.0
    return f"{mean_us:>10.2f} +/- {stdev_us:>9.2f} us"


def fmt_throughput(samples: List[float], msg_bytes: int) -> str:
    mean_s = statistics.mean(samples)
    if mean_s <= 0:
        return "n/a"
    mb_per_s = msg_bytes / mean_s / (1024 * 1024)
    return f"{mb_per_s:>10.1f} MB/s"


def bench_one(cli_kem_name: str, iters: int, msg_size: int) -> None:
    alg = resolve_kem_name(cli_kem_name)
    print(f"\n=== {cli_kem_name}  (liboqs: {alg})  iters={iters} ===")

    # --- Sizes -------------------------------------------------------------
    with oqs.KeyEncapsulation(alg) as kem:
        details = kem.details
    pk_size = details["length_public_key"]
    sk_size = details["length_secret_key"]
    ct_size = details["length_ciphertext"]
    ss_size = details["length_shared_secret"]
    sec_level = details.get("claimed_nist_level", "?")

    print(f"  Claimed NIST level:    {sec_level}")
    print(f"  Public key size:    {pk_size:>8d} bytes")
    print(f"  Secret key size:    {sk_size:>8d} bytes")
    print(f"  Ciphertext size:    {ct_size:>8d} bytes")
    print(f"  Shared secret:      {ss_size:>8d} bytes")

    # --- Keygen ------------------------------------------------------------
    def _keygen() -> None:
        with oqs.KeyEncapsulation(alg) as k:
            k.generate_keypair()

    for _ in range(WARMUP_ITERS):
        _keygen()
    keygen_samples = time_n(_keygen, iters)
    print(f"  Keygen:           {fmt_us(keygen_samples)}")

    # --- Encap (vs a fixed server pk) -------------------------------------
    server = oqs.KeyEncapsulation(alg)
    server_pk = server.generate_keypair()

    captured_cts: List[bytes] = []

    def _encap() -> None:
        with oqs.KeyEncapsulation(alg) as c:
            ct, _ = c.encap_secret(server_pk)
            captured_cts.append(ct)

    for _ in range(WARMUP_ITERS):
        _encap()
    captured_cts.clear()
    encap_samples = time_n(_encap, iters)
    print(f"  Encap:            {fmt_us(encap_samples)}")

    # --- Decap (replay each captured ct against `server`) -----------------
    # Pre-generate a fresh batch of cts so timing isn't entangled with encap.
    decap_inputs: List[bytes] = []
    for _ in range(iters + WARMUP_ITERS):
        with oqs.KeyEncapsulation(alg) as c:
            ct, _ = c.encap_secret(server_pk)
            decap_inputs.append(ct)

    for ct in decap_inputs[:WARMUP_ITERS]:
        server.decap_secret(ct)

    decap_samples: List[float] = []
    for ct in decap_inputs[WARMUP_ITERS:]:
        t0 = time.perf_counter()
        server.decap_secret(ct)
        decap_samples.append(time.perf_counter() - t0)
    server.free()
    print(f"  Decap:            {fmt_us(decap_samples)}")

    # --- End-to-end KEM handshake (no sockets) ----------------------------
    def _handshake() -> None:
        with oqs.KeyEncapsulation(alg) as s, oqs.KeyEncapsulation(alg) as c:
            pk = s.generate_keypair()
            ct, ss_c = c.encap_secret(pk)
            ss_s = s.decap_secret(ct)
            assert ss_c == ss_s

    for _ in range(WARMUP_ITERS):
        _handshake()
    e2e_samples = time_n(_handshake, iters)
    print(f"  E2E handshake:    {fmt_us(e2e_samples)}")

    # --- AES-GCM record throughput ---------------------------------------
    # One real handshake, then push iters records through SecureChannel.
    with oqs.KeyEncapsulation(alg) as s, oqs.KeyEncapsulation(alg) as c:
        pk = s.generate_keypair()
        ct, ss_c = c.encap_secret(pk)
        ss_s = s.decap_secret(ct)
    aes_key = derive_aes_key(ss_s, pk + ct)
    sender = SecureChannel(aes_key, SENDER_ID_CLIENT)
    receiver = SecureChannel(aes_key, SENDER_ID_SERVER)

    msg = b"\xab" * msg_size
    records: List[bytes] = []

    encrypt_samples: List[float] = []
    for _ in range(WARMUP_ITERS):
        records.append(sender.encrypt(msg))
    records.clear()
    # Reset send counter is intentional? No — keep going. But we need
    # receiver's last_seen aligned. We'll just run encrypt timing first,
    # collect records, then time decrypt.
    for _ in range(iters):
        t0 = time.perf_counter()
        rec = sender.encrypt(msg)
        encrypt_samples.append(time.perf_counter() - t0)
        records.append(rec)

    # Skip the warm-up records on the receiver by fast-forwarding last_seen.
    # Simpler: feed all records to receiver in order; receiver was not used
    # during warm-up, so we need to also feed those warm-up records if any.
    # We already cleared them, so just feed `records` (post-warmup) — but
    # the sender's counter has advanced past WARMUP_ITERS, so receiver will
    # accept counter=WARMUP_ITERS first and reject earlier ones. That's
    # exactly what we want.
    decrypt_samples: List[float] = []
    for rec in records:
        t0 = time.perf_counter()
        receiver.decrypt(rec)
        decrypt_samples.append(time.perf_counter() - t0)

    print(f"  AES-GCM encrypt ({msg_size}B record):  "
          f"{fmt_us(encrypt_samples)}    {fmt_throughput(encrypt_samples, msg_size)}")
    print(f"  AES-GCM decrypt ({msg_size}B record):  "
          f"{fmt_us(decrypt_samples)}    {fmt_throughput(decrypt_samples, msg_size)}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="PQ secure channel benchmarks")
    ap.add_argument("--kem", choices=sorted(KEM_REGISTRY), required=True)
    ap.add_argument("--iters", type=int, default=1000)
    ap.add_argument("--msg-size", type=int, default=1024,
                    help="AES-GCM record plaintext size in bytes")
    args = ap.parse_args(argv)

    if args.iters < 2:
        print("--iters must be >= 2", file=sys.stderr)
        return 2

    bench_one(args.kem, args.iters, args.msg_size)
    return 0


if __name__ == "__main__":
    sys.exit(main())
