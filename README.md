# pq-secure-channel

Two quantum-resistant secure communication channels between two parties, built for NYU CS6903 Project 3.5. The channels protect against eavesdropping, modification, and replay. The KEM is swappable: **Kyber768** (lattice-based, exposed by liboqs as ML-KEM-768 / FIPS 203) or **BIKE-L3** (code-based, QC-MDPC). Everything else — handshake glue, AES-256-GCM record layer, replay-protected nonces, framing — is identical across both, so the only difference between the two demos is the KEM.

> **Note on the code-based pick.** The original plan was HQC-192. HQC was removed from `liboqs` in 2024 after a security advisory from the HQC team and is pending re-introduction to match the NIST-standardized version (selected March 2025). BIKE-L3 is the substitute used here: it is also code-based, sits at the same NIST security level (3), and gives a more apples-to-apples size/runtime comparison with Kyber768 than Classic McEliece would.

## Design

- **Handshake.** Server generates a fresh KEM keypair per connection and sends the public key. Client encapsulates, sends the resulting ciphertext, and both sides hold the same shared secret.
- **Key derivation.** `aes_key = HKDF-SHA256(ikm = shared_secret, salt = SHA256(kem_pk || kem_ct), info = b"pq-secure-channel v1 aes-256-gcm", L = 32)`. The transcript-hash salt binds the derived key to the exact handshake bytes both sides observed.
- **Record layer.** AES-256-GCM with a 12-byte nonce of the form `sender_id (4B BE) || counter (8B BE)`. Client uses sender ID `0x00000001`, server uses `0x00000002`, so the two directions cannot collide on a nonce. Counter starts at 0 and increments per outgoing record.
- **Replay protection.** Each receiver tracks the last-seen counter per sender ID and rejects any record whose counter is ≤ it. On TCP this also cleanly rejects out-of-order delivery.
- **Integrity.** AES-GCM's authentication tag covers the ciphertext under the nonce, so any modification to either fails decryption.
- **Wire framing.** Every blob (KEM public key, KEM ciphertext, each AES-GCM record) is sent as a 4-byte big-endian length prefix followed by the payload. Needed because BIKE-L3 public keys and ciphertexts are several KB.

### Threats covered

| Threat | Mechanism |
| --- | --- |
| Passive eavesdropping | AES-256-GCM under a fresh per-connection key |
| Tampering with messages on the wire | AES-GCM tag verification |
| Replay of a captured record | Per-sender monotonic counter, last-seen tracking |
| Out-of-order injection | Same monotonic-counter check |

### Not covered (deliberate)

The handshake is **not authenticated**. An active attacker between client and server could substitute their own KEM public key and run two independent sessions. Adding server authentication would require a PQ signature (e.g., ML-DSA / Dilithium) over the public key, plus a trust anchor on the client. This project's scope is the three threats called out in the spec — eavesdropping, modification, replay — and the unauthenticated handshake is acceptable for that scope.

## Install

`liboqs-python` is a `ctypes` wrapper, so it needs the **shared** liboqs library (`.dylib` on macOS, `.so` on Linux). Homebrew's `liboqs` formula installs only the static archive (`.a`), so on macOS we build liboqs from source.

### macOS

```bash
# 1. Build dependencies.
brew install cmake ninja openssl@3

# 2. Build liboqs as a shared library and install to ~/.local/oqs.
git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git ~/src/liboqs
cd ~/src/liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX="$HOME/.local/oqs" \
              -DOQS_BUILD_ONLY_LIB=ON \
              -DBUILD_SHARED_LIBS=ON ..
ninja && ninja install

# 3. Tell liboqs-python where the dylib lives.
export OQS_INSTALL_PATH="$HOME/.local/oqs"
export DYLD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib:$DYLD_LIBRARY_PATH"

# 4. Python deps.
cd /path/to/pq-secure-channel
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 5. Sanity check.
python3 -c "import oqs; print('ML-KEM-768' in oqs.get_enabled_kem_mechanisms(), 'BIKE-L3' in oqs.get_enabled_kem_mechanisms())"
# Expected: True True
```

For future shells, add the two `export` lines to your `~/.zshrc`.

### Linux

Same steps as macOS, except:

- Replace `brew install` with your package manager (e.g. `apt install cmake ninja-build libssl-dev`).
- Replace `DYLD_LIBRARY_PATH` with `LD_LIBRARY_PATH`.

### If `liboqs-python` lags behind liboqs

The PyPI build is occasionally a release behind. If `import oqs` warns about a version mismatch and a KEM you expect is missing, install from upstream against your already-built liboqs:

```bash
pip install --no-build-isolation \
    git+https://github.com/open-quantum-safe/liboqs-python.git
```

## Run

In one terminal:

```bash
source .venv/bin/activate
python -m src.server --kem kyber768       # or --kem bike-l3
```

In another:

```bash
source .venv/bin/activate
python -m src.client --kem kyber768       # must match the server's --kem
```

Type lines on the client; the server prints what it decrypted and echoes `echo: <line>` back through the same channel. Ctrl-D on the client closes the connection.

## Bench

```bash
python -m src.bench --kem kyber768 --iters 1000
python -m src.bench --kem bike-l3  --iters 1000
```

The bench reports public/secret/ciphertext/shared-secret sizes (one-time, from `oqs.KeyEncapsulation.details`) and mean ± stddev for: KEM keygen, encap, decap, end-to-end KEM handshake (no socket in the loop), and AES-GCM encrypt/decrypt for a `--msg-size` byte record.

### Sample comparison

Numbers below are from a 50-iteration run on macOS (Apple Silicon, Python 3.11.7, liboqs 0.15.0, liboqs-python 0.14.1). Both KEMs claim NIST security level 3.

| Metric | Kyber768 (ML-KEM-768) | BIKE-L3 | Ratio (BIKE / Kyber) |
| --- | ---: | ---: | ---: |
| Public key size | 1,184 B | 3,083 B | 2.6x |
| Secret key size | 2,400 B | 10,105 B | 4.2x |
| Ciphertext size | 1,088 B | 3,115 B | 2.9x |
| Shared secret size | 32 B | 32 B | 1.0x |
| Keygen | 12.35 +/- 0.88 us | 16,481.85 +/- 589.32 us | ~1,335x |
| Encap | 13.90 +/- 0.97 us | 832.25 +/- 32.70 us | ~60x |
| Decap | 12.24 +/- 0.17 us | 12,815.69 +/- 503.77 us | ~1,047x |
| E2E KEM handshake | 38.50 +/- 1.12 us | 29,662.03 +/- 435.15 us | ~770x |
| AES-GCM encrypt (1 KB record) | 1.13 us / 860.5 MB/s | 1.54 us / 632.5 MB/s | KEM-independent (run noise) |
| AES-GCM decrypt (1 KB record) | 1.27 us / 768.5 MB/s | 1.27 us / 770.9 MB/s | KEM-independent |

**Reading the table.** Kyber768 wins on every KEM-side metric and by very large margins, especially keygen and decap. BIKE-L3's bottleneck is keygen and decap, both involving QC-MDPC code operations whose constant-time implementations are intrinsically expensive; encap is much cheaper and BIKE is "only" ~60x slower there. Sizes are also clearly in Kyber's favor — pk and ct are both ~3x smaller — which matters whenever the public key has to be shipped over the wire on every connection (as in our handshake).

The AES-GCM rows should be statistically identical between the two KEM columns: the record layer doesn't depend on which KEM was used for key agreement. Small differences are run-to-run timer noise, and the gap shrinks toward zero as `--iters` increases.

**Takeaway for the spec's "design validity" criterion.** Both schemes give the same 256-bit AES key from a level-3-secure handshake, and both produce a working channel that resists eavesdropping, modification, and replay. For interactive 2-party communication where handshake latency is user-visible, Kyber768 is the obviously practical choice; BIKE remains relevant as a hedge against unforeseen weaknesses in the lattice family, since its security rests on a fundamentally different (code-based) assumption.

## Tests

```bash
pytest -q
```

Required cases (each parametrized over both KEMs): correct decryption, modified-ciphertext rejection, replay rejection, out-of-order rejection. Plus a few helper-level sanity tests (nonce round-trip, unknown-KEM error, short-record error, distinct sender IDs).

## Layout

```
pq-secure-channel/
├── README.md
├── requirements.txt
├── setup_liboqs.sh
├── src/
│   ├── __init__.py
│   ├── channel.py     # KEM registry, handshake, SecureChannel, framing
│   ├── server.py      # socket server demo
│   ├── client.py      # socket client demo
│   └── bench.py       # benchmarks
└── tests/
    ├── __init__.py
    └── test_channel.py
```
