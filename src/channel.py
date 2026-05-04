"""
KEM-agnostic post-quantum secure channel.

Pieces:
- KEM_REGISTRY:         user-facing CLI names -> liboqs algorithm names.
- derive_aes_key:       HKDF-SHA256 from KEM shared secret + transcript hash.
- make_nonce/parse_nonce: 12-byte AES-GCM nonces = sender_id (4B) || counter (8B).
- SecureChannel:        AES-256-GCM record layer with per-sender replay tracking.
- server_handshake / client_handshake: run a KEM handshake over a socket and
                        return a ready-to-use SecureChannel.
- send_frame / recv_frame: 4-byte length-prefixed wire framing for blobs.

Threat model covered: passive eavesdropping (AES-GCM), modification (GCM tag),
replay and out-of-order delivery (per-sender monotonic counter). The handshake
is intentionally NOT authenticated -- see README.
"""

from __future__ import annotations

import hashlib
import socket as _socket
import struct
import threading
from typing import Tuple

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------------------------------------------------------------------------
# KEM registry
# ---------------------------------------------------------------------------

# CLI name -> liboqs mechanism name.
# Kyber768 was standardized in FIPS 203 as ML-KEM-768; we accept the legacy
# CLI alias for clarity but use the standardized name internally.
KEM_REGISTRY: dict[str, str] = {
    "kyber768": "ML-KEM-768",
    "bike-l3":  "BIKE-L3",
}


def resolve_kem_name(cli_name: str) -> str:
    """Map a CLI flag value (e.g. 'kyber768') to the liboqs algorithm name."""
    try:
        return KEM_REGISTRY[cli_name.lower()]
    except KeyError as exc:
        raise ValueError(
            f"Unknown KEM {cli_name!r}. Choose one of: "
            f"{sorted(KEM_REGISTRY)}"
        ) from exc


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SENDER_ID_CLIENT: int = 0x00000001
SENDER_ID_SERVER: int = 0x00000002

NONCE_LEN: int = 12              # AES-GCM standard nonce length
GCM_TAG_LEN: int = 16            # AES-GCM tag length
LENGTH_PREFIX_LEN: int = 4       # 4-byte big-endian frame header

HKDF_INFO: bytes = b"pq-secure-channel v1 aes-256-gcm"


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_aes_key(shared_secret: bytes, transcript: bytes) -> bytes:
    """
    HKDF-SHA256(ikm=shared_secret, salt=SHA256(transcript), info=HKDF_INFO, L=32).

    `transcript` should be `kem_public_key || kem_ciphertext`. Hashing it into
    the salt binds the AES key to the exact handshake bytes both peers saw,
    so any handshake tampering yields different keys on the two sides and the
    very first record will fail GCM authentication.
    """
    salt = hashlib.sha256(transcript).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=HKDF_INFO,
    ).derive(shared_secret)


# ---------------------------------------------------------------------------
# Nonces
# ---------------------------------------------------------------------------

def make_nonce(sender_id: int, counter: int) -> bytes:
    """12-byte nonce: 4-byte BE sender ID || 8-byte BE counter."""
    if not 0 <= sender_id < 2**32:
        raise ValueError("sender_id out of uint32 range")
    if not 0 <= counter < 2**64:
        raise ValueError("counter out of uint64 range")
    return struct.pack(">IQ", sender_id, counter)


def parse_nonce(nonce: bytes) -> Tuple[int, int]:
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes, got {len(nonce)}")
    sender_id, counter = struct.unpack(">IQ", nonce)
    return sender_id, counter


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

def send_frame(sock: _socket.socket, payload: bytes) -> None:
    """Send a 4-byte length-prefixed frame."""
    if len(payload) >= 2**32:
        raise ValueError("frame too large for 4-byte length prefix")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_exact(sock: _socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection mid-frame")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock: _socket.socket) -> bytes:
    """Read one length-prefixed frame and return its payload."""
    header = _recv_exact(sock, LENGTH_PREFIX_LEN)
    (length,) = struct.unpack(">I", header)
    return _recv_exact(sock, length)


# ---------------------------------------------------------------------------
# Channel
# ---------------------------------------------------------------------------

class ReplayError(Exception):
    """Raised when a record's counter is <= the last-seen counter for its sender."""


class SecureChannel:
    """
    AES-256-GCM record layer over a key derived from a PQ KEM handshake.

    A wire record is `nonce(12B) || gcm_ciphertext_with_tag`.
    The same AES key is used in both directions; nonce uniqueness is enforced
    by giving each direction a distinct sender_id in the nonce prefix.
    """

    def __init__(self, aes_key: bytes, sender_id: int):
        if len(aes_key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        self._aead = AESGCM(aes_key)
        self._sender_id = sender_id
        self._send_counter: int = 0
        self._last_seen: dict[int, int] = {}
        self._lock = threading.Lock()

    @property
    def sender_id(self) -> int:
        return self._sender_id

    def encrypt(self, plaintext: bytes) -> bytes:
        """Build a wire record carrying `plaintext` under a fresh nonce."""
        with self._lock:
            counter = self._send_counter
            if counter >= 2**64:
                raise OverflowError("counter exhausted; rotate the channel")
            nonce = make_nonce(self._sender_id, counter)
            self._send_counter = counter + 1
        ct_and_tag = self._aead.encrypt(nonce, plaintext, None)
        return nonce + ct_and_tag

    def decrypt(self, record: bytes) -> bytes:
        """Verify, decrypt, and return plaintext from a wire record.

        Raises:
            ValueError: record too short to contain nonce + tag.
            ReplayError: counter <= last-seen for this sender_id.
            cryptography.exceptions.InvalidTag: GCM authentication failed
                (record was modified, or AES key disagrees).
        """
        if len(record) < NONCE_LEN + GCM_TAG_LEN:
            raise ValueError("record shorter than nonce + tag")
        nonce = record[:NONCE_LEN]
        ct_and_tag = record[NONCE_LEN:]
        sender_id, counter = parse_nonce(nonce)

        with self._lock:
            last = self._last_seen.get(sender_id, -1)
            if counter <= last:
                raise ReplayError(
                    f"counter {counter} <= last-seen {last} for sender "
                    f"0x{sender_id:08x}"
                )
            # Authenticate before recording the counter, so a tampered record
            # never poisons the replay window.
            plaintext = self._aead.decrypt(nonce, ct_and_tag, None)
            self._last_seen[sender_id] = counter
        return plaintext


# ---------------------------------------------------------------------------
# Handshakes
# ---------------------------------------------------------------------------

def server_handshake(sock: _socket.socket, cli_kem_name: str) -> SecureChannel:
    """
    Server side of the handshake.

    Generates a fresh KEM keypair, sends the public key, receives the
    encapsulated ciphertext, decapsulates, and returns a SecureChannel keyed
    on the derived AES-256 key (with sender_id = SENDER_ID_SERVER).
    """
    alg = resolve_kem_name(cli_kem_name)
    with oqs.KeyEncapsulation(alg) as kem:
        public_key = kem.generate_keypair()
        send_frame(sock, public_key)
        kem_ciphertext = recv_frame(sock)
        shared_secret = kem.decap_secret(kem_ciphertext)
    transcript = public_key + kem_ciphertext
    aes_key = derive_aes_key(shared_secret, transcript)
    return SecureChannel(aes_key, SENDER_ID_SERVER)


def client_handshake(sock: _socket.socket, cli_kem_name: str) -> SecureChannel:
    """
    Client side of the handshake.

    Receives the server's KEM public key, encapsulates a fresh shared secret,
    sends the resulting ciphertext, and returns a SecureChannel keyed on the
    derived AES-256 key (with sender_id = SENDER_ID_CLIENT).
    """
    alg = resolve_kem_name(cli_kem_name)
    public_key = recv_frame(sock)
    with oqs.KeyEncapsulation(alg) as kem:
        kem_ciphertext, shared_secret = kem.encap_secret(public_key)
        send_frame(sock, kem_ciphertext)
    transcript = public_key + kem_ciphertext
    aes_key = derive_aes_key(shared_secret, transcript)
    return SecureChannel(aes_key, SENDER_ID_CLIENT)


__all__ = [
    "KEM_REGISTRY",
    "resolve_kem_name",
    "derive_aes_key",
    "make_nonce",
    "parse_nonce",
    "send_frame",
    "recv_frame",
    "ReplayError",
    "SecureChannel",
    "server_handshake",
    "client_handshake",
    "SENDER_ID_CLIENT",
    "SENDER_ID_SERVER",
    "NONCE_LEN",
    "GCM_TAG_LEN",
    "LENGTH_PREFIX_LEN",
    "HKDF_INFO",
]
