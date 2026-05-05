"""
Pytest suite for SecureChannel.


Required cases (project spec):
- test_correct_decryption: roundtrip plaintext == ciphertext after channel decrypts.
- test_modified_ciphertext_rejected: flipping a byte in the GCM ciphertext or tag fails.
- test_replayed_message_rejected: re-feeding a previously accepted record fails.
- test_out_of_order_counter_rejected: a record with counter < last-seen fails.

Each is parametrized over both KEMs.

Plus a few sanity tests on the helpers.
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

import oqs

from src.channel import (
    GCM_TAG_LEN,
    KEM_REGISTRY,
    NONCE_LEN,
    ReplayError,
    SENDER_ID_CLIENT,
    SENDER_ID_SERVER,
    SecureChannel,
    derive_aes_key,
    make_nonce,
    parse_nonce,
    resolve_kem_name,
)


KEMS = sorted(KEM_REGISTRY)


# ---------------------------------------------------------------------------
# Helper: do a real KEM handshake in-process, no sockets.
# ---------------------------------------------------------------------------

def make_channel_pair(cli_kem_name: str) -> tuple[SecureChannel, SecureChannel]:
    """Return (client_channel, server_channel) sharing a fresh AES-256 key."""
    alg = resolve_kem_name(cli_kem_name)
    server = oqs.KeyEncapsulation(alg)
    client = oqs.KeyEncapsulation(alg)
    try:
        pk = server.generate_keypair()
        ct, ss_c = client.encap_secret(pk)
        ss_s = server.decap_secret(ct)
        assert ss_c == ss_s, "KEM shared secret mismatch"
        aes_key = derive_aes_key(ss_s, pk + ct)
    finally:
        server.free()
        client.free()
    return (
        SecureChannel(aes_key, SENDER_ID_CLIENT),
        SecureChannel(aes_key, SENDER_ID_SERVER),
    )


# ---------------------------------------------------------------------------
# Required cases, parametrized over both KEMs.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kem", KEMS)
def test_correct_decryption(kem):
    client, server = make_channel_pair(kem)
    payloads = [b"", b"hello", b"\x00" * 1024, b"\xff" * 1, b"unicode: snowman \xe2\x98\x83"]
    for msg in payloads:
        record = client.encrypt(msg)
        assert server.decrypt(record) == msg


@pytest.mark.parametrize("kem", KEMS)
def test_modified_ciphertext_rejected(kem):
    client, server = make_channel_pair(kem)

    # Flip a byte inside the GCM ciphertext region.
    record = bytearray(client.encrypt(b"sensitive payload"))
    flip_index = NONCE_LEN  # first byte of the AEAD output
    record[flip_index] ^= 0x01
    with pytest.raises(InvalidTag):
        server.decrypt(bytes(record))

    # Flip a byte inside the GCM tag (last 16 bytes).
    client2, server2 = make_channel_pair(kem)
    record2 = bytearray(client2.encrypt(b"another"))
    record2[-1] ^= 0x80
    with pytest.raises(InvalidTag):
        server2.decrypt(bytes(record2))


@pytest.mark.parametrize("kem", KEMS)
def test_replayed_message_rejected(kem):
    client, server = make_channel_pair(kem)
    record = client.encrypt(b"replay me if you dare")
    assert server.decrypt(record) == b"replay me if you dare"
    # Same exact bytes again -> must fail with ReplayError, not InvalidTag.
    with pytest.raises(ReplayError):
        server.decrypt(record)


@pytest.mark.parametrize("kem", KEMS)
def test_out_of_order_counter_rejected(kem):
    client, server = make_channel_pair(kem)
    # Produce three records in order: counter 0, 1, 2.
    r0 = client.encrypt(b"a")
    r1 = client.encrypt(b"b")
    r2 = client.encrypt(b"c")
    # Receiver sees r2 first (counter=2). last_seen advances to 2.
    assert server.decrypt(r2) == b"c"
    # r0 and r1 (counter 0 and 1) must now be rejected as out-of-order.
    with pytest.raises(ReplayError):
        server.decrypt(r0)
    with pytest.raises(ReplayError):
        server.decrypt(r1)


# ---------------------------------------------------------------------------
# Helper-level sanity tests (KEM-independent; run once).
# ---------------------------------------------------------------------------

def test_nonce_roundtrip():
    n = make_nonce(SENDER_ID_CLIENT, 0)
    assert len(n) == NONCE_LEN
    sid, ctr = parse_nonce(n)
    assert sid == SENDER_ID_CLIENT
    assert ctr == 0

    n2 = make_nonce(SENDER_ID_SERVER, 2**63 - 1)
    sid2, ctr2 = parse_nonce(n2)
    assert sid2 == SENDER_ID_SERVER
    assert ctr2 == 2**63 - 1


def test_resolve_unknown_kem_raises():
    with pytest.raises(ValueError):
        resolve_kem_name("not-a-real-kem")


def test_decrypt_short_record_raises():
    chan = SecureChannel(b"\x00" * 32, SENDER_ID_CLIENT)
    with pytest.raises(ValueError):
        chan.decrypt(b"too short")  # < NONCE_LEN + GCM_TAG_LEN


def test_send_counter_increments():
    chan = SecureChannel(b"\x00" * 32, SENDER_ID_CLIENT)
    r0 = chan.encrypt(b"x")
    r1 = chan.encrypt(b"y")
    _, c0 = parse_nonce(r0[:NONCE_LEN])
    _, c1 = parse_nonce(r1[:NONCE_LEN])
    assert c0 == 0 and c1 == 1


def test_distinct_directions_use_distinct_sender_ids():
    """Sanity: if two channels share a key but use different sender IDs,
    nonces never collide even if their counters do."""
    key = b"\x11" * 32
    a = SecureChannel(key, SENDER_ID_CLIENT)
    b = SecureChannel(key, SENDER_ID_SERVER)
    ra = a.encrypt(b"from a")
    rb = b.encrypt(b"from b")
    assert ra[:NONCE_LEN] != rb[:NONCE_LEN]
