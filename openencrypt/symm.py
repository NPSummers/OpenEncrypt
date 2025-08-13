"""
Simple symmetric encryption built on SHAKE256 stream and HMAC-SHA3.

This is purely didactic and not constant-time.
"""

from __future__ import annotations

import hmac
from typing import Tuple
import hashlib

from .sha3 import shake256, sha3_256


def kdf(key_material: bytes, context: bytes, outlen: int = 64) -> bytes:
	return shake256(key_material + context, outlen)


def stream_xor(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
	keystream = shake256(key + nonce, len(plaintext))
	return bytes([p ^ k for p, k in zip(plaintext, keystream)])


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, ad: bytes = b"") -> Tuple[bytes, bytes]:
	# Derive enc and mac keys
	km = kdf(key, b"enc", 64)
	k_enc, k_mac = km[:32], km[32:]
	ciphertext = stream_xor(k_enc, nonce, plaintext)
	tag = hmac.new(k_mac, ad + b"|" + nonce + b"|" + ciphertext, hashlib.sha3_256).digest()
	return ciphertext, tag


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, ad: bytes = b"") -> bytes | None:
	km = kdf(key, b"enc", 64)
	k_enc, k_mac = km[:32], km[32:]
	expected = hmac.new(k_mac, ad + b"|" + nonce + b"|" + ciphertext, hashlib.sha3_256).digest()
	if not hmac.compare_digest(expected, tag):
		return None
	return stream_xor(k_enc, nonce, ciphertext)


