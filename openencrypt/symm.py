"""
Simple symmetric encryption built on SHAKE256 stream and HMAC-SHA3.

This is a minimal Encrypt-then-MAC construction:
- stream cipher: SHAKE256(key || nonce) XOR plaintext
- MAC: HMAC-SHA3-256 over (ad || nonce || ciphertext)

Constant-time note:
- Tag verification uses `hmac.compare_digest`.
- The rest is written in a "constant-time style" with respect to secret data,
  but CPython cannot provide strict constant-time guarantees.
"""

from __future__ import annotations

import hmac
from typing import Tuple
import hashlib

from .sha3 import shake256, sha3_256


def kdf(key_material: bytes, context: bytes, outlen: int = 64) -> bytes:
	return shake256(key_material + context, outlen)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
	if len(a) != len(b):
		raise ValueError("xor length mismatch")
	# Loop count depends only on length, not on secret data.
	return bytes(x ^ y for x, y in zip(a, b))


def stream_xor(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
	keystream = shake256(key + nonce, len(plaintext))
	return _xor_bytes(plaintext, keystream)


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, ad: bytes = b"") -> Tuple[bytes, bytes]:
	# Derive enc and mac keys
	km = kdf(key, b"enc", 64)
	k_enc, k_mac = km[:32], km[32:]
	ciphertext = stream_xor(k_enc, nonce, plaintext)
	m = hmac.new(k_mac, digestmod=hashlib.sha3_256)
	m.update(ad)
	m.update(b"|")
	m.update(nonce)
	m.update(b"|")
	m.update(ciphertext)
	tag = m.digest()
	return ciphertext, tag


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, ad: bytes = b"") -> bytes | None:
	km = kdf(key, b"enc", 64)
	k_enc, k_mac = km[:32], km[32:]
	m = hmac.new(k_mac, digestmod=hashlib.sha3_256)
	m.update(ad)
	m.update(b"|")
	m.update(nonce)
	m.update(b"|")
	m.update(ciphertext)
	expected = m.digest()
	if not hmac.compare_digest(expected, tag):
		return None
	return stream_xor(k_enc, nonce, ciphertext)


