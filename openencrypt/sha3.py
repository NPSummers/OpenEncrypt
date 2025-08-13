"""
SHA3/SHAKE wrappers around hashlib for clarity.
"""

from __future__ import annotations

import hashlib
from typing import Tuple


def sha3_256(data: bytes) -> bytes:
	return hashlib.sha3_256(data).digest()


def sha3_512(data: bytes) -> bytes:
	return hashlib.sha3_512(data).digest()


def shake128(data: bytes, outlen: int) -> bytes:
	sh = hashlib.shake_128()
	sh.update(data)
	return sh.digest(outlen)


def shake256(data: bytes, outlen: int) -> bytes:
	sh = hashlib.shake_256()
	sh.update(data)
	return sh.digest(outlen)


