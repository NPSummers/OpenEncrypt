from __future__ import annotations

import base64
from typing import Tuple

from .sha3 import shake256


FIXED_CHARS = 4096
FIXED_BYTES = (FIXED_CHARS * 3) // 4  # 3072, must be multiple of 3


def pack_to_fixed(data: bytes) -> bytes:
	if len(data) > FIXED_BYTES - 5:
		raise ValueError("data too long for fixed envelope")
	header = b"OE1" + len(data).to_bytes(2, "big")
	rem = FIXED_BYTES - len(header) - len(data)
	fill = shake256(header + data, rem)
	return header + data + fill


def unpack_from_fixed(blob: bytes) -> bytes:
	if len(blob) != FIXED_BYTES:
		raise ValueError("invalid fixed blob size")
	if not blob[:3] == b"OE1":
		raise ValueError("invalid header")
	ln = int.from_bytes(blob[3:5], "big")
	payload = blob[5:5 + ln]
	expected = pack_to_fixed(payload)
	if expected != blob:
		raise ValueError("envelope integrity failed")
	return payload


def b64u_nopad_encode_fixed(blob: bytes) -> str:
	if len(blob) != FIXED_BYTES:
		raise ValueError("invalid blob length for encoding")
	s = base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")
	if len(s) != FIXED_CHARS:
		raise AssertionError("encoding did not produce fixed length")
	return s


def b64u_nopad_decode_fixed(s: str) -> bytes:
	if len(s) != FIXED_CHARS:
		raise ValueError("invalid key length; must be 4096 chars")
	# multiple of 4, no padding needed
	blob = base64.urlsafe_b64decode(s + "==")
	if len(blob) != FIXED_BYTES:
		raise ValueError("decoded blob wrong size")
	return blob


def export_fixed_text(data: bytes) -> str:
	blob = pack_to_fixed(data)
	return b64u_nopad_encode_fixed(blob)


def import_fixed_text(s: str) -> bytes:
	blob = b64u_nopad_decode_fixed(s)
	return unpack_from_fixed(blob)


