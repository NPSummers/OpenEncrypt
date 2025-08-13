from __future__ import annotations

import base64
from typing import Tuple, Dict, Optional


def _wrap64(s: str) -> str:
	return "\n".join(s[i:i + 64] for i in range(0, len(s), 64))


def encode_text_armor(kind: str, text: str, version: str = "OpenEncrypt-edu", headers: Optional[Dict[str, str]] = None) -> str:
	head = f"-----BEGIN OPENENCRYPT {kind}-----\nVersion: {version}\n"
	if headers:
		for k, v in headers.items():
			head += f"{k}: {v}\n"
	head += "\n"
	body = _wrap64(text)
	foot = f"\n-----END OPENENCRYPT {kind}-----\n"
	return head + body + foot


def encode_bytes_armor(kind: str, data: bytes, version: str = "OpenEncrypt-edu", headers: Optional[Dict[str, str]] = None) -> str:
	head = f"-----BEGIN OPENENCRYPT {kind}-----\nVersion: {version}\n"
	if headers:
		for k, v in headers.items():
			head += f"{k}: {v}\n"
	head += "\n"
	b64 = base64.b64encode(data).decode("ascii")
	body = _wrap64(b64)
	foot = f"\n-----END OPENENCRYPT {kind}-----\n"
	return head + body + foot


def decode_armor_full(armored: str) -> Tuple[str, Dict[str, str], str]:
	lines = armored.splitlines()
	if not lines or not lines[0].startswith("-----BEGIN OPENENCRYPT "):
		raise ValueError("bad armor header")
	kind = lines[0][len("-----BEGIN OPENENCRYPT ") : -5]
	# parse headers until blank line
	headers: Dict[str, str] = {}
	i = 1
	while i < len(lines) and lines[i].strip() != "":
		line = lines[i].strip()
		if ":" in line:
			k, v = line.split(":", 1)
			headers[k.strip()] = v.strip()
		i += 1
	# skip blank line
	while i < len(lines) and lines[i].strip() == "":
		i += 1
	# body until footer
	body_parts = []
	while i < len(lines) and not lines[i].startswith("-----END OPENENCRYPT "):
		body_parts.append(lines[i].strip())
		i += 1
	if i >= len(lines) or lines[i].strip() != f"-----END OPENENCRYPT {kind}-----":
		raise ValueError("bad armor footer")
	body = "".join(body_parts)
	return kind, headers, body


def decode_armor(armored: str) -> Tuple[str, str]:
	kind, _headers, body = decode_armor_full(armored)
	return kind, body


