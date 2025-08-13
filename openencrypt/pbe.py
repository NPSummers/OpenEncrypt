from __future__ import annotations

import os
import base64
import hashlib
from typing import Tuple, Dict

from .symm import encrypt as symm_encrypt, decrypt as symm_decrypt


DEFAULT_SCRYPT_N = 1 << 14
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1


def kdf_scrypt(passphrase: str, salt: bytes, n: int, r: int, p: int, dklen: int = 32) -> bytes:
	# Avoid maxmem issues on some platforms by not specifying it
	return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen)


def encrypt_secret(plaintext: bytes, passphrase: str) -> Tuple[Dict[str, str], bytes]:
	salt = os.urandom(16)
	key = kdf_scrypt(passphrase, salt, DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_R, DEFAULT_SCRYPT_P)
	nonce = os.urandom(16)
	ciphertext, tag = symm_encrypt(key, nonce, plaintext, ad=b"openencrypt-secret")
	sealed = b"OESEAL1" + salt + nonce + tag + ciphertext
	headers = {
		"KDF": "scrypt",
		"N": str(DEFAULT_SCRYPT_N),
		"r": str(DEFAULT_SCRYPT_R),
		"p": str(DEFAULT_SCRYPT_P),
		"Salt": base64.b64encode(salt).decode("ascii"),
	}
	return headers, sealed


def decrypt_secret(sealed: bytes, passphrase: str, headers: Dict[str, str]) -> bytes:
	if not sealed.startswith(b"OESEAL1"):
		raise ValueError("bad sealed secret header")
	salt = base64.b64decode(headers["Salt"]) if "Salt" in headers else sealed[7:23]
	try:
		n = int(headers.get("N", str(DEFAULT_SCRYPT_N)))
		r = int(headers.get("r", str(DEFAULT_SCRYPT_R)))
		p = int(headers.get("p", str(DEFAULT_SCRYPT_P)))
	except Exception as e:
		raise ValueError("invalid scrypt params") from e
	key = kdf_scrypt(passphrase, salt, n, r, p)
	# sealed layout: magic(7) | salt(16) | nonce(16) | tag(32) | ciphertext
	if len(sealed) < 7 + 16 + 16 + 32:
		raise ValueError("sealed too short")
	_off = 7
	_salt = sealed[_off:_off + 16]
	_off += 16
	nonce = sealed[_off:_off + 16]
	_off += 16
	tag = sealed[_off:_off + 32]
	_off += 32
	ciphertext = sealed[_off:]
	pt = symm_decrypt(key, nonce, ciphertext, tag, ad=b"openencrypt-secret")
	if pt is None:
		raise ValueError("bad passphrase or corrupted secret")
	return pt


