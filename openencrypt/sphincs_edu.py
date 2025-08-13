"""
Educational SPHINCS+-like signature (very simplified):
- One small Merkle tree layer with WOTS+-like chains using SHAKE256
- Not parameter compatible, not secure; for demonstration only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from .sha3 import shake256, sha3_256


WOTS_LEN = 16  # number of chains (tiny)
WOTS_STEPS = 16  # steps per chain
SEED_BYTES = 32


def prf(seed: bytes, ctx: bytes, outlen: int) -> bytes:
	return shake256(seed + ctx, outlen)


def chain_step(x: bytes) -> bytes:
	return sha3_256(x)


def wots_gen_pk(sk_seed: bytes, addr: bytes) -> List[bytes]:
	pk_elems: List[bytes] = []
	for i in range(WOTS_LEN):
		x = prf(sk_seed, addr + bytes([i]), 32)
		for _ in range(WOTS_STEPS):
			x = chain_step(x)
		pk_elems.append(x)
	return pk_elems


def wots_sign(sk_seed: bytes, addr: bytes, msg_hash: bytes) -> List[bytes]:
	sig: List[bytes] = []
	for i in range(WOTS_LEN):
		x = prf(sk_seed, addr + bytes([i]), 32)
		steps = msg_hash[i] % (WOTS_STEPS + 1)
		for _ in range(steps):
			x = chain_step(x)
		sig.append(x)
	return sig


def wots_pk_from_sig(sig: List[bytes], addr: bytes, msg_hash: bytes) -> List[bytes]:
	pk: List[bytes] = []
	for i in range(WOTS_LEN):
		x = sig[i]
		steps_done = msg_hash[i] % (WOTS_STEPS + 1)
		for _ in range(WOTS_STEPS - steps_done):
			x = chain_step(x)
		pk.append(x)
	return pk


def l_tree(hashes: List[bytes]) -> bytes:
	cur = list(hashes)
	while len(cur) > 1:
		next_level: List[bytes] = []
		for i in range(0, len(cur), 2):
			left = cur[i]
			right = cur[i + 1] if i + 1 < len(cur) else cur[i]
			next_level.append(sha3_256(left + right))
		cur = next_level
	return cur[0]


@dataclass
class SPublicKey:
	root: bytes  # Merkle root
	seed: bytes  # public seed for address derivation


@dataclass
class SSecretKey:
	seed: bytes  # secret seed for WOTS chains
	pub: SPublicKey


def keygen(seed: bytes | None = None) -> Tuple[SPublicKey, SSecretKey]:
	if seed is None:
		seed = shake256(b"sphincs-edu-seed", 32)
	pub_seed = shake256(seed + b"pub", 32)
	sk_seed = shake256(seed + b"sk", 32)
	# Single leaf tree
	wots_pk = wots_gen_pk(sk_seed, b"leaf0" + pub_seed[:8])
	root = l_tree(wots_pk)
	pk = SPublicKey(root=root, seed=pub_seed)
	sk = SSecretKey(seed=sk_seed, pub=pk)
	return pk, sk


def sign(sk: SSecretKey, message: bytes) -> bytes:
	msg_hash = sha3_256(sk.pub.seed + message)
	sig_elems = wots_sign(sk.seed, b"leaf0" + sk.pub.seed[:8], msg_hash)
	# Serialize: concatenated 32-byte elements
	return b"".join(sig_elems)


def verify(pk: SPublicKey, message: bytes, signature: bytes) -> bool:
	if len(signature) != WOTS_LEN * 32:
		return False
	msg_hash = sha3_256(pk.seed + message)
	sig_elems = [signature[i * 32:(i + 1) * 32] for i in range(WOTS_LEN)]
	pk_elems = wots_pk_from_sig(sig_elems, b"leaf0" + pk.seed[:8], msg_hash)
	root = l_tree(pk_elems)
	return root == pk.root


