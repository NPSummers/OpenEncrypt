"""
SPHINCS+ (more production-shaped) signature in pure Python (stdlib only).

This implements the SPHINCS+ structure (FORS + hypertree of WOTS+).
Hash function family: SHAKE256 (via stdlib hashlib wrappers in `openencrypt/sha3.py`).

Important security note:
- This code is **not constant-time** in the strong sense (CPython).
- It is written in a "constant-time style" where feasible (no secret-indexed tables,
  no early-exit comparisons), but CPython/runtime effects still leak timing.

Reference (design/notation): SPHINCS+ paper
  https://sphincs.org/data/sphincs+-paper.pdf
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import List, Tuple

from .sha3 import sha3_256, shake256


@dataclass(frozen=True)
class SPXParams:
	name: str
	n: int  # hash output bytes
	w: int  # Winternitz base (must be power of 2, typically 16)
	full_height: int  # total hypertree height
	d: int  # number of layers
	fors_height: int  # a
	fors_trees: int  # k

	@property
	def tree_height(self) -> int:
		if self.full_height % self.d != 0:
			raise ValueError("full_height must be divisible by d")
		return self.full_height // self.d


# "Production-shaped" default: large parameters, SHAKE-based.
# NOTE: Parameter values are intended to match a SHAKE-256f-simple style profile from the SPHINCS+ design,
# but this Python implementation is for offline experimentation, not hardened production deployment.
SPHINCS_SHAKE_256F_SIMPLE = SPXParams(
	name="SPHINCS+-SHAKE-256f-simple",
	n=32,
	w=16,
	full_height=66,
	d=22,
	fors_height=6,
	fors_trees=33,
)

# Small fast parameter set for tests/dev (NOT standardized, NOT for security)
SPHINCS_TEST_UNSAFE = SPXParams(
	name="SPHINCS+-TEST-UNSAFE",
	n=16,
	w=16,
	full_height=12,
	d=3,
	fors_height=4,
	fors_trees=8,
)


def _u32(x: int) -> int:
	return x & 0xFFFFFFFF


def _to_bytes_u32_be(x: int) -> bytes:
	return _u32(x).to_bytes(4, "big")


class Address:
	"""
	SPHINCS+ address: 8 x 32-bit words => 32 bytes.
	We keep fields used for domain separation. This is compatible with the spec's "address" concept
	(though exact field semantics depend on the variant).
	"""

	__slots__ = ("words",)

	def __init__(self) -> None:
		self.words = [0] * 8

	def copy(self) -> "Address":
		a = Address()
		a.words = list(self.words)
		return a

	def set_layer(self, layer: int) -> None:
		self.words[0] = _u32(layer)

	def set_tree(self, tree: int) -> None:
		# tree is 64-bit in spec; store high/low in words[1], words[2]
		self.words[1] = _u32(tree >> 32)
		self.words[2] = _u32(tree)

	def set_type(self, typ: int) -> None:
		self.words[3] = _u32(typ)

	def set_keypair(self, kp: int) -> None:
		self.words[4] = _u32(kp)

	def set_chain(self, chain: int) -> None:
		self.words[5] = _u32(chain)

	def set_hash(self, h: int) -> None:
		self.words[6] = _u32(h)

	def set_tree_height(self, th: int) -> None:
		self.words[5] = _u32(th)

	def set_tree_index(self, ti: int) -> None:
		self.words[6] = _u32(ti)

	def to_bytes(self) -> bytes:
		return b"".join(_to_bytes_u32_be(w) for w in self.words)


# Address types (domain separation)
ADDR_TYPE_WOTS = 0
ADDR_TYPE_WOTSPK = 1
ADDR_TYPE_HASHTREE = 2
ADDR_TYPE_FORS_TREE = 3
ADDR_TYPE_FORS_ROOTS = 4


def _shake_out(data: bytes, outlen: int) -> bytes:
	return shake256(data, outlen)


def _prf(seed: bytes, addr: Address, outlen: int) -> bytes:
	# PRF(sk_seed, addr) -> n bytes
	return _shake_out(seed + addr.to_bytes(), outlen)


def _thash(params: SPXParams, pub_seed: bytes, addr: Address, ins: bytes) -> bytes:
	# Tweakable hash: SHAKE256(pub_seed || addr || ins) -> n bytes
	return _shake_out(pub_seed + addr.to_bytes() + ins, params.n)


def _base_w(params: SPXParams, x: bytes, out_len: int) -> List[int]:
	"""
	Convert bytes to base-w digits (w is power of two).
	"""
	w = params.w
	logw = 4  # for w=16
	if w != 16:
		raise ValueError("only w=16 supported in this implementation")
	res: List[int] = []
	total = 0
	bits = 0
	for b in x:
		total = (total << 8) | b
		bits += 8
		while bits >= logw and len(res) < out_len:
			bits -= logw
			res.append((total >> bits) & (w - 1))
		if len(res) >= out_len:
			break
	if len(res) != out_len:
		# pad with zeros deterministically
		res.extend([0] * (out_len - len(res)))
	return res


def _wots_lengths(params: SPXParams) -> Tuple[int, int, int]:
	# w=16 => log_w = 4
	logw = 4
	len1 = (8 * params.n) // logw
	# len2 = floor(log_w(len1*(w-1)))+1; for w=16 this is 3 for n=32
	# compute generically
	x = len1 * (params.w - 1)
	len2 = 0
	while x > 0:
		x //= params.w
		len2 += 1
	if len2 == 0:
		len2 = 1
	return len1, len2, len1 + len2


def _wots_checksum(params: SPXParams, msg_basew: List[int], len2: int) -> List[int]:
	csum = 0
	for d in msg_basew:
		csum += (params.w - 1) - d
	# left shift to align to byte boundary as in reference constructions
	# For w=16, shift by (8 - ((len2*logw) % 8)) % 8 bits; here logw=4.
	logw = 4
	shift = (8 - ((len2 * logw) % 8)) % 8
	csum <<= shift
	# encode checksum to bytes then base_w
	# ceil(len2*logw/8) bytes
	blen = (len2 * logw + 7) // 8
	csum_bytes = csum.to_bytes(blen, "big")
	return _base_w(params, csum_bytes, len2)


def _chain(params: SPXParams, pub_seed: bytes, addr: Address, x: bytes, i: int, s: int) -> bytes:
	"""
	Iterate the chaining function s times starting at step i.
	"""
	out = x
	for j in range(i, i + s):
		a = addr.copy()
		a.set_hash(j)
		out = _thash(params, pub_seed, a, out)
	return out


def _wots_gen_sk(params: SPXParams, sk_seed: bytes, addr: Address, i: int) -> bytes:
	a = addr.copy()
	a.set_chain(i)
	a.set_hash(0)
	return _prf(sk_seed, a, params.n)


def _wots_gen_pk(params: SPXParams, sk_seed: bytes, pub_seed: bytes, addr: Address) -> bytes:
	len1, len2, l = _wots_lengths(params)
	parts: List[bytes] = []
	for i in range(l):
		sk_i = _wots_gen_sk(params, sk_seed, addr, i)
		a = addr.copy()
		a.set_chain(i)
		parts.append(_chain(params, pub_seed, a, sk_i, 0, params.w - 1))
	# compress WOTS pk using thash with dedicated type
	pk_addr = addr.copy()
	pk_addr.set_type(ADDR_TYPE_WOTSPK)
	return _thash(params, pub_seed, pk_addr, b"".join(parts))


def _wots_sign(params: SPXParams, sk_seed: bytes, pub_seed: bytes, addr: Address, msg: bytes) -> bytes:
	len1, len2, l = _wots_lengths(params)
	msg_basew = _base_w(params, msg, len1)
	csum = _wots_checksum(params, msg_basew, len2)
	steps = msg_basew + csum
	sig_parts: List[bytes] = []
	for i in range(l):
		sk_i = _wots_gen_sk(params, sk_seed, addr, i)
		a = addr.copy()
		a.set_chain(i)
		sig_parts.append(_chain(params, pub_seed, a, sk_i, 0, steps[i]))
	return b"".join(sig_parts)


def _wots_pk_from_sig(params: SPXParams, pub_seed: bytes, addr: Address, sig: bytes, msg: bytes) -> bytes:
	len1, len2, l = _wots_lengths(params)
	if len(sig) != l * params.n:
		raise ValueError("bad WOTS signature length")
	msg_basew = _base_w(params, msg, len1)
	csum = _wots_checksum(params, msg_basew, len2)
	steps = msg_basew + csum
	parts: List[bytes] = []
	for i in range(l):
		part = sig[i * params.n:(i + 1) * params.n]
		a = addr.copy()
		a.set_chain(i)
		parts.append(_chain(params, pub_seed, a, part, steps[i], (params.w - 1) - steps[i]))
	pk_addr = addr.copy()
	pk_addr.set_type(ADDR_TYPE_WOTSPK)
	return _thash(params, pub_seed, pk_addr, b"".join(parts))


def _gen_leaf(params: SPXParams, sk_seed: bytes, pub_seed: bytes, addr: Address, idx: int) -> bytes:
	# leaf is WOTS pk compressed
	a = addr.copy()
	a.set_type(ADDR_TYPE_WOTS)
	a.set_keypair(idx)
	return _wots_gen_pk(params, sk_seed, pub_seed, a)


def _treehash(params: SPXParams, sk_seed: bytes, pub_seed: bytes, addr: Address, leaf_idx: int, height: int) -> Tuple[bytes, List[bytes]]:
	"""
	Compute root and auth path for a Merkle tree of given height.
	Tree has 2^height leaves, each derived from WOTS keys.
	"""
	if leaf_idx < 0 or leaf_idx >= (1 << height):
		raise ValueError("leaf_idx out of range")
	auth: List[bytes] = [b""] * height
	# Generate leaves
	nodes: List[bytes] = [_gen_leaf(params, sk_seed, pub_seed, addr, i) for i in range(1 << height)]
	idx = leaf_idx
	for lvl in range(height):
		auth[lvl] = nodes[idx ^ 1]
		parents: List[bytes] = []
		for j in range(0, len(nodes), 2):
			parent_addr = addr.copy()
			parent_addr.set_type(ADDR_TYPE_HASHTREE)
			parent_addr.set_tree_height(lvl + 1)
			parent_addr.set_tree_index(j // 2)
			parents.append(_thash(params, pub_seed, parent_addr, nodes[j] + nodes[j + 1]))
		nodes = parents
		idx >>= 1
	return nodes[0], auth


def _compute_root(params: SPXParams, pub_seed: bytes, leaf: bytes, leaf_idx: int, auth: List[bytes], addr: Address) -> bytes:
	node = leaf
	for h, sibling in enumerate(auth):
		parent_addr = addr.copy()
		parent_addr.set_type(ADDR_TYPE_HASHTREE)
		parent_addr.set_tree_height(h + 1)
		parent_addr.set_tree_index(leaf_idx >> (h + 1))
		if ((leaf_idx >> h) & 1) == 0:
			node = _thash(params, pub_seed, parent_addr, node + sibling)
		else:
			node = _thash(params, pub_seed, parent_addr, sibling + node)
	return node


def _fors_msg_to_indices(params: SPXParams, m: bytes) -> List[int]:
	# Interpret as k indices, each of a bits.
	k = params.fors_trees
	a = params.fors_height
	total_bits = k * a
	need_bytes = (total_bits + 7) // 8
	m = (m + b"\x00" * need_bytes)[:need_bytes]
	indices: List[int] = []
	bitpos = 0
	for _ in range(k):
		idx = 0
		for j in range(a):
			byte = m[bitpos // 8]
			bit = (byte >> (bitpos % 8)) & 1
			idx |= (bit << j)
			bitpos += 1
		indices.append(idx)
	return indices


def _fors_sk_gen(params: SPXParams, sk_seed: bytes, addr: Address, idx: int) -> bytes:
	a = addr.copy()
	a.set_type(ADDR_TYPE_FORS_TREE)
	a.set_tree_height(0)
	a.set_tree_index(idx)
	return _prf(sk_seed, a, params.n)


def _fors_leaf(params: SPXParams, sk_seed: bytes, pub_seed: bytes, addr: Address, idx: int) -> bytes:
	sk = _fors_sk_gen(params, sk_seed, addr, idx)
	a = addr.copy()
	a.set_type(ADDR_TYPE_FORS_TREE)
	a.set_tree_height(0)
	a.set_tree_index(idx)
	return _thash(params, pub_seed, a, sk)


def _fors_treehash(params: SPXParams, sk_seed: bytes, pub_seed: bytes, addr: Address, base: int, leaf_idx: int) -> Tuple[bytes, List[bytes]]:
	# FORS tree of height a; leaves are indexed globally as base + i.
	h = params.fors_height
	if leaf_idx < 0 or leaf_idx >= (1 << h):
		raise ValueError("FORS leaf_idx out of range")
	auth: List[bytes] = [b""] * h
	nodes: List[bytes] = [_fors_leaf(params, sk_seed, pub_seed, addr, base + i) for i in range(1 << h)]
	idx = leaf_idx
	for lvl in range(h):
		auth[lvl] = nodes[idx ^ 1]
		parents: List[bytes] = []
		for j in range(0, len(nodes), 2):
			parent_addr = addr.copy()
			parent_addr.set_type(ADDR_TYPE_FORS_TREE)
			parent_addr.set_tree_height(lvl + 1)
			# global node index at height (lvl+1)
			parent_addr.set_tree_index((base + (j << lvl)) >> (lvl + 1))
			parents.append(_thash(params, pub_seed, parent_addr, nodes[j] + nodes[j + 1]))
		nodes = parents
		idx >>= 1
	return nodes[0], auth


def _fors_sign(params: SPXParams, sk_seed: bytes, pub_seed: bytes, addr: Address, m: bytes) -> Tuple[bytes, bytes]:
	indices = _fors_msg_to_indices(params, m)
	k = params.fors_trees
	a = params.fors_height
	sig_parts: List[bytes] = []
	roots: List[bytes] = []
	for t in range(k):
		leaf_idx = indices[t]
		base = t << a
		tree_addr = addr.copy()
		# secret key for selected leaf (global index)
		sk = _fors_sk_gen(params, sk_seed, tree_addr, base + leaf_idx)
		# auth path and root
		root, auth = _fors_treehash(params, sk_seed, pub_seed, tree_addr, base, leaf_idx)
		sig_parts.append(sk)
		sig_parts.extend(auth)
		roots.append(root)
	# FORS public key from roots
	pk_addr = addr.copy()
	pk_addr.set_type(ADDR_TYPE_FORS_ROOTS)
	fors_pk = _thash(params, pub_seed, pk_addr, b"".join(roots))
	return b"".join(sig_parts), fors_pk


def _fors_pk_from_sig(params: SPXParams, pub_seed: bytes, addr: Address, sig: bytes, m: bytes) -> bytes:
	indices = _fors_msg_to_indices(params, m)
	k = params.fors_trees
	a = params.fors_height
	need = k * (a + 1) * params.n
	if len(sig) != need:
		raise ValueError("bad FORS signature length")
	off = 0
	roots: List[bytes] = []
	for t in range(k):
		base = t << a
		leaf_idx = indices[t]
		sk = sig[off:off + params.n]
		off += params.n
		auth = [sig[off + i * params.n:off + (i + 1) * params.n] for i in range(a)]
		off += a * params.n
		tree_addr = addr.copy()
		tree_addr.set_type(ADDR_TYPE_FORS_TREE)
		leaf_addr = tree_addr.copy()
		leaf_addr.set_tree_height(0)
		leaf_addr.set_tree_index(base + leaf_idx)
		leaf = _thash(params, pub_seed, leaf_addr, sk)
		root = leaf
		for h in range(a):
			parent_addr = tree_addr.copy()
			parent_addr.set_tree_height(h + 1)
			parent_addr.set_tree_index((base + leaf_idx) >> (h + 1))
			sib = auth[h]
			if ((leaf_idx >> h) & 1) == 0:
				root = _thash(params, pub_seed, parent_addr, root + sib)
			else:
				root = _thash(params, pub_seed, parent_addr, sib + root)
		roots.append(root)
	pk_addr = addr.copy()
	pk_addr.set_type(ADDR_TYPE_FORS_ROOTS)
	return _thash(params, pub_seed, pk_addr, b"".join(roots))


def _h_msg(params: SPXParams, R: bytes, pk: bytes, m: bytes) -> bytes:
	# Output length: fors_msg_bytes + tree_bytes + leaf_bytes
	fors_bits = params.fors_trees * params.fors_height
	fors_bytes = (fors_bits + 7) // 8
	tree_bits = params.full_height - params.tree_height
	tree_bytes = (tree_bits + 7) // 8
	leaf_bits = params.tree_height
	leaf_bytes = (leaf_bits + 7) // 8
	outlen = fors_bytes + tree_bytes + leaf_bytes
	return _shake_out(R + pk + m, outlen)


def _bytes_to_int_le(b: bytes) -> int:
	return int.from_bytes(b, "little")


def _parse_digest(params: SPXParams, digest: bytes) -> Tuple[bytes, int, int]:
	fors_bits = params.fors_trees * params.fors_height
	fors_bytes = (fors_bits + 7) // 8
	tree_bits = params.full_height - params.tree_height
	tree_bytes = (tree_bits + 7) // 8
	leaf_bits = params.tree_height
	leaf_bytes = (leaf_bits + 7) // 8
	fors_m = digest[:fors_bytes]
	tree = _bytes_to_int_le(digest[fors_bytes:fors_bytes + tree_bytes]) & ((1 << tree_bits) - 1)
	leaf = _bytes_to_int_le(digest[fors_bytes + tree_bytes:fors_bytes + tree_bytes + leaf_bytes]) & ((1 << leaf_bits) - 1)
	return fors_m, tree, leaf


def signature_size(params: SPXParams) -> int:
	len1, len2, l = _wots_lengths(params)
	wots_sig = l * params.n
	auth = params.tree_height * params.n
	fors_sig = params.fors_trees * (params.fors_height + 1) * params.n
	return params.n + fors_sig + params.d * (wots_sig + auth)


@dataclass(frozen=True)
class PublicKey:
	params: SPXParams
	pub_seed: bytes
	root: bytes

	@property
	def raw(self) -> bytes:
		return self.pub_seed + self.root


@dataclass(frozen=True)
class SecretKey:
	params: SPXParams
	sk_seed: bytes
	sk_prf: bytes
	pub_seed: bytes
	root: bytes

	@property
	def raw(self) -> bytes:
		return self.sk_seed + self.sk_prf + self.pub_seed + self.root

	@property
	def public(self) -> PublicKey:
		return PublicKey(params=self.params, pub_seed=self.pub_seed, root=self.root)


def keygen(params: SPXParams = SPHINCS_SHAKE_256F_SIMPLE, seed: bytes | None = None) -> Tuple[PublicKey, SecretKey]:
	if seed is None:
		seed = os.urandom(params.n)
		seed = sha3_256(seed)[:params.n] if params.n != 32 else seed
	# derive deterministic seeds from provided seed
	sk_seed = sha3_256(seed + b"sk_seed")[:params.n]
	sk_prf = sha3_256(seed + b"sk_prf")[:params.n]
	pub_seed = sha3_256(seed + b"pub_seed")[:params.n]
	# compute top root (tree index 0, leaf 0) for highest layer
	top_addr = Address()
	top_addr.set_layer(params.d - 1)
	top_addr.set_tree(0)
	root, _auth = _treehash(params, sk_seed, pub_seed, top_addr, leaf_idx=0, height=params.tree_height)
	pk = PublicKey(params=params, pub_seed=pub_seed, root=root)
	sk = SecretKey(params=params, sk_seed=sk_seed, sk_prf=sk_prf, pub_seed=pub_seed, root=root)
	return pk, sk


def sign(sk: SecretKey, message: bytes, optrand: bytes | None = None) -> bytes:
	params = sk.params
	if optrand is None:
		optrand = os.urandom(params.n)
	# R = PRF_msg(sk_prf, optrand, m) (simple: SHAKE of concatenation)
	R = _shake_out(sk.sk_prf + optrand + message, params.n)
	pk_bytes = sk.pub_seed + sk.root
	digest = _h_msg(params, R, pk_bytes, message)
	fors_m, tree, leaf_idx = _parse_digest(params, digest)

	# FORS sign
	fors_addr = Address()
	fors_addr.set_layer(0)
	fors_addr.set_tree(tree)
	fors_sig, fors_pk = _fors_sign(params, sk.sk_seed, sk.pub_seed, fors_addr, fors_m)

	sig_parts: List[bytes] = [R, fors_sig]
	# Hypertree
	root = fors_pk
	cur_tree = tree
	cur_leaf = leaf_idx
	for layer in range(params.d):
		addr = Address()
		addr.set_layer(layer)
		addr.set_tree(cur_tree)
		# WOTS sign current root
		wots_addr = addr.copy()
		wots_addr.set_type(ADDR_TYPE_WOTS)
		wots_addr.set_keypair(cur_leaf)
		wots_sig = _wots_sign(params, sk.sk_seed, sk.pub_seed, wots_addr, sha3_256(root)[:params.n])
		# Auth path for that leaf in this layer
		root2, auth = _treehash(params, sk.sk_seed, sk.pub_seed, addr, leaf_idx=cur_leaf, height=params.tree_height)
		sig_parts.append(wots_sig)
		sig_parts.append(b"".join(auth))
		root = root2
		# derive next layer indices
		cur_leaf = cur_tree & ((1 << params.tree_height) - 1)
		cur_tree >>= params.tree_height
	return b"".join(sig_parts)


def verify(pk: PublicKey, message: bytes, signature: bytes) -> bool:
	params = pk.params
	sig_len = signature_size(params)
	if len(signature) != sig_len:
		return False
	len1, len2, l = _wots_lengths(params)
	wots_sig_len = l * params.n
	auth_len = params.tree_height * params.n
	fors_sig_len = params.fors_trees * (params.fors_height + 1) * params.n

	off = 0
	R = signature[off:off + params.n]
	off += params.n
	fors_sig = signature[off:off + fors_sig_len]
	off += fors_sig_len
	pk_bytes = pk.pub_seed + pk.root
	digest = _h_msg(params, R, pk_bytes, message)
	fors_m, tree, leaf_idx = _parse_digest(params, digest)
	fors_addr = Address()
	fors_addr.set_layer(0)
	fors_addr.set_tree(tree)
	root = _fors_pk_from_sig(params, pk.pub_seed, fors_addr, fors_sig, fors_m)

	cur_tree = tree
	cur_leaf = leaf_idx
	for layer in range(params.d):
		addr = Address()
		addr.set_layer(layer)
		addr.set_tree(cur_tree)
		wots_addr = addr.copy()
		wots_addr.set_type(ADDR_TYPE_WOTS)
		wots_addr.set_keypair(cur_leaf)
		wots_sig = signature[off:off + wots_sig_len]
		off += wots_sig_len
		auth_bytes = signature[off:off + auth_len]
		off += auth_len
		auth = [auth_bytes[i * params.n:(i + 1) * params.n] for i in range(params.tree_height)]
		wots_pk = _wots_pk_from_sig(params, pk.pub_seed, wots_addr, wots_sig, sha3_256(root)[:params.n])
		leaf = wots_pk
		root = _compute_root(params, pk.pub_seed, leaf, cur_leaf, auth, addr)
		cur_leaf = cur_tree & ((1 << params.tree_height) - 1)
		cur_tree >>= params.tree_height
	return root == pk.root

