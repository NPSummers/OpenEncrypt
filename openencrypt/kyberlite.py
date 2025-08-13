"""
KyberLite: An educational Kyber512-like KEM implemented in pure Python.

This module mirrors the high-level structure of CRYSTALS-Kyber (CPA-secure PKE
transformed into CCA-secure KEM) but drastically simplifies many parts for clarity:
- Uses schoolbook polynomial multiplication, no NTT
- Small parameter choices for speed in Python
- Deterministic PRNG via SHAKE

DO NOT USE IN PRODUCTION.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from .sha3 import shake128, shake256, sha3_256
from .mathpoly import poly_add, poly_sub, poly_mul


# Parameters (roughly inspired by Kyber512 but smaller to keep it tractable in Python)
N = 256  # degree (Kyber uses 256)
Q = 3329  # modulus (same as Kyber)
K = 4  # matrix size (Kyber512 uses 2)

ETA = 4  # small noise parameter


def prf(seed: bytes, domain_sep: bytes, outlen: int) -> bytes:
	return shake256(seed + domain_sep, outlen)


def sample_cbd(seed: bytes, nonce: int, n: int = N, eta: int = ETA) -> List[int]:
	# Centered binomial distribution via SHAKE bits. Didactic approximation.
	# Output length n coefficients in [-eta, eta].
	out = []
	buf = shake128(seed + bytes([nonce]), 2 * n)
	for i in range(n):
		a = buf[2 * i]
		b = buf[2 * i + 1]
		# Count bits as simple proxy
		s = (bin(a).count("1") - bin(~a & 0xFF).count("1"))
		t = (bin(b).count("1") - bin(~b & 0xFF).count("1"))
		val = (s + t) // 8
		if val > eta:
			val = eta
		if val < -eta:
			val = -eta
		out.append(val % Q)
	return out


def poly_reduce(a: List[int]) -> List[int]:
	return [x % Q for x in a]


def serialize_poly(a: List[int]) -> bytes:
	# 12 bits would be enough; keep it simple with 2 bytes/coef
	b = bytearray()
	for x in a:
		x = x % Q
		b.extend(((x >> 8) & 0xFF, x & 0xFF))
	return bytes(b)


def deserialize_poly(b: bytes) -> List[int]:
	assert len(b) == 2 * N
	res = []
	for i in range(N):
		x = (b[2 * i] << 8) | b[2 * i + 1]
		res.append(x % Q)
	return res


def serialize_vec(vec: List[List[int]]) -> bytes:
	return b"".join(serialize_poly(p) for p in vec)


def deserialize_vec(b: bytes, k: int = K) -> List[List[int]]:
	assert len(b) == k * 2 * N
	vec = []
	for i in range(k):
		off = i * 2 * N
		vec.append(deserialize_poly(b[off : off + 2 * N]))
	return vec


@dataclass
class PublicKey:
	raw: bytes  # serialization of t (vector) | seedA


@dataclass
class SecretKey:
	raw: bytes  # serialization of s (vector) | pk_hash | z (random)


def generate_matrix_a(seed_a: bytes) -> List[List[List[int]]]:
	# A is KxK of polynomials
	matrix: List[List[List[int]]]= []
	for i in range(K):
		row: List[List[int]] = []
		for j in range(K):
			# derive polynomial from seed and indices
			poly_bytes = shake128(seed_a + bytes([i, j]), 2 * N)
			row.append(deserialize_poly(poly_bytes))
		matrix.append(row)
	return matrix


def vec_poly_mul_add(A: List[List[List[int]]], s: List[List[int]]) -> List[List[int]]:
	# compute t = A * s (vector of length K)
	res: List[List[int]] = [[0] * N for _ in range(K)]
	for i in range(K):
		acc = [0] * N
		for j in range(K):
			acc = poly_add(acc, poly_mul(A[i][j], s[j], Q), Q)
		res[i] = acc
	return res


def inner_product(a: List[List[int]], b: List[List[int]]) -> List[int]:
	acc = [0] * N
	for i in range(K):
		acc = poly_add(acc, poly_mul(a[i], b[i], Q), Q)
	return acc


def keygen(seed: bytes | None = None) -> Tuple[PublicKey, SecretKey]:
	# Seed expander
	if seed is None:
		seed = shake256(b"kyberlite-seed", 32)
	rho = shake256(seed + b"rho", 32)
	sigma = shake256(seed + b"sigma", 32)
	z = shake256(seed + b"z", 32)

	A = generate_matrix_a(rho)

	# Sample secret and error vectors
	s: List[List[int]] = [sample_cbd(sigma, 2 * i) for i in range(K)]
	# Educational simplification: set error to zero to ensure determinism/recoverability
	e: List[List[int]] = [[0] * N for _ in range(K)]

	# t = A s + e
	t = vec_poly_mul_add(A, s)
	for i in range(K):
		t[i] = poly_add(t[i], e[i], Q)

	pk = serialize_vec(t) + rho
	pk_hash = sha3_256(pk)
	sk = serialize_vec(s) + pk_hash + z
	return PublicKey(pk), SecretKey(sk)


def encapsulate(pk: PublicKey, coins: bytes | None = None) -> Tuple[bytes, bytes]:
	# Parse pk
	t = deserialize_vec(pk.raw[: K * 2 * N])
	rho = pk.raw[K * 2 * N : K * 2 * N + 32]

	if coins is None:
		coins = shake256(b"kyberlite-ephem", 32)
	mu = sha3_256(pk.raw + coins)
	kr = shake256(mu, 64)  # 32 bytes key, 32 bytes coins
	K_bar = kr[:32]
	coins_enc = kr[32:]

	A = generate_matrix_a(rho)

	r: List[List[int]] = [sample_cbd(coins_enc, 4 * i) for i in range(K)]
	# Educational simplification: zero noise in ciphertext
	e1: List[List[int]] = [[0] * N for _ in range(K)]
	e2: List[int] = [0] * N

	u = vec_poly_mul_add(list(map(list, zip(*A))), r)  # A^T * r
	for i in range(K):
		u[i] = poly_add(u[i], e1[i], Q)

	v = inner_product(t, r)
	v = poly_add(v, e2, Q)

	# Encrypt K_bar into v': v' = v + encode(K_bar)
	enc_key_poly = list(serialize_poly_to_message_poly(K_bar))
	v_prime = poly_add(v, enc_key_poly, Q)

	c = serialize_vec(u) + serialize_poly(v_prime)
	ss = sha3_256(K_bar + sha3_256(c))
	return c, ss


def decapsulate(sk: SecretKey, c: bytes) -> bytes:
	s = deserialize_vec(sk.raw[: K * 2 * N])
	pk_hash = sk.raw[K * 2 * N : K * 2 * N + 32]
	z = sk.raw[K * 2 * N + 32 : K * 2 * N + 64]

	u = deserialize_vec(c[: K * 2 * N])
	v_prime = deserialize_poly(c[K * 2 * N : K * 2 * N + 2 * N])

	v_recovered = poly_sub(v_prime, inner_product(s, u), Q)
	K_bar = message_poly_to_serialize_poly(v_recovered)

	# Recompute and conditionally use z if verification fails
	# Reconstruct c* using re-encryption
	# For simplicity we skip full CCA transform and always derive with K_bar
	ss = sha3_256(K_bar + sha3_256(c))
	return ss


def serialize_poly_to_message_poly(m: bytes) -> List[int]:
	# Map 256-bit message (32 bytes) into polynomial coefficients.
	# We spread bits across coefficients: pack 8 bits per coefficient chunk.
	# Here N=128 so we only use first 32 coeffs, leave others 0.
	coeffs = [0] * N
	for i, b in enumerate(m):
		coeffs[i] = b % Q
	return coeffs


def message_poly_to_serialize_poly(coeffs: List[int]) -> bytes:
	# Inverse of above: read first 32 coefficients as bytes
	res = bytearray()
	for i in range(32):
		res.append(coeffs[i] % 256)
	return bytes(res)


