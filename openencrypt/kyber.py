"""
CRYSTALS-Kyber Round3 (v3.01) KEM in pure Python (stdlib only).

Implements the Kyber.CCAKEM construction from the Round3 specification.

Security notes:
- This is **not side-channel hardened** (Python big-int/branches/memory access).
- Intended for correctness, testability, and "production-shaped" APIs, not speed.

Spec reference:
  CRYSTALS-Kyber Algorithm Specifications (Round3, v3.01)
  https://pq-crystals.org/kyber/data/kyber-specification-round3-20210131.pdf
"""

from __future__ import annotations

from dataclasses import dataclass
import hmac
import os
from typing import Iterable, List, Sequence, Tuple

from .sha3 import sha3_256, sha3_512, shake128, shake256


N = 256
Q = 3329
SYMBYTES = 32


@dataclass(frozen=True)
class KyberParams:
	name: str
	k: int
	eta1: int
	eta2: int
	du: int
	dv: int


KYBER512 = KyberParams(name="Kyber512", k=2, eta1=3, eta2=2, du=10, dv=4)
KYBER768 = KyberParams(name="Kyber768", k=3, eta1=2, eta2=2, du=10, dv=4)
KYBER1024 = KyberParams(name="Kyber1024", k=4, eta1=2, eta2=2, du=11, dv=5)


def _montgomery_reduce(a: int) -> int:
	# For pure Python schoolbook implementation we keep it simple:
	return a % Q


def _freeze(a: int) -> int:
	return a % Q


def _poly_add(a: Sequence[int], b: Sequence[int]) -> List[int]:
	return [(_freeze(x + y)) for x, y in zip(a, b)]


def _poly_sub(a: Sequence[int], b: Sequence[int]) -> List[int]:
	return [(_freeze(x - y)) for x, y in zip(a, b)]


def _poly_mul(a: Sequence[int], b: Sequence[int]) -> List[int]:
	"""
	Negacyclic multiplication in R_q = Z_q[x]/(x^N + 1).
	Schoolbook; correct but slow.
	"""
	res = [0] * N
	for i in range(N):
		ai = a[i]
		for j in range(N):
			prod = ai * b[j]
			idx = i + j
			if idx < N:
				res[idx] += prod
			else:
				res[idx - N] -= prod
	return [_freeze(x) for x in res]


def _polyvec_pointwise_acc(a: Sequence[Sequence[int]], b: Sequence[Sequence[int]]) -> List[int]:
	acc = [0] * N
	for i in range(len(a)):
		acc = _poly_add(acc, _poly_mul(a[i], b[i]))
	return acc


def _bytes_to_u16_le(b0: int, b1: int) -> int:
	return b0 | (b1 << 8)


def _poly_tobytes(a: Sequence[int]) -> bytes:
	# 12-bit packing, 256 coefficients => 384 bytes
	r = bytearray(384)
	for i in range(N // 2):
		t0 = _freeze(a[2 * i])
		t1 = _freeze(a[2 * i + 1])
		r[3 * i + 0] = t0 & 0xFF
		r[3 * i + 1] = ((t0 >> 8) | ((t1 & 0x0F) << 4)) & 0xFF
		r[3 * i + 2] = (t1 >> 4) & 0xFF
	return bytes(r)


def _poly_frombytes(b: bytes) -> List[int]:
	if len(b) != 384:
		raise ValueError("poly_frombytes expects 384 bytes")
	r = [0] * N
	for i in range(N // 2):
		r[2 * i] = (b[3 * i + 0] | ((b[3 * i + 1] & 0x0F) << 8)) % Q
		r[2 * i + 1] = ((b[3 * i + 1] >> 4) | (b[3 * i + 2] << 4)) % Q
	return r


def _polyvec_tobytes(v: Sequence[Sequence[int]]) -> bytes:
	return b"".join(_poly_tobytes(p) for p in v)


def _polyvec_frombytes(b: bytes, k: int) -> List[List[int]]:
	if len(b) != 384 * k:
		raise ValueError("polyvec_frombytes: wrong length")
	return [_poly_frombytes(b[i * 384:(i + 1) * 384]) for i in range(k)]


def _poly_compress(a: Sequence[int], d: int) -> bytes:
	if d == 4:
		# 256*4 bits => 128 bytes
		r = bytearray(128)
		for i in range(N // 2):
			t0 = (((_freeze(a[2 * i]) << d) + Q // 2) // Q) & 0x0F
			t1 = (((_freeze(a[2 * i + 1]) << d) + Q // 2) // Q) & 0x0F
			r[i] = t0 | (t1 << 4)
		return bytes(r)
	if d == 5:
		# 256*5 bits => 160 bytes, pack 8 coeffs into 5 bytes
		r = bytearray(160)
		for i in range(N // 8):
			t = [0] * 8
			for j in range(8):
				t[j] = (((_freeze(a[8 * i + j]) << d) + Q // 2) // Q) & 0x1F
			r[5 * i + 0] = (t[0] | ((t[1] & 0x07) << 5)) & 0xFF
			r[5 * i + 1] = ((t[1] >> 3) | (t[2] << 2) | ((t[3] & 0x01) << 7)) & 0xFF
			r[5 * i + 2] = ((t[3] >> 1) | (t[4] << 4)) & 0xFF
			r[5 * i + 3] = ((t[4] >> 4) | (t[5] << 1) | ((t[6] & 0x03) << 6)) & 0xFF
			r[5 * i + 4] = ((t[6] >> 2) | (t[7] << 3)) & 0xFF
		return bytes(r)
	raise ValueError("unsupported d for poly_compress")


def _poly_decompress(b: bytes, d: int) -> List[int]:
	r = [0] * N
	if d == 4:
		if len(b) != 128:
			raise ValueError("poly_decompress d=4 expects 128 bytes")
		for i in range(N // 2):
			t0 = b[i] & 0x0F
			t1 = (b[i] >> 4) & 0x0F
			r[2 * i] = ((t0 * Q + (1 << (d - 1))) >> d) % Q
			r[2 * i + 1] = ((t1 * Q + (1 << (d - 1))) >> d) % Q
		return r
	if d == 5:
		if len(b) != 160:
			raise ValueError("poly_decompress d=5 expects 160 bytes")
		for i in range(N // 8):
			b0, b1, b2, b3, b4 = b[5 * i:5 * i + 5]
			t0 = b0 & 0x1F
			t1 = ((b0 >> 5) | ((b1 & 0x03) << 3)) & 0x1F
			t2 = (b1 >> 2) & 0x1F
			t3 = ((b1 >> 7) | ((b2 & 0x0F) << 1)) & 0x1F
			t4 = ((b2 >> 4) | ((b3 & 0x01) << 4)) & 0x1F
			t5 = (b3 >> 1) & 0x1F
			t6 = ((b3 >> 6) | ((b4 & 0x07) << 2)) & 0x1F
			t7 = (b4 >> 3) & 0x1F
			ts = [t0, t1, t2, t3, t4, t5, t6, t7]
			for j in range(8):
				r[8 * i + j] = ((ts[j] * Q + (1 << (d - 1))) >> d) % Q
		return r
	raise ValueError("unsupported d for poly_decompress")


def _polyvec_compress(v: Sequence[Sequence[int]], d: int) -> bytes:
	k = len(v)
	if d == 10:
		# 4 coeffs => 5 bytes. 256 coeff => 320 bytes per poly.
		out = bytearray(320 * k)
		off = 0
		for p in v:
			for i in range(N // 4):
				t = [0] * 4
				for j in range(4):
					t[j] = (((_freeze(p[4 * i + j]) << d) + Q // 2) // Q) & 0x3FF
				out[off + 0] = (t[0] >> 0) & 0xFF
				out[off + 1] = ((t[0] >> 8) | ((t[1] & 0x3F) << 2)) & 0xFF
				out[off + 2] = ((t[1] >> 6) | ((t[2] & 0x0F) << 4)) & 0xFF
				out[off + 3] = ((t[2] >> 4) | ((t[3] & 0x03) << 6)) & 0xFF
				out[off + 4] = (t[3] >> 2) & 0xFF
				off += 5
		return bytes(out)
	if d == 11:
		# 8 coeffs => 11 bytes. 256 coeff => 352 bytes per poly.
		out = bytearray(352 * k)
		off = 0
		for p in v:
			for i in range(N // 8):
				t = [0] * 8
				for j in range(8):
					t[j] = (((_freeze(p[8 * i + j]) << d) + Q // 2) // Q) & 0x7FF
				out[off + 0] = (t[0] >> 0) & 0xFF
				out[off + 1] = ((t[0] >> 8) | ((t[1] & 0x1F) << 3)) & 0xFF
				out[off + 2] = ((t[1] >> 5) | ((t[2] & 0x03) << 6)) & 0xFF
				out[off + 3] = (t[2] >> 2) & 0xFF
				out[off + 4] = ((t[2] >> 10) | ((t[3] & 0x7F) << 1)) & 0xFF
				out[off + 5] = ((t[3] >> 7) | ((t[4] & 0x0F) << 4)) & 0xFF
				out[off + 6] = ((t[4] >> 4) | ((t[5] & 0x01) << 7)) & 0xFF
				out[off + 7] = (t[5] >> 1) & 0xFF
				out[off + 8] = ((t[5] >> 9) | ((t[6] & 0x3F) << 2)) & 0xFF
				out[off + 9] = ((t[6] >> 6) | ((t[7] & 0x07) << 5)) & 0xFF
				out[off + 10] = (t[7] >> 3) & 0xFF
				off += 11
		return bytes(out)
	raise ValueError("unsupported d for polyvec_compress")


def _polyvec_decompress(b: bytes, k: int, d: int) -> List[List[int]]:
	out: List[List[int]] = []
	if d == 10:
		if len(b) != 320 * k:
			raise ValueError("polyvec_decompress d=10: wrong length")
		off = 0
		for _ in range(k):
			p = [0] * N
			for i in range(N // 4):
				b0, b1, b2, b3, b4 = b[off:off + 5]
				off += 5
				t0 = (b0 | (b1 << 8)) & 0x3FF
				t1 = ((b1 >> 2) | (b2 << 6)) & 0x3FF
				t2 = ((b2 >> 4) | (b3 << 4)) & 0x3FF
				t3 = ((b3 >> 6) | (b4 << 2)) & 0x3FF
				ts = [t0, t1, t2, t3]
				for j in range(4):
					p[4 * i + j] = ((ts[j] * Q + (1 << (d - 1))) >> d) % Q
			out.append(p)
		return out
	if d == 11:
		if len(b) != 352 * k:
			raise ValueError("polyvec_decompress d=11: wrong length")
		off = 0
		for _ in range(k):
			p = [0] * N
			for i in range(N // 8):
				ch = b[off:off + 11]
				off += 11
				b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10 = ch
				t0 = (b0 | (b1 << 8)) & 0x7FF
				t1 = ((b1 >> 3) | (b2 << 5)) & 0x7FF
				t2 = ((b2 >> 6) | (b3 << 2) | (b4 << 10)) & 0x7FF
				t3 = ((b4 >> 1) | (b5 << 7)) & 0x7FF
				t4 = ((b5 >> 4) | (b6 << 4)) & 0x7FF
				t5 = ((b6 >> 7) | (b7 << 1) | (b8 << 9)) & 0x7FF
				t6 = ((b8 >> 2) | (b9 << 6)) & 0x7FF
				t7 = ((b9 >> 5) | (b10 << 3)) & 0x7FF
				ts = [t0, t1, t2, t3, t4, t5, t6, t7]
				for j in range(8):
					p[8 * i + j] = ((ts[j] * Q + (1 << (d - 1))) >> d) % Q
			out.append(p)
		return out
	raise ValueError("unsupported d for polyvec_decompress")


def _poly_frommsg(m: bytes) -> List[int]:
	if len(m) != SYMBYTES:
		raise ValueError("poly_frommsg expects 32-byte message")
	r = [0] * N
	for i in range(N):
		bit = (m[i // 8] >> (i % 8)) & 1
		r[i] = (bit * ((Q + 1) // 2)) % Q
	return r


def _poly_tomsg(a: Sequence[int]) -> bytes:
	out = bytearray(SYMBYTES)
	for i in range(N):
		t = (((_freeze(a[i]) << 1) + Q // 2) // Q) & 1
		out[i // 8] |= t << (i % 8)
	return bytes(out)


def _shake128_stream(seed: bytes, outlen: int) -> bytes:
	return shake128(seed, outlen)


def _rej_uniform(buf: bytes, num: int) -> List[int]:
	r: List[int] = []
	# Consume 3 bytes -> 2 12-bit values
	i = 0
	while len(r) < num and i + 3 <= len(buf):
		d0 = buf[i] | ((buf[i + 1] & 0x0F) << 8)
		d1 = (buf[i + 1] >> 4) | (buf[i + 2] << 4)
		i += 3
		if d0 < Q:
			r.append(d0)
			if len(r) == num:
				break
		if d1 < Q:
			r.append(d1)
	return r


def _gen_matrix(rho: bytes, k: int, transpose: bool) -> List[List[List[int]]]:
	# A is k x k; each entry a polynomial sampled uniformly mod q using SHAKE128 XOF.
	A: List[List[List[int]]] = []
	for i in range(k):
		row: List[List[int]] = []
		for j in range(k):
			xof_in = rho + bytes([j, i]) if transpose else rho + bytes([i, j])
			need = N
			outlen = 768  # plenty for 256 coeffs via rej. sampling
			coeffs: List[int] = []
			while len(coeffs) < need:
				buf = _shake128_stream(xof_in, outlen)
				coeffs = _rej_uniform(buf, need)
				outlen *= 2
			row.append(coeffs[:N])
		A.append(row)
	return A


def _prf(seed: bytes, nonce: int, outlen: int) -> bytes:
	if nonce < 0 or nonce > 255:
		raise ValueError("nonce must fit in 1 byte")
	return shake256(seed + bytes([nonce]), outlen)


def _cbd_eta(buf: bytes, eta: int) -> List[int]:
	"""
	Centered binomial distribution.
	- eta=2 uses 128 bytes input
	- eta=3 uses 192 bytes input
	"""
	if eta == 2:
		if len(buf) != 128:
			raise ValueError("cbd eta=2 expects 128 bytes")
		r = [0] * N
		for i in range(N // 8):
			t = int.from_bytes(buf[4 * i:4 * i + 4], "little")
			d = (t & 0x55555555) + ((t >> 1) & 0x55555555)
			for j in range(8):
				a = (d >> (4 * j)) & 0x3
				b = (d >> (4 * j + 2)) & 0x3
				r[8 * i + j] = _freeze(a - b)
		return r
	if eta == 3:
		if len(buf) != 192:
			raise ValueError("cbd eta=3 expects 192 bytes")
		r = [0] * N
		for i in range(N // 4):
			t = int.from_bytes(buf[3 * i:3 * i + 3], "little")
			d = (t & 0x00249249) + ((t >> 1) & 0x00249249) + ((t >> 2) & 0x00249249)
			for j in range(4):
				a = (d >> (6 * j)) & 0x7
				b = (d >> (6 * j + 3)) & 0x7
				r[4 * i + j] = _freeze(a - b)
		return r
	raise ValueError("unsupported eta")


def _poly_getnoise(seed: bytes, nonce: int, eta: int) -> List[int]:
	inlen = (eta * N) // 4
	buf = _prf(seed, nonce, inlen)
	return _cbd_eta(buf, eta)


def _polyvec_getnoise(seed: bytes, nonce0: int, k: int, eta: int) -> List[List[int]]:
	return [_poly_getnoise(seed, nonce0 + i, eta) for i in range(k)]


def _indcpa_keypair(params: KyberParams, d: bytes | None = None) -> Tuple[bytes, bytes]:
	"""
	Returns (pk, sk_indcpa) where:
	- pk = polyvec(t) || rho
	- sk = polyvec(s)
	"""
	if d is None:
		d = os.urandom(SYMBYTES)
	gh = sha3_512(d)
	rho, sigma = gh[:SYMBYTES], gh[SYMBYTES:]
	A = _gen_matrix(rho, params.k, transpose=False)
	s = _polyvec_getnoise(sigma, 0, params.k, params.eta1)
	e = _polyvec_getnoise(sigma, params.k, params.k, params.eta1)
	t: List[List[int]] = []
	for i in range(params.k):
		# t[i] = sum_j A[i][j] * s[j] + e[i]
		acc = [0] * N
		for j in range(params.k):
			acc = _poly_add(acc, _poly_mul(A[i][j], s[j]))
		t.append(_poly_add(acc, e[i]))
	pk = _polyvec_tobytes(t) + rho
	sk = _polyvec_tobytes(s)
	return pk, sk


def _indcpa_enc(params: KyberParams, m: bytes, pk: bytes, coins: bytes) -> bytes:
	if len(m) != SYMBYTES or len(coins) != SYMBYTES:
		raise ValueError("indcpa_enc: m and coins must be 32 bytes each")
	k = params.k
	t = _polyvec_frombytes(pk[:384 * k], k)
	rho = pk[384 * k:384 * k + SYMBYTES]
	A_t = _gen_matrix(rho, k, transpose=True)
	r = _polyvec_getnoise(coins, 0, k, params.eta1)
	e1 = _polyvec_getnoise(coins, k, k, params.eta2)
	e2 = _poly_getnoise(coins, 2 * k, params.eta2)

	u: List[List[int]] = []
	for i in range(k):
		acc = [0] * N
		for j in range(k):
			acc = _poly_add(acc, _poly_mul(A_t[i][j], r[j]))
		u.append(_poly_add(acc, e1[i]))
	v = _poly_add(_polyvec_pointwise_acc(t, r), e2)
	v = _poly_add(v, _poly_frommsg(m))

	c1 = _polyvec_compress(u, params.du)
	c2 = _poly_compress(v, params.dv)
	return c1 + c2


def _indcpa_dec(params: KyberParams, c: bytes, sk_indcpa: bytes) -> bytes:
	k = params.k
	c1_len = (320 if params.du == 10 else 352) * k
	c2_len = 128 if params.dv == 4 else 160
	if len(c) != c1_len + c2_len:
		raise ValueError("indcpa_dec: ciphertext wrong length")
	u = _polyvec_decompress(c[:c1_len], k, params.du)
	v = _poly_decompress(c[c1_len:], params.dv)
	s = _polyvec_frombytes(sk_indcpa, k)
	mp = _poly_sub(v, _polyvec_pointwise_acc(s, u))
	return _poly_tomsg(mp)


def _kdf(ss_in: bytes) -> bytes:
	# KDF output is 32 bytes using SHAKE256
	return shake256(ss_in, SYMBYTES)


def kem_sizes(params: KyberParams) -> Tuple[int, int, int, int]:
	"""
	Returns (pk_bytes, sk_bytes, ct_bytes, ss_bytes)
	"""
	pk_bytes = 384 * params.k + SYMBYTES
	sk_indcpa = 384 * params.k
	sk_bytes = sk_indcpa + pk_bytes + SYMBYTES + SYMBYTES  # sk || pk || H(pk) || z
	ct_bytes = ((320 if params.du == 10 else 352) * params.k) + (128 if params.dv == 4 else 160)
	return pk_bytes, sk_bytes, ct_bytes, SYMBYTES


@dataclass(frozen=True)
class PublicKey:
	params: KyberParams
	raw: bytes


@dataclass(frozen=True)
class SecretKey:
	params: KyberParams
	raw: bytes


def keygen(params: KyberParams = KYBER512, seed: bytes | None = None) -> Tuple[PublicKey, SecretKey]:
	"""
	Generate Kyber KEM keypair.
	- If seed is provided (32 bytes), keys are deterministic (for tests).
	"""
	if seed is not None and len(seed) != SYMBYTES:
		raise ValueError("seed must be 32 bytes")
	pk, sk_indcpa = _indcpa_keypair(params, d=seed)
	hpk = sha3_256(pk)
	z = os.urandom(SYMBYTES) if seed is None else sha3_256(seed + b"z")
	sk = sk_indcpa + pk + hpk + z
	return PublicKey(params=params, raw=pk), SecretKey(params=params, raw=sk)


def encapsulate(pk: PublicKey, coins: bytes | None = None) -> Tuple[bytes, bytes]:
	"""
	Returns (ciphertext, shared_secret).
	- If coins is provided (32 bytes), encapsulation is deterministic (for tests).
	"""
	params = pk.params
	_, _, ct_bytes, _ = kem_sizes(params)
	if coins is None:
		m = os.urandom(SYMBYTES)
	else:
		if len(coins) != SYMBYTES:
			raise ValueError("coins must be 32 bytes")
		m = sha3_256(coins)  # deterministic but not trivially replaying input
	hpk = sha3_256(pk.raw)
	kr = sha3_512(m + hpk)  # 64 bytes => K || coins
	Kbar, coins2 = kr[:SYMBYTES], kr[SYMBYTES:]
	c = _indcpa_enc(params, m, pk.raw, coins2)
	if len(c) != ct_bytes:
		raise AssertionError("ciphertext length mismatch")
	ss = _kdf(Kbar + sha3_256(c))
	return c, ss


def decapsulate(sk: SecretKey, c: bytes) -> bytes:
	params = sk.params
	pk_bytes, sk_bytes, ct_bytes, _ = kem_sizes(params)
	if len(sk.raw) != sk_bytes:
		raise ValueError("secret key wrong length for params")
	if len(c) != ct_bytes:
		raise ValueError("ciphertext wrong length for params")
	sk_indcpa = sk.raw[:384 * params.k]
	pk = sk.raw[384 * params.k:384 * params.k + pk_bytes]
	hpk = sk.raw[384 * params.k + pk_bytes:384 * params.k + pk_bytes + SYMBYTES]
	z = sk.raw[384 * params.k + pk_bytes + SYMBYTES:384 * params.k + pk_bytes + 2 * SYMBYTES]

	m = _indcpa_dec(params, c, sk_indcpa)
	kr = sha3_512(m + hpk)
	Kbar, coins2 = kr[:SYMBYTES], kr[SYMBYTES:]
	cmp = _indcpa_enc(params, m, pk, coins2)
	if not hmac.compare_digest(c, cmp):
		Kbar = z
	return _kdf(Kbar + sha3_256(c))


def params_from_name(name: str) -> KyberParams:
	name = name.strip()
	if name == "Kyber512":
		return KYBER512
	if name == "Kyber768":
		return KYBER768
	if name == "Kyber1024":
		return KYBER1024
	raise ValueError("unknown Kyber params name")


def params_to_id(params: KyberParams) -> int:
	if params.name == "Kyber512":
		return 1
	if params.name == "Kyber768":
		return 2
	if params.name == "Kyber1024":
		return 3
	raise ValueError("unknown params")


def params_from_id(pid: int) -> KyberParams:
	if pid == 1:
		return KYBER512
	if pid == 2:
		return KYBER768
	if pid == 3:
		return KYBER1024
	raise ValueError("unknown Kyber param id")

