"""
Small polynomial ring utilities for Kyber-like operations over R_q = Z_q[X]/(X^n + 1).

This is a didactic, straightforward implementation prioritizing clarity over speed.
Not constant-time.
"""

from __future__ import annotations

from typing import List, Tuple


def poly_add(a: List[int], b: List[int], q: int) -> List[int]:
	return [(x + y) % q for x, y in zip(a, b)]


def poly_sub(a: List[int], b: List[int], q: int) -> List[int]:
	return [(x - y) % q for x, y in zip(a, b)]


def poly_neg(a: List[int], q: int) -> List[int]:
	return [(-x) % q for x in a]


def poly_mul(a: List[int], b: List[int], q: int) -> List[int]:
	# Schoolbook multiplication in R_q = Z_q[X]/(X^n + 1)
	n = len(a)
	assert len(b) == n
	res = [0] * n
	for i in range(n):
		ai = a[i]
		for j in range(n):
			k = i + j
			if k < n:
				res[k] = (res[k] + ai * b[j]) % q
			else:
				# X^n == -1 mod (X^n + 1)
				res[k - n] = (res[k - n] - ai * b[j]) % q
	return res


def poly_center(a: List[int], q: int) -> List[int]:
	# Map coefficients to centered representatives in [-(q//2), q//2]
	return [((x + q//2) % q) - q//2 for x in a]


def compress_coefficient(x: int, q: int, bits: int) -> int:
	# Simple rounding compression: round to bits precision
	levels = 1 << bits
	return int((x % q) * levels / q + 0.5) & (levels - 1)


def decompress_coefficient(xc: int, q: int, bits: int) -> int:
	levels = 1 << bits
	return int((xc * q + levels // 2) // levels) % q


def ntt_placeholder(a: List[int], q: int) -> List[int]:
	# Placeholder for NTT. For simplicity we don't implement NTT; we rely on schoolbook.
	return list(a)


def inv_ntt_placeholder(a: List[int], q: int) -> List[int]:
	return list(a)


