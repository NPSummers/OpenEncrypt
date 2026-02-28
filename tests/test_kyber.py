import unittest

from openencrypt.kyber import (
	KYBER512,
	KYBER768,
	KYBER1024,
	decapsulate,
	encapsulate,
	kem_sizes,
	keygen,
)


class TestKyberKEM(unittest.TestCase):
	def _roundtrip(self, params):
		seed = bytes([7]) * 32
		coins = bytes([9]) * 32
		pk, sk = keygen(params=params, seed=seed)
		ct, ss = encapsulate(pk, coins=coins)
		ss2 = decapsulate(sk, ct)
		self.assertEqual(ss, ss2)

		pk_len, sk_len, ct_len, ss_len = kem_sizes(params)
		self.assertEqual(len(pk.raw), pk_len)
		self.assertEqual(len(sk.raw), sk_len)
		self.assertEqual(len(ct), ct_len)
		self.assertEqual(len(ss), ss_len)

	def _fo_tamper(self, params):
		seed = bytes([1]) * 32
		coins = bytes([2]) * 32
		pk, sk = keygen(params=params, seed=seed)
		ct, ss = encapsulate(pk, coins=coins)
		# Flip one bit; decapsulation should still output 32 bytes but produce a different secret.
		ct_bad = bytearray(ct)
		ct_bad[len(ct_bad) // 2] ^= 0x01
		ss_bad = decapsulate(sk, bytes(ct_bad))
		self.assertEqual(len(ss_bad), 32)
		self.assertNotEqual(ss_bad, ss)

	def test_kyber512_roundtrip(self):
		self._roundtrip(KYBER512)

	def test_kyber768_roundtrip(self):
		self._roundtrip(KYBER768)

	def test_kyber1024_roundtrip(self):
		self._roundtrip(KYBER1024)

	def test_kyber512_tamper_fo_fallback(self):
		self._fo_tamper(KYBER512)

	def test_kyber768_tamper_fo_fallback(self):
		self._fo_tamper(KYBER768)

	def test_kyber1024_tamper_fo_fallback(self):
		self._fo_tamper(KYBER1024)


if __name__ == "__main__":
	unittest.main()

