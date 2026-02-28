import unittest

from openencrypt import sphincs_plus as spx


class TestSphincsPlus(unittest.TestCase):
	def test_toy_sign_verify(self):
		p = spx.SPHINCS_TEST_UNSAFE
		pk, sk = spx.keygen(params=p, seed=b"\x01" * p.n)
		msg = b"hello"
		sig = spx.sign(sk, msg, optrand=b"\x02" * p.n)
		self.assertTrue(spx.verify(pk, msg, sig))
		self.assertFalse(spx.verify(pk, msg + b"!", sig))

	def test_prod_param_smoke_sizes(self):
		p = spx.SPHINCS_SHAKE_256F_SIMPLE
		self.assertEqual(p.n, 32)
		self.assertGreater(spx.signature_size(p), 10_000)


if __name__ == "__main__":
	unittest.main()

