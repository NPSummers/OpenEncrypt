import os
import subprocess
import unittest


class TestOpenEncryptUniformFailure(unittest.TestCase):
	def test_decrypt_failure_is_uniform(self):
		# Keygen
		subprocess.check_call(
			[
				"python3",
				"-m",
				"openencrypt.openencrypt",
				"keygen",
				"--public",
				"/tmp/oe_pub.asc",
				"--secret",
				"/tmp/oe_sec.asc",
				"--name",
				"Alice",
				"--email",
				"alice@example.com",
			],
			stdout=subprocess.DEVNULL,
		)
		# Encrypt a message
		with open("/tmp/oe_msg.txt", "wb") as f:
			f.write(b"hello")
		subprocess.check_call(
			[
				"python3",
				"-m",
				"openencrypt.openencrypt",
				"encrypt",
				"--input",
				"/tmp/oe_msg.txt",
				"--output",
				"/tmp/oe_msg.asc",
				"--public",
				"/tmp/oe_pub.asc",
				"--secret",
				"/tmp/oe_sec.asc",
			],
			stdout=subprocess.DEVNULL,
		)
		# Tamper the file (truncate) and attempt decrypt.
		with open("/tmp/oe_msg.asc", "rb") as f:
			data = f.read()
		with open("/tmp/oe_msg_bad.asc", "wb") as f:
			f.write(data[: len(data) // 2])
		p = subprocess.run(
			[
				"python3",
				"-m",
				"openencrypt.openencrypt",
				"decrypt",
				"--input",
				"/tmp/oe_msg_bad.asc",
				"--output",
				"/tmp/oe_out.txt",
				"--secret",
				"/tmp/oe_sec.asc",
				"--public",
				"/tmp/oe_pub.asc",
			],
			capture_output=True,
			text=True,
		)
		self.assertEqual(p.returncode, 2)
		self.assertIn("decryption failed", p.stderr)


if __name__ == "__main__":
	unittest.main()

