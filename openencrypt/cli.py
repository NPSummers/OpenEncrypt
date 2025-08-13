from __future__ import annotations

import argparse
import os
import sys

from .kyberlite import keygen, encapsulate, decapsulate, PublicKey, SecretKey
from .sha3 import sha3_256
from .symm import encrypt as symm_encrypt, decrypt as symm_decrypt


def cmd_keygen(args: argparse.Namespace) -> None:
	pk, sk = keygen()
	with open(args.public, "wb") as f:
		f.write(pk.raw)
	with open(args.secret, "wb") as f:
		f.write(sk.raw)
	print(f"wrote public key to {args.public}, secret key to {args.secret}")


def cmd_encaps(args: argparse.Namespace) -> None:
	with open(args.public, "rb") as f:
		pk_bytes = f.read()
	pk = PublicKey(pk_bytes)
	c, ss = encapsulate(pk)
	with open(args.cipherkey, "wb") as f:
		f.write(c)
	with open(args.shared, "wb") as f:
		f.write(ss)
	print(f"wrote KEM ciphertext to {args.cipherkey}, shared secret to {args.shared}")


def cmd_decaps(args: argparse.Namespace) -> None:
	with open(args.secret, "rb") as f:
		sk_bytes = f.read()
	sk = SecretKey(sk_bytes)
	with open(args.cipherkey, "rb") as f:
		c = f.read()
	ss = decapsulate(sk, c)
	with open(args.shared, "wb") as f:
		f.write(ss)
	print(f"wrote shared secret to {args.shared}")


def cmd_encrypt(args: argparse.Namespace) -> None:
	with open(args.shared, "rb") as f:
		ss = f.read()
	with open(args.input, "rb") as f:
		pt = f.read()
	nonce = sha3_256(os.urandom(32))[:16]
	ciphertext, tag = symm_encrypt(ss, nonce, pt, ad=args.ad.encode())
	with open(args.output, "wb") as f:
		f.write(nonce + tag + ciphertext)
	print(f"wrote ciphertext to {args.output}")


def cmd_decrypt(args: argparse.Namespace) -> None:
	with open(args.shared, "rb") as f:
		ss = f.read()
	with open(args.input, "rb") as f:
		blob = f.read()
	if len(blob) < 16 + 32:
		print("ciphertext too short", file=sys.stderr)
		sys.exit(2)
	nonce, tag, ct = blob[:16], blob[16:48], blob[48:]
	pt = symm_decrypt(ss, nonce, ct, tag, ad=args.ad.encode())
	if pt is None:
		print("authentication failed", file=sys.stderr)
		sys.exit(2)
	with open(args.output, "wb") as f:
		f.write(pt)
	print(f"wrote plaintext to {args.output}")


def build_parser() -> argparse.ArgumentParser:
	ap = argparse.ArgumentParser(prog="openencrypt", description="Educational PQ offline crypto")
	sub = ap.add_subparsers(dest="cmd", required=True)

	ap_k = sub.add_parser("keygen", help="generate keypair")
	ap_k.add_argument("--public", default="pk.bin")
	ap_k.add_argument("--secret", default="sk.bin")
	ap_k.set_defaults(func=cmd_keygen)

	ap_ce = sub.add_parser("encaps", help="encapsulate to a public key")
	ap_ce.add_argument("--public", default="pk.bin")
	ap_ce.add_argument("--cipherkey", default="c_kem.bin")
	ap_ce.add_argument("--shared", default="ss.bin")
	ap_ce.set_defaults(func=cmd_encaps)

	ap_cd = sub.add_parser("decaps", help="decapsulate with a secret key")
	ap_cd.add_argument("--secret", default="sk.bin")
	ap_cd.add_argument("--cipherkey", default="c_kem.bin")
	ap_cd.add_argument("--shared", default="ss.bin")
	ap_cd.set_defaults(func=cmd_decaps)

	ap_e = sub.add_parser("encrypt", help="symmetric encrypt with shared secret")
	ap_e.add_argument("--shared", default="ss.bin")
	ap_e.add_argument("--input", required=True)
	ap_e.add_argument("--output", required=True)
	ap_e.add_argument("--ad", default="")
	ap_e.set_defaults(func=cmd_encrypt)

	ap_d = sub.add_parser("decrypt", help="symmetric decrypt with shared secret")
	ap_d.add_argument("--shared", default="ss.bin")
	ap_d.add_argument("--input", required=True)
	ap_d.add_argument("--output", required=True)
	ap_d.add_argument("--ad", default="")
	ap_d.set_defaults(func=cmd_decrypt)

	return ap


def main(argv: list[str] | None = None) -> int:
	parser = build_parser()
	args = parser.parse_args(argv)
	args.func(args)
	return 0


if __name__ == "__main__":
	sys.exit(main())


