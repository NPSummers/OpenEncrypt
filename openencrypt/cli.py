from __future__ import annotations

import argparse
import os
import sys

from .kyber import (
	KYBER512,
	KYBER768,
	KYBER1024,
	PublicKey,
	SecretKey,
	decapsulate,
	encapsulate,
	keygen,
	params_from_id,
	params_to_id,
)
from .sha3 import sha3_256
from .symm import encrypt as symm_encrypt, decrypt as symm_decrypt


MAGIC = b"KYB3"


def _params_from_args(name: str):
	if name == "Kyber512":
		return KYBER512
	if name == "Kyber768":
		return KYBER768
	if name == "Kyber1024":
		return KYBER1024
	raise ValueError("unknown params (use Kyber512/Kyber768/Kyber1024)")


def _wrap_blob(params_id: int, payload: bytes) -> bytes:
	return MAGIC + bytes([params_id]) + payload


def _unwrap_blob(blob: bytes) -> tuple[int, bytes]:
	if len(blob) < 5 or blob[:4] != MAGIC:
		raise ValueError("invalid Kyber blob (missing magic)")
	return blob[4], blob[5:]


def cmd_keygen(args: argparse.Namespace) -> None:
	params = _params_from_args(args.params)
	pk, sk = keygen(params=params)
	with open(args.public, "wb") as f:
		f.write(_wrap_blob(params_to_id(pk.params), pk.raw))
	with open(args.secret, "wb") as f:
		f.write(_wrap_blob(params_to_id(sk.params), sk.raw))
	print(f"wrote public key to {args.public}, secret key to {args.secret}")


def cmd_encaps(args: argparse.Namespace) -> None:
	with open(args.public, "rb") as f:
		pk_blob = f.read()
	pid, pk_bytes = _unwrap_blob(pk_blob)
	params = params_from_id(pid)
	pk = PublicKey(params=params, raw=pk_bytes)
	c, ss = encapsulate(pk)
	with open(args.cipherkey, "wb") as f:
		f.write(_wrap_blob(pid, c))
	with open(args.shared, "wb") as f:
		f.write(ss)
	print(f"wrote KEM ciphertext to {args.cipherkey}, shared secret to {args.shared}")


def cmd_decaps(args: argparse.Namespace) -> None:
	with open(args.secret, "rb") as f:
		sk_blob = f.read()
	pid_sk, sk_bytes = _unwrap_blob(sk_blob)
	params = params_from_id(pid_sk)
	sk = SecretKey(params=params, raw=sk_bytes)
	with open(args.cipherkey, "rb") as f:
		c_blob = f.read()
	pid_c, c = _unwrap_blob(c_blob)
	if pid_c != pid_sk:
		raise ValueError("ciphertext params do not match secret key params")
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
	ap = argparse.ArgumentParser(prog="openencrypt", description="Offline crypto (pure Python; experimental)")
	sub = ap.add_subparsers(dest="cmd", required=True)

	ap_k = sub.add_parser("keygen", help="generate keypair")
	ap_k.add_argument("--public", default="pk.bin")
	ap_k.add_argument("--secret", default="sk.bin")
	ap_k.add_argument("--params", default="Kyber512", choices=["Kyber512", "Kyber768", "Kyber1024"])
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


