from __future__ import annotations

import argparse
import os
import sys
import base64

from .kyberlite import keygen as kem_keygen, encapsulate, decapsulate, PublicKey, SecretKey, N, K
from .sphincs_edu import keygen as sig_keygen, sign, verify, SPublicKey, SSecretKey
from .symm import encrypt as symm_encrypt, decrypt as symm_decrypt
from .sha3 import sha3_256
from .keycodec import export_fixed_text, import_fixed_text
from .armor import encode_text_armor, encode_bytes_armor, decode_armor, decode_armor_full
from .pbe import encrypt_secret, decrypt_secret


def write_text(path: str, text: str) -> None:
	with open(path, "w", encoding="utf-8") as f:
		f.write(text)


def read_text(path: str) -> str:
	with open(path, "r", encoding="utf-8") as f:
		return f.read().strip()


def cmd_keygen(args: argparse.Namespace) -> None:
	# Generate a unified key pair: KEM and SIG bundled; output one public and one secret file
	pk_kem, sk_kem = kem_keygen()
	pk_sig, sk_sig = sig_keygen()
	user_id = f"{args.name} <{args.email}>"
	pub_text = export_fixed_text(pk_kem.raw + pk_sig.root + pk_sig.seed)
	sec_text = export_fixed_text(sk_kem.raw + sk_sig.seed + pk_sig.root + pk_sig.seed)
	pub_headers = {"User-ID": user_id}
	sec_headers = {"User-ID": user_id}
	if getattr(args, "secret_passphrase_env", None):
		pw = os.environ.get(args.secret_passphrase_env, "")
		if not pw:
			print("missing passphrase in env", file=sys.stderr)
			sys.exit(2)
		extra_headers, sealed = encrypt_secret(sec_text.encode("utf-8"), pw)
		sec_headers.update(extra_headers)
		with open(args.secret, "w", encoding="utf-8") as f:
			f.write(encode_bytes_armor("PRIVATE KEY", sealed, headers=sec_headers))
	else:
		write_text(args.secret, encode_text_armor("PRIVATE KEY", sec_text, headers=sec_headers))
	write_text(args.public, encode_text_armor("PUBLIC KEY", pub_text, headers=pub_headers))
	print("wrote armored 4096-char keys")


def parse_public(text: str) -> tuple[PublicKey, SPublicKey]:
	kind, body = decode_armor(text)
	if kind != "PUBLIC KEY":
		raise ValueError("not a public key")
	b = import_fixed_text(body)
	pkkem = PublicKey(b[: K * 2 * N + 32])
	spk = SPublicKey(root=b[K * 2 * N + 32:K * 2 * N + 64], seed=b[K * 2 * N + 64:K * 2 * N + 96])
	return pkkem, spk


def parse_private(text: str) -> tuple[SecretKey, SSecretKey]:
	kind, body = decode_armor(text)
	if kind != "PRIVATE KEY":
		raise ValueError("not a private key")
	b = import_fixed_text(body)
	skkem = SecretKey(b[: K * 2 * N + 64])
	seed = b[K * 2 * N + 64:K * 2 * N + 96]
	spk = SPublicKey(root=b[K * 2 * N + 96:K * 2 * N + 128], seed=b[K * 2 * N + 128:K * 2 * N + 160])
	return skkem, SSecretKey(seed=seed, pub=spk)


def load_public_file(path: str) -> tuple[PublicKey, SPublicKey, str]:
	text = read_text(path)
	_kind, headers, _body = decode_armor_full(text)
	uid = headers.get("User-ID", "")
	pk_kem, pk_sig = parse_public(text)
	return pk_kem, pk_sig, uid


def load_private_file(path: str, passphrase_env: str | None = None) -> tuple[SecretKey, SSecretKey, str]:
	text = read_text(path)
	_kind, headers, body = decode_armor_full(text)
	uid = headers.get("User-ID", "")
	if headers.get("KDF"):
		if not passphrase_env:
			raise ValueError("secret key is encrypted; provide --secret-passphrase-env")
		pw = os.environ.get(passphrase_env, "")
		if not pw:
			raise ValueError("missing passphrase in env")
		sealed = base64.b64decode(body)
		sec_text = decrypt_secret(sealed, pw, headers).decode("utf-8")
		b = import_fixed_text(sec_text)
	else:
		b = import_fixed_text(body)
	sk_kem = SecretKey(b[: K * 2 * N + 64])
	seed = b[K * 2 * N + 64:K * 2 * N + 96]
	spk = SPublicKey(root=b[K * 2 * N + 96:K * 2 * N + 128], seed=b[K * 2 * N + 128:K * 2 * N + 160])
	return sk_kem, SSecretKey(seed=seed, pub=spk), uid


def cmd_encrypt(args: argparse.Namespace) -> None:
	# Inputs
	pt = open(args.input, "rb").read()
	pk_kem, pk_sig, pub_uid = load_public_file(args.public)
	sk_kem, sk_sig, sec_uid = load_private_file(args.secret, getattr(args, "secret_passphrase_env", None))

	# Sign the plaintext
	context = ("From:" + pub_uid + "|To:" + sec_uid + "|").encode("utf-8")
	signature = sign(sk_sig, context + pt)
	message = signature + pt

	# KEM to recipient's public key
	c_kem, ss = encapsulate(pk_kem)
	nonce = sha3_256(os.urandom(32))[:16]
	aad = b"openencrypt|" + sec_uid.encode("utf-8") + b"|" + pub_uid.encode("utf-8")
	ciphertext, tag = symm_encrypt(ss, nonce, message, ad=aad)
	armored = encode_bytes_armor("MESSAGE", c_kem + nonce + tag + ciphertext, headers={"From": sec_uid, "To": pub_uid})
	with open(args.output, "w", encoding="utf-8") as f:
		f.write(armored)
	print(f"wrote ciphertext to {args.output}")


def cmd_decrypt(args: argparse.Namespace) -> None:
	armored = read_text(args.input)
	kind, body = decode_armor(armored)
	if kind != "MESSAGE":
		print("not an OpenEncrypt MESSAGE", file=sys.stderr)
		sys.exit(2)
	blob = base64.b64decode(body)
	sk_kem, sk_sig, sec_uid = load_private_file(args.secret, getattr(args, "secret_passphrase_env", None))
	pk_kem, pk_sig, pub_uid = load_public_file(args.public)

	c_len = (K + 1) * 2 * N  # serialize_vec(u)=K*2*N, serialize_poly(v')=2*N
	off = c_len
	c_kem = blob[:off]
	nonce = blob[off:off + 16]
	tag = blob[off + 16:off + 48]
	cipher = blob[off + 48:]
	ss = decapsulate(sk_kem, c_kem)
	aad = b"openencrypt|" + sec_uid.encode("utf-8") + b"|" + pub_uid.encode("utf-8")
	msg = symm_decrypt(ss, nonce, cipher, tag, ad=aad)
	if msg is None or len(msg) < 32 * 16:
		print("decryption/auth failed", file=sys.stderr)
		sys.exit(2)
	signature = msg[:32 * 16]
	pt = msg[32 * 16:]
	context = ("From:" + pub_uid + "|To:" + sec_uid + "|").encode("utf-8")
	if not verify(pk_sig, context + pt, signature):
		print("signature verify failed", file=sys.stderr)
		sys.exit(3)
	open(args.output, "wb").write(pt)
	print(f"wrote plaintext to {args.output}")


def build_parser() -> argparse.ArgumentParser:
	ap = argparse.ArgumentParser(description="OpenEncrypt standalone (educational)")
	sub = ap.add_subparsers(dest="cmd", required=True)

	ap_k = sub.add_parser("keygen", help="generate one armored 4096-char keypair")
	ap_k.add_argument("--public", default="pub.asc")
	ap_k.add_argument("--secret", default="sec.asc")
	ap_k.add_argument("--name", required=True)
	ap_k.add_argument("--email", required=True)
	ap_k.add_argument("--secret-passphrase-env")
	ap_k.set_defaults(func=cmd_keygen)

	ap_e = sub.add_parser("encrypt", help="sign (private) then encrypt (public)")
	ap_e.add_argument("--input", required=True)
	ap_e.add_argument("--output", required=True)
	ap_e.add_argument("--public", default="pub.asc")
	ap_e.add_argument("--secret", default="sec.asc")
	ap_e.add_argument("--secret-passphrase-env")
	ap_e.set_defaults(func=cmd_encrypt)

	ap_d = sub.add_parser("decrypt", help="decrypt (private) then verify (public)")
	ap_d.add_argument("--input", required=True)
	ap_d.add_argument("--output", required=True)
	ap_d.add_argument("--secret", default="sec.asc")
	ap_d.add_argument("--public", default="pub.asc")
	ap_d.add_argument("--secret-passphrase-env")
	ap_d.set_defaults(func=cmd_decrypt)

	return ap


def main(argv: list[str] | None = None) -> int:
	parser = build_parser()
	args = parser.parse_args(argv)
	args.func(args)
	return 0


if __name__ == "__main__":
	sys.exit(main())


