from __future__ import annotations

import argparse
import os
import sys
import base64

from . import kyber as kyber_kem
from .kyber import KYBER512, KYBER768, KYBER1024
from . import sphincs_plus as sig_plus
from .symm import encrypt as symm_encrypt, decrypt as symm_decrypt
from .sha3 import sha3_256
from .keycodec import export_fixed_text, import_fixed_text
from .armor import encode_text_armor, encode_bytes_armor, decode_armor, decode_armor_full
from .pbe import encrypt_secret, decrypt_secret


PUB3_MAGIC = b"OE-PUB3\x00"
SEC3_MAGIC = b"OE-SEC3\x00"
MSG3_MAGIC = b"OE-MSG3\x00"

SIG3_MAGIC = b"OE-SIG3\x00"

SIG3_PARAMS_ID = 1  # currently only SPHINCS_SHAKE_256F_SIMPLE is supported for v3


def _kem_params_from_args(name: str) -> kyber_kem.KyberParams:
	if name == "Kyber512":
		return KYBER512
	if name == "Kyber768":
		return KYBER768
	if name == "Kyber1024":
		return KYBER1024
	raise ValueError("unknown KEM params")


def write_text(path: str, text: str) -> None:
	with open(path, "w", encoding="utf-8") as f:
		f.write(text)


def read_text(path: str) -> str:
	with open(path, "r", encoding="utf-8") as f:
		return f.read().strip()


def cmd_keygen(args: argparse.Namespace) -> None:
	# Generate a unified key pair: KEM and SIG bundled; output one public and one secret file
	kem_params = _kem_params_from_args(getattr(args, "kem", "Kyber512"))
	pk_kem, sk_kem = kyber_kem.keygen(params=kem_params)
	sig_params = sig_plus.SPHINCS_SHAKE_256F_SIMPLE
	pk_sig, sk_sig = sig_plus.keygen(params=sig_params)
	user_id = f"{args.name} <{args.email}>"
	pid = kyber_kem.params_to_id(pk_kem.params)
	# v3 payloads are self-describing: kem_pid + sig_pid
	sid = 1
	root_slot = pk_sig.root.ljust(32, b"\x00")
	pub_seed_slot = pk_sig.pub_seed.ljust(32, b"\x00")
	pub_payload = PUB3_MAGIC + bytes([pid, sid]) + pk_kem.raw + root_slot + pub_seed_slot
	sec_payload = SEC3_MAGIC + bytes([pid, sid]) + sk_kem.raw + sk_sig.raw + root_slot + pub_seed_slot
	pub_text = export_fixed_text(pub_payload)
	sec_text = export_fixed_text(sec_payload)
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
	print(f"wrote armored 4096-char keys ({kem_params.name})")


def parse_public(text: str) -> tuple[kyber_kem.PublicKey, sig_plus.PublicKey]:
	kind, body = decode_armor(text)
	if kind != "PUBLIC KEY":
		raise ValueError("not a public key")
	b = import_fixed_text(body)
	# v3: Kyber + SPHINCS+ (root||pub_seed)
	if b.startswith(PUB3_MAGIC) and len(b) >= len(PUB3_MAGIC) + 2:
		pid = b[len(PUB3_MAGIC)]
		sid = b[len(PUB3_MAGIC) + 1]
		if sid != 1:
			raise ValueError("unsupported signature params id (expected 1)")
		kem_params = kyber_kem.params_from_id(pid)
		pk_bytes, _sk_bytes, _ct_bytes, _ss_bytes = kyber_kem.kem_sizes(kem_params)
		off = len(PUB3_MAGIC) + 2
		pkkem = kyber_kem.PublicKey(params=kem_params, raw=b[off:off + pk_bytes])
		off += pk_bytes
		root = b[off:off + 32]
		pub_seed = b[off + 32:off + 64]
		sig_params = sig_plus.SPHINCS_SHAKE_256F_SIMPLE
		spk = sig_plus.PublicKey(params=sig_params, root=root[:sig_params.n], pub_seed=pub_seed[:sig_params.n])
		return pkkem, spk
	raise ValueError("unsupported public key format (expected v3)")


def parse_private(text: str) -> tuple[kyber_kem.SecretKey, sig_plus.SecretKey]:
	kind, body = decode_armor(text)
	if kind != "PRIVATE KEY":
		raise ValueError("not a private key")
	b = import_fixed_text(body)
	# v3: Kyber + SPHINCS+
	if b.startswith(SEC3_MAGIC) and len(b) >= len(SEC3_MAGIC) + 2:
		pid = b[len(SEC3_MAGIC)]
		sid = b[len(SEC3_MAGIC) + 1]
		if sid != 1:
			raise ValueError("unsupported signature params id (expected 1)")
		kem_params = kyber_kem.params_from_id(pid)
		_pk_bytes, sk_bytes, _ct_bytes, _ss_bytes = kyber_kem.kem_sizes(kem_params)
		off = len(SEC3_MAGIC) + 2
		skkem = kyber_kem.SecretKey(params=kem_params, raw=b[off:off + sk_bytes])
		off += sk_bytes
		sig_params = sig_plus.SPHINCS_SHAKE_256F_SIMPLE
		sk_len = 4 * sig_params.n
		sk_raw = b[off:off + sk_len]
		off += sk_len
		root_slot = b[off:off + 32]
		pub_seed_slot = b[off + 32:off + 64]
		root = root_slot[:sig_params.n]
		pub_seed = pub_seed_slot[:sig_params.n]
		# reconstruct secret key dataclass
		sk_seed = sk_raw[:sig_params.n]
		sk_prf = sk_raw[sig_params.n:2 * sig_params.n]
		pub_seed2 = sk_raw[2 * sig_params.n:3 * sig_params.n]
		root2 = sk_raw[3 * sig_params.n:4 * sig_params.n]
		sksig = sig_plus.SecretKey(params=sig_params, sk_seed=sk_seed, sk_prf=sk_prf, pub_seed=pub_seed2, root=root2)
		if pub_seed2 != pub_seed or root2 != root:
			raise ValueError("signature key mismatch in secret key payload")
		return skkem, sksig
	raise ValueError("unsupported private key format (expected v3)")


def load_public_file(path: str) -> tuple[kyber_kem.PublicKey, sig_plus.PublicKey, str]:
	text = read_text(path)
	_kind, headers, _body = decode_armor_full(text)
	uid = headers.get("User-ID", "")
	pk_kem, pk_sig = parse_public(text)
	return pk_kem, pk_sig, uid


def load_private_file(path: str, passphrase_env: str | None = None) -> tuple[kyber_kem.SecretKey, sig_plus.SecretKey, str]:
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
	# Re-wrap into an armored PRIVATE KEY block for reuse of parse_private()
	# (parse_private expects armor text input; we already have the decoded payload)
	if b.startswith(SEC3_MAGIC):
		pid = b[len(SEC3_MAGIC)]
		sid = b[len(SEC3_MAGIC) + 1]
		if sid != 1:
			raise ValueError("unsupported signature params id (expected 1)")
		params = kyber_kem.params_from_id(pid)
		_pk_bytes, sk_bytes, _ct_bytes, _ss_bytes = kyber_kem.kem_sizes(params)
		off = len(SEC3_MAGIC) + 2
		sk_kem = kyber_kem.SecretKey(params=params, raw=b[off:off + sk_bytes])
		off += sk_bytes
		sig_params = sig_plus.SPHINCS_SHAKE_256F_SIMPLE
		sk_len = 4 * sig_params.n
		sk_raw = b[off:off + sk_len]
		off += sk_len
		root_slot = b[off:off + 32]
		pub_seed_slot = b[off + 32:off + 64]
		root = root_slot[:sig_params.n]
		pub_seed = pub_seed_slot[:sig_params.n]
		sk_seed = sk_raw[:sig_params.n]
		sk_prf = sk_raw[sig_params.n:2 * sig_params.n]
		pub_seed2 = sk_raw[2 * sig_params.n:3 * sig_params.n]
		root2 = sk_raw[3 * sig_params.n:4 * sig_params.n]
		sksig = sig_plus.SecretKey(params=sig_params, sk_seed=sk_seed, sk_prf=sk_prf, pub_seed=pub_seed2, root=root2)
		if pub_seed2 != pub_seed or root2 != root:
			raise ValueError("signature key mismatch in secret key payload")
		return sk_kem, sksig, uid
	raise ValueError("unsupported private key format (expected v3)")


def cmd_encrypt(args: argparse.Namespace) -> None:
	# Inputs
	pt = open(args.input, "rb").read()
	pk_kem, pk_sig, pub_uid = load_public_file(args.public)
	sk_kem, sk_sig, sec_uid = load_private_file(args.secret, getattr(args, "secret_passphrase_env", None))

	# Sign the plaintext
	context = ("From:" + pub_uid + "|To:" + sec_uid + "|").encode("utf-8")
	signature = sig_plus.sign(sk_sig, context + pt)
	# Fixed-size framing: signature size is deterministic for the parameter set.
	expected_sig_len = sig_plus.signature_size(sig_plus.SPHINCS_SHAKE_256F_SIMPLE)
	if len(signature) != expected_sig_len:
		raise ValueError("signature length mismatch")
	sig_blob = SIG3_MAGIC + signature
	message = sig_blob + pt

	# KEM to recipient's public key
	c_kem, ss = kyber_kem.encapsulate(pk_kem)
	pid = kyber_kem.params_to_id(pk_kem.params)
	c_blob = MSG3_MAGIC + bytes([pid]) + c_kem
	nonce = sha3_256(os.urandom(32))[:16]
	aad = b"openencrypt|" + sec_uid.encode("utf-8") + b"|" + pub_uid.encode("utf-8")
	ciphertext, tag = symm_encrypt(ss, nonce, message, ad=aad)
	armored = encode_bytes_armor("MESSAGE", c_blob + nonce + tag + ciphertext, headers={"From": sec_uid, "To": pub_uid})
	with open(args.output, "w", encoding="utf-8") as f:
		f.write(armored)
	print(f"wrote ciphertext to {args.output}")


def cmd_decrypt(args: argparse.Namespace) -> None:
	armored = read_text(args.input)
	# Parse message best-effort; on any failure we still run the same expensive work and return a generic error.
	blob = b""
	try:
		kind, body = decode_armor(armored)
		if kind == "MESSAGE":
			blob = base64.b64decode(body)
	except Exception:
		blob = b""
	sk_kem, sk_sig, sec_uid = load_private_file(args.secret, getattr(args, "secret_passphrase_env", None))
	pk_kem, pk_sig, pub_uid = load_public_file(args.public)

	ok = True

	# --- KEM decapsulation (always run) ---
	# If message is malformed, we still run decapsulation on a dummy ciphertext of the right size to equalize work.
	pid = kyber_kem.params_to_id(sk_kem.params)
	params = kyber_kem.params_from_id(pid)
	_pk_bytes, _sk_bytes, ct_bytes, _ss_bytes = kyber_kem.kem_sizes(params)
	off = len(MSG3_MAGIC) + 1
	c_kem = bytes(ct_bytes)
	if blob.startswith(MSG3_MAGIC) and len(blob) >= off + ct_bytes:
		pid_msg = blob[len(MSG3_MAGIC)]
		if pid_msg != pid:
			ok = False
		c_kem = blob[off:off + ct_bytes]
		off = off + ct_bytes
	else:
		ok = False
	ss = kyber_kem.decapsulate(sk_kem, c_kem)

	# --- Symmetric decrypt+auth (always run) ---
	nonce = b"\x00" * 16
	tag = b"\x00" * 32
	cipher = b""
	if len(blob) >= off + 16 + 32:
		nonce = blob[off:off + 16]
		tag = blob[off + 16:off + 48]
		cipher = blob[off + 48:]
	else:
		ok = False
	aad = b"openencrypt|" + sec_uid.encode("utf-8") + b"|" + pub_uid.encode("utf-8")
	msg = symm_decrypt(ss, nonce, cipher, tag, ad=aad)
	if msg is None:
		ok = False
		msg = b""  # continue with dummy parsing below

	# --- Signature verify (always run once) ---
	context = ("From:" + pub_uid + "|To:" + sec_uid + "|").encode("utf-8")
	expected_sig_len = sig_plus.signature_size(sig_plus.SPHINCS_SHAKE_256F_SIMPLE)
	signature = b"\x00" * expected_sig_len
	pt_out = b""
	if msg.startswith(SIG3_MAGIC) and len(msg) >= len(SIG3_MAGIC) + expected_sig_len:
		signature = msg[len(SIG3_MAGIC):len(SIG3_MAGIC) + expected_sig_len]
		pt_out = msg[len(SIG3_MAGIC) + expected_sig_len:]
	else:
		ok = False
		# dummy plaintext used only to keep verify cost similar
		pt_out = b""
	sig_ok = sig_plus.verify(pk_sig, context + pt_out, signature)
	if not sig_ok:
		ok = False

	if not ok:
		print("decryption failed", file=sys.stderr)
		sys.exit(2)

	open(args.output, "wb").write(pt_out)
	print(f"wrote plaintext to {args.output}")


def build_parser() -> argparse.ArgumentParser:
	ap = argparse.ArgumentParser(description="OpenEncrypt standalone (pure Python; experimental)")
	sub = ap.add_subparsers(dest="cmd", required=True)

	ap_k = sub.add_parser("keygen", help="generate one armored 4096-char keypair")
	ap_k.add_argument("--public", default="pub.asc")
	ap_k.add_argument("--secret", default="sec.asc")
	ap_k.add_argument("--name", required=True)
	ap_k.add_argument("--email", required=True)
	ap_k.add_argument("--kem", default="Kyber512", choices=["Kyber512", "Kyber768", "Kyber1024"])
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


