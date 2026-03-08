## OpenEncrypt (Pure Python, experimental)

This is a from-scratch Python prototype that bundles:
- **CRYSTALS-Kyber Round3 KEM (v3.01)** (spec-aligned, pure stdlib Python)
- A **SPHINCS+ structured signature** (FORS + WOTS+ hypertree, SHAKE256-based) in `openencrypt/sphincs_plus.py`

It is **not constant-time**, not audited, and Python is not a good vehicle for production post-quantum cryptography implementations. Treat this as an offline prototype and learning tool.

Kyber spec reference: [`kyber-specification-round3-20210131.pdf`](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210131.pdf) and [`eprint.iacr.org/2017/634.pdf`]([https://pq-crystals.org/kyber/data/kyber-specification-round3-20210131.pdf](https://eprint.iacr.org/2017/634.pdf))
SPHINCS+ design reference: [`sphincs+-paper.pdf`](https://sphincs.org/data/sphincs+-paper.pdf)

### How it works (high level)

- One unified keypair (public + private): contains a Kyber-like KEM and a SPHINCS+-style signature key.
- Keys and messages are ASCII-armored (PGP-style) with headers.
- Sign-then-encrypt: private key signs; public key is used for KEM encryption; decrypt verifies the signature.
- Optional passphrase protection for the private key (scrypt + SHAKE-based AEAD-like seal).

### Running without installing

Use the module entrypoint directly; no package install required.

### Generate a keypair (with identity)

PowerShell:

```bash
python -m openencrypt.openencrypt keygen --public pub.asc --secret sec.asc --name "Alice" --email "alice@example.com"
```

With passphrase-protected secret key (PowerShell):

```bash
$Env:OPENENC_PW = "strong passphrase"
python -m openencrypt.openencrypt keygen --public pub.asc --secret sec.asc --name "Alice" --email "alice@example.com" --secret-passphrase-env OPENENC_PW
```

cmd.exe (set env var for one command):

```bat
cmd /c "set OPENENC_PW=strong passphrase && python -m openencrypt.openencrypt keygen --public pub.asc --secret sec.asc --name \"Alice\" --email \"alice@example.com\" --secret-passphrase-env OPENENC_PW"
```

### Encrypt (sign with private, encrypt to public)

```bash
python -m openencrypt.openencrypt encrypt --input msg.txt --output msg.asc --public pub.asc --secret sec.asc
```

If your secret key is passphrase-protected add:

```bash
--secret-passphrase-env OPENENC_PW
```

### Decrypt (decrypt with private, verify with public)

```bash
python -m openencrypt.openencrypt decrypt --input msg.asc --output out.txt --secret sec.asc --public pub.asc
```

### Failure behavior

Decryption failures are deliberately **uniform** (always `decryption failed`) to reduce remote timing/oracle signal.

### Selecting Kyber parameter sets

Default is **Kyber512**. You can choose:

```bash
python -m openencrypt.openencrypt keygen --kem Kyber768 --public pub.asc --secret sec.asc --name "Alice" --email "alice@example.com"
```

If your secret key is passphrase-protected add the same flag:

```bash
--secret-passphrase-env OPENENC_PW
```

### Armor format

- Keys: `-----BEGIN OPENENCRYPT PUBLIC KEY-----` / `-----BEGIN OPENENCRYPT PRIVATE KEY-----`
  - Headers include `Version:`, `User-ID: Name <email>` and for encrypted secret keys also `KDF`, `N`, `r`, `p`, `Salt`.
- Messages: `-----BEGIN OPENENCRYPT MESSAGE-----` with headers `From:` and `To:`.
- Headers are bound into signature and AEAD associated data.

### Notes

- Kyber KEM implementation is in `openencrypt/kyber.py` and follows the Round3 v3.01 structure (CPA PKE + FO transform).
- Pure Python, offline; uses standard library `hashlib` SHA3/SHAKE.
- Not side-channel hardened; “constant-time” in Python is best-effort only.
