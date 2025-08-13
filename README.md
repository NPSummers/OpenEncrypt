## OpenEncrypt (Educational)

This is an educational, from-scratch Python prototype inspired by CRYSTALS-Kyber and SPHINCS+. It is not constant-time and has not been audited. Do not use for real security.

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

- Parameters are reduced for clarity and performance in Python.
- Pure Python, offline; uses the standard library SHA3/SHAKE.
- For learning only; not side-channel hardened.
