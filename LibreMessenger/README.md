# LibreMessenger

LibreMessenger is a small Flask messaging app built on top of the `openencrypt` library.

## What it does

- Lets users create accounts with a username and password.
- Generates a per-user OpenEncrypt keypair on signup.
- Encrypts each message using:
  - sender signing key (private) for signature
  - recipient KEM key (public) for encryption
- Lets recipients decrypt with:
  - recipient KEM key (private)
  - sender signature key (public) for verification
- Saves a second encrypted copy for the sender, encrypted to the sender's own public key so the sender can decrypt their own sent history.
- Stores accounts and messages in a SQLite database.
- Uses a Discord-style DM interface (DM list + active conversation pane).

## Run

From repo root:

```powershell
pip install -r LibreMessenger/requirements.txt
python LibreMessenger/run.py
```

Then open:

- <http://127.0.0.1:5050/register>

## Data storage

LibreMessenger stores app data under `LibreMessenger/data/`:

- `libremessenger.db`
- `keys/<username>/public.asc`
- `keys/<username>/private.asc`

## Notes

- This app intentionally does **not** modify `openencrypt` library code.
- `openencrypt` itself is marked experimental and not production-hardened.

