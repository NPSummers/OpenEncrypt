from __future__ import annotations

import argparse
import base64
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from openencrypt import kyber, openencrypt as oe, sphincs_plus, symm

MESSAGE_MAGIC = b"LIBREMSG1\x00"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,32}$")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db_path(data_dir: Path) -> Path:
    return data_dir / "libremessenger.db"


def _open_db(data_dir: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(data_dir))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _bootstrap_storage(data_dir: Path) -> None:
    (data_dir / "keys").mkdir(parents=True, exist_ok=True)
    with _open_db(data_dir) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                public_key_path TEXT NOT NULL,
                private_key_path TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                recipient_payload TEXT NOT NULL,
                sender_copy_payload TEXT NOT NULL,
                FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(recipient_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_messages_sender_created
            ON messages(sender_id, created_at);

            CREATE INDEX IF NOT EXISTS idx_messages_recipient_created
            ON messages(recipient_id, created_at);
            """
        )


def _user_key_dir(data_dir: Path, username: str) -> Path:
    return data_dir / "keys" / username


def _user_public_key_path(data_dir: Path, username: str) -> Path:
    return _user_key_dir(data_dir, username) / "public.asc"


def _user_private_key_path(data_dir: Path, username: str) -> Path:
    return _user_key_dir(data_dir, username) / "private.asc"


def _get_user_by_username(data_dir: Path, username: str) -> Optional[sqlite3.Row]:
    with _open_db(data_dir) as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return row


def _list_usernames(data_dir: Path) -> list[str]:
    with _open_db(data_dir) as conn:
        rows = conn.execute("SELECT username FROM users ORDER BY username ASC").fetchall()
    return [row["username"] for row in rows]


def _insert_message(
    data_dir: Path,
    sender_id: int,
    recipient_id: int,
    recipient_payload: str,
    sender_copy_payload: str,
) -> None:
    with _open_db(data_dir) as conn:
        conn.execute(
            """
            INSERT INTO messages (sender_id, recipient_id, created_at, recipient_payload, sender_copy_payload)
            VALUES (?, ?, ?, ?, ?)
            """,
            (sender_id, recipient_id, _iso_now(), recipient_payload, sender_copy_payload),
        )
        conn.commit()


def _encode_message_for_recipient(
    plaintext: str,
    sender_name: str,
    recipient_name: str,
    sender_sig_private: sphincs_plus.SecretKey,
    recipient_kem_public: kyber.PublicKey,
) -> str:
    pt = plaintext.encode("utf-8")
    context = f"From:{sender_name}|To:{recipient_name}|".encode("utf-8")
    signature = sphincs_plus.sign(sender_sig_private, context + pt)
    signed_plaintext = signature + pt

    c_kem, shared_secret = kyber.encapsulate(recipient_kem_public)
    pid = kyber.params_to_id(recipient_kem_public.params)
    nonce = os.urandom(16)
    ad = b"libremessenger|" + sender_name.encode("utf-8") + b"|" + recipient_name.encode("utf-8")
    ciphertext, tag = symm.encrypt(shared_secret, nonce, signed_plaintext, ad=ad)

    blob = MESSAGE_MAGIC + bytes([pid]) + c_kem + nonce + tag + ciphertext
    return base64.b64encode(blob).decode("ascii")


def _decode_message_for_recipient(
    payload_b64: str,
    sender_name: str,
    recipient_name: str,
    recipient_kem_private: kyber.SecretKey,
    sender_sig_public: sphincs_plus.PublicKey,
) -> str:
    blob = base64.b64decode(payload_b64)
    if not blob.startswith(MESSAGE_MAGIC):
        raise ValueError("invalid message header")

    off = len(MESSAGE_MAGIC)
    pid = blob[off]
    off += 1
    expected_pid = kyber.params_to_id(recipient_kem_private.params)
    if pid != expected_pid:
        raise ValueError("message KEM params do not match recipient key")

    params = kyber.params_from_id(pid)
    _pk_bytes, _sk_bytes, ct_bytes, _ss_bytes = kyber.kem_sizes(params)
    if len(blob) < off + ct_bytes + 16 + 32:
        raise ValueError("message payload is truncated")

    c_kem = blob[off : off + ct_bytes]
    off += ct_bytes
    nonce = blob[off : off + 16]
    off += 16
    tag = blob[off : off + 32]
    off += 32
    ciphertext = blob[off:]

    shared_secret = kyber.decapsulate(recipient_kem_private, c_kem)
    ad = b"libremessenger|" + sender_name.encode("utf-8") + b"|" + recipient_name.encode("utf-8")
    signed_plaintext = symm.decrypt(shared_secret, nonce, ciphertext, tag, ad=ad)
    if signed_plaintext is None:
        raise ValueError("authentication failed")

    sig_len = sphincs_plus.signature_size(sphincs_plus.SPHINCS_SHAKE_256F_SIMPLE)
    if len(signed_plaintext) < sig_len:
        raise ValueError("signed plaintext is too short")

    signature = signed_plaintext[:sig_len]
    plaintext = signed_plaintext[sig_len:]
    context = f"From:{sender_name}|To:{recipient_name}|".encode("utf-8")
    if not sphincs_plus.verify(sender_sig_public, context + plaintext, signature):
        raise ValueError("signature verification failed")
    return plaintext.decode("utf-8", errors="replace")


def _register_user(data_dir: Path, username: str, password: str) -> tuple[bool, str]:
    if _get_user_by_username(data_dir, username):
        return False, "That username is already taken."
    if not USERNAME_RE.fullmatch(username):
        return False, "Username must be 3-32 chars using letters, numbers, _ or -."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."

    key_dir = _user_key_dir(data_dir, username)
    key_dir.mkdir(parents=True, exist_ok=True)
    pub_path = _user_public_key_path(data_dir, username)
    sec_path = _user_private_key_path(data_dir, username)
    oe.cmd_keygen(
        argparse.Namespace(
            public=str(pub_path),
            secret=str(sec_path),
            name=username,
            email=f"{username}@libremessenger.local",
            kem="Kyber512",
            secret_passphrase_env=None,
        )
    )

    with _open_db(data_dir) as conn:
        conn.execute(
            """
            INSERT INTO users (username, password_hash, public_key_path, private_key_path, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, generate_password_hash(password), str(pub_path), str(sec_path), _iso_now()),
        )
        conn.commit()
    return True, "Account created. You can sign in now."


def _send_message(data_dir: Path, sender: str, recipient: str, plaintext: str) -> tuple[bool, str]:
    if not plaintext.strip():
        return False, "Message cannot be empty."

    sender_row = _get_user_by_username(data_dir, sender)
    recipient_row = _get_user_by_username(data_dir, recipient)
    if not sender_row:
        return False, "Sender account no longer exists."
    if not recipient_row:
        return False, f"Recipient '{recipient}' was not found."

    sender_public_path = sender_row["public_key_path"]
    sender_private_path = sender_row["private_key_path"]
    recipient_public_path = recipient_row["public_key_path"]

    sender_kem_public, _sender_sig_public, _sender_uid = oe.load_public_file(sender_public_path)
    _sender_kem_private, sender_sig_private, _sender_uid2 = oe.load_private_file(sender_private_path)
    recipient_kem_public, _recipient_sig_public, _recipient_uid = oe.load_public_file(
        recipient_public_path
    )

    recipient_payload = _encode_message_for_recipient(
        plaintext=plaintext,
        sender_name=sender,
        recipient_name=recipient,
        sender_sig_private=sender_sig_private,
        recipient_kem_public=recipient_kem_public,
    )
    sender_copy_payload = _encode_message_for_recipient(
        plaintext=plaintext,
        sender_name=sender,
        recipient_name=sender,
        sender_sig_private=sender_sig_private,
        recipient_kem_public=sender_kem_public,
    )

    _insert_message(
        data_dir=data_dir,
        sender_id=sender_row["id"],
        recipient_id=recipient_row["id"],
        recipient_payload=recipient_payload,
        sender_copy_payload=sender_copy_payload,
    )
    return True, "Message sent."


def _dm_partners(data_dir: Path, username: str) -> list[str]:
    me = _get_user_by_username(data_dir, username)
    if not me:
        return []

    with _open_db(data_dir) as conn:
        rows = conn.execute(
            """
            SELECT p.username AS partner, MAX(m.created_at) AS last_at
            FROM messages m
            JOIN users p
              ON p.id = CASE
                    WHEN m.sender_id = ? THEN m.recipient_id
                    ELSE m.sender_id
                END
            WHERE m.sender_id = ? OR m.recipient_id = ?
            GROUP BY p.username
            ORDER BY last_at DESC
            """,
            (me["id"], me["id"], me["id"]),
        ).fetchall()
    return [row["partner"] for row in rows]


def _load_user_keys(data_dir: Path, username: str) -> tuple[kyber.SecretKey, sphincs_plus.PublicKey]:
    row = _get_user_by_username(data_dir, username)
    if not row:
        raise ValueError(f"user '{username}' does not exist")
    kem_private, _sig_private, _uid_sec = oe.load_private_file(row["private_key_path"])
    _kem_public, sig_public, _uid_pub = oe.load_public_file(row["public_key_path"])
    return kem_private, sig_public


def _read_dm_messages(
    data_dir: Path, current_username: str, partner_username: str
) -> list[dict[str, str]]:
    me = _get_user_by_username(data_dir, current_username)
    partner = _get_user_by_username(data_dir, partner_username)
    if not me or not partner:
        return []

    my_kem_private, my_sig_public = _load_user_keys(data_dir, current_username)
    _partner_kem_private, partner_sig_public = _load_user_keys(data_dir, partner_username)

    with _open_db(data_dir) as conn:
        rows = conn.execute(
            """
            SELECT m.created_at, m.sender_id, m.recipient_id, m.recipient_payload, m.sender_copy_payload
            FROM messages m
            WHERE (m.sender_id = ? AND m.recipient_id = ?)
               OR (m.sender_id = ? AND m.recipient_id = ?)
            ORDER BY m.created_at ASC
            """,
            (me["id"], partner["id"], partner["id"], me["id"]),
        ).fetchall()

    rendered: list[dict[str, str]] = []
    for row in rows:
        is_outgoing = row["sender_id"] == me["id"]
        try:
            if is_outgoing:
                plaintext = _decode_message_for_recipient(
                    payload_b64=row["sender_copy_payload"],
                    sender_name=current_username,
                    recipient_name=current_username,
                    recipient_kem_private=my_kem_private,
                    sender_sig_public=my_sig_public,
                )
            else:
                plaintext = _decode_message_for_recipient(
                    payload_b64=row["recipient_payload"],
                    sender_name=partner_username,
                    recipient_name=current_username,
                    recipient_kem_private=my_kem_private,
                    sender_sig_public=partner_sig_public,
                )
        except Exception as exc:
            plaintext = f"[unable to decrypt: {exc}]"

        rendered.append(
            {
                "direction": "outgoing" if is_outgoing else "incoming",
                "created_at": row["created_at"],
                "plaintext": plaintext,
            }
        )
    return rendered


def _all_other_users(data_dir: Path, username: str) -> list[str]:
    return [u for u in _list_usernames(data_dir) if u != username]


def _messages_update_token(data_dir: Path, username: str, partner_username: str) -> str:
    me = _get_user_by_username(data_dir, username)
    if not me:
        return "missing-user"

    with _open_db(data_dir) as conn:
        global_state = conn.execute(
            """
            SELECT COUNT(*) AS cnt, MAX(created_at) AS last_at
            FROM messages
            WHERE sender_id = ? OR recipient_id = ?
            """,
            (me["id"], me["id"]),
        ).fetchone()

        dm_count = 0
        dm_last_at = ""
        if partner_username:
            partner = _get_user_by_username(data_dir, partner_username)
            if partner:
                dm_state = conn.execute(
                    """
                    SELECT COUNT(*) AS cnt, MAX(created_at) AS last_at
                    FROM messages
                    WHERE (sender_id = ? AND recipient_id = ?)
                       OR (sender_id = ? AND recipient_id = ?)
                    """,
                    (me["id"], partner["id"], partner["id"], me["id"]),
                ).fetchone()
                dm_count = int(dm_state["cnt"] or 0)
                dm_last_at = str(dm_state["last_at"] or "")

    global_count = int(global_state["cnt"] or 0)
    global_last_at = str(global_state["last_at"] or "")
    return f"{global_count}:{global_last_at}|{dm_count}:{dm_last_at}"


def create_app(data_dir: str | Path | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.config["SECRET_KEY"] = os.environ.get("LIBREMESSENGER_SECRET_KEY", secrets.token_hex(32))
    app.config["DATA_DIR"] = Path(data_dir) if data_dir else Path(__file__).parent / "data"
    app.config["DATA_DIR"].mkdir(parents=True, exist_ok=True)
    _bootstrap_storage(app.config["DATA_DIR"])

    @app.get("/")
    def index():
        if session.get("username"):
            return redirect(url_for("messages"))
        return redirect(url_for("login"))

    @app.get("/messages")
    def messages():
        username = session.get("username")
        if not username:
            return redirect(url_for("login"))

        all_users = _all_other_users(app.config["DATA_DIR"], username)
        dm_partners = _dm_partners(app.config["DATA_DIR"], username)

        selected_partner = request.args.get("dm", "").strip()
        if selected_partner and selected_partner not in all_users:
            selected_partner = ""
        if not selected_partner and dm_partners:
            selected_partner = dm_partners[0]

        conversation = (
            _read_dm_messages(app.config["DATA_DIR"], username, selected_partner)
            if selected_partner
            else []
        )
        update_token = _messages_update_token(app.config["DATA_DIR"], username, selected_partner)
        return render_template(
            "messages.html",
            username=username,
            dm_partners=dm_partners,
            all_users=all_users,
            selected_partner=selected_partner,
            conversation=conversation,
            update_token=update_token,
        )

    @app.get("/messages/updates")
    def messages_updates():
        username = session.get("username")
        if not username:
            return jsonify({"error": "not_authenticated"}), 401

        selected_partner = request.args.get("dm", "").strip()
        token = _messages_update_token(app.config["DATA_DIR"], username, selected_partner)
        return jsonify({"token": token})

    @app.post("/messages/send")
    def send_message():
        username = session.get("username")
        if not username:
            return redirect(url_for("login"))

        recipient = request.form.get("recipient", "").strip()
        plaintext = request.form.get("message", "")
        ok, message = _send_message(app.config["DATA_DIR"], username, recipient, plaintext)
        flash(message, "success" if ok else "error")
        if recipient:
            return redirect(url_for("messages", dm=recipient))
        return redirect(url_for("messages"))

    @app.get("/chat")
    def chat_alias():
        return redirect(url_for("messages"))

    @app.get("/signup")
    def signup_alias():
        return redirect(url_for("register"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            ok, message = _register_user(app.config["DATA_DIR"], username, password)
            if ok:
                flash(message, "success")
                return redirect(url_for("login"))
            flash(message, "error")
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = _get_user_by_username(app.config["DATA_DIR"], username)
            if not user or not check_password_hash(user["password_hash"], password):
                flash("Invalid username or password.", "error")
                return render_template("login.html")
            session["username"] = username
            flash(f"Welcome back, {username}.", "success")
            return redirect(url_for("messages"))
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    return app
