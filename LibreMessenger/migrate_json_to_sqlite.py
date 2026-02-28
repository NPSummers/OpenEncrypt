from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from LibreMessenger.app import _bootstrap_storage, _open_db


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_users_json(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _load_messages_json(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, list):
        raise ValueError(f"{path} must contain a JSON array")
    return payload


def migrate(data_dir: Path, dry_run: bool = False) -> None:
    users_path = data_dir / "users.json"
    messages_path = data_dir / "messages.json"

    users_json = _load_users_json(users_path)
    messages_json = _load_messages_json(messages_path)

    _bootstrap_storage(data_dir)

    inserted_users = 0
    existing_users = 0
    inserted_messages = 0
    skipped_messages = 0
    duplicate_messages = 0

    with _open_db(data_dir) as conn:
        # Build username -> id map from db after insert/lookups.
        user_id_by_name: dict[str, int] = {}

        for username, user in users_json.items():
            if not isinstance(user, dict):
                continue
            password_hash = str(user.get("password_hash", ""))
            public_key_path = str(
                user.get("public_key_path")
                or user.get("public_key")
                or (data_dir / "keys" / username / "public.asc")
            )
            private_key_path = str(
                user.get("private_key_path")
                or user.get("private_key")
                or (data_dir / "keys" / username / "private.asc")
            )
            created_at = str(user.get("created_at") or _iso_now())

            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if existing is None:
                inserted_users += 1
                conn.execute(
                    """
                    INSERT INTO users (username, password_hash, public_key_path, private_key_path, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (username, password_hash, public_key_path, private_key_path, created_at),
                )
            else:
                existing_users += 1

            db_row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if db_row is not None:
                user_id_by_name[username] = int(db_row["id"])

        for msg in messages_json:
            if not isinstance(msg, dict):
                skipped_messages += 1
                continue

            sender = str(msg.get("sender", ""))
            recipient = str(msg.get("recipient", ""))
            recipient_payload = str(msg.get("recipient_payload", ""))
            sender_copy_payload = str(msg.get("sender_copy_payload", ""))
            created_at = str(msg.get("created_at") or _iso_now())

            sender_id = user_id_by_name.get(sender)
            recipient_id = user_id_by_name.get(recipient)
            if sender_id is None or recipient_id is None:
                skipped_messages += 1
                continue
            if not recipient_payload or not sender_copy_payload:
                skipped_messages += 1
                continue

            duplicate = conn.execute(
                """
                SELECT id
                FROM messages
                WHERE sender_id = ?
                  AND recipient_id = ?
                  AND created_at = ?
                  AND recipient_payload = ?
                  AND sender_copy_payload = ?
                LIMIT 1
                """,
                (sender_id, recipient_id, created_at, recipient_payload, sender_copy_payload),
            ).fetchone()
            if duplicate is not None:
                duplicate_messages += 1
                continue

            inserted_messages += 1
            conn.execute(
                """
                INSERT INTO messages (sender_id, recipient_id, created_at, recipient_payload, sender_copy_payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                (sender_id, recipient_id, created_at, recipient_payload, sender_copy_payload),
            )

        if not dry_run:
            conn.commit()
        else:
            conn.rollback()

    print("Migration summary")
    print(f"- Data directory: {data_dir}")
    print(f"- Users inserted: {inserted_users}")
    print(f"- Users already present: {existing_users}")
    print(f"- Messages inserted: {inserted_messages}")
    print(f"- Messages skipped (invalid/missing users): {skipped_messages}")
    print(f"- Messages skipped (duplicates): {duplicate_messages}")
    print(f"- Mode: {'dry-run (no changes saved)' if dry_run else 'committed'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Migrate LibreMessenger users/messages JSON data into SQLite."
    )
    parser.add_argument(
        "--data-dir",
        default=str(Path(__file__).parent / "data"),
        help="Path to LibreMessenger data directory (default: LibreMessenger/data)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and report migration without writing to DB",
    )
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    migrate(data_dir=data_dir, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

