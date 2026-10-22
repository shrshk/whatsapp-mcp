"""Build a filtered copy of the message store that holds only authorized chats.

Run this as a trusted process next to the bridge. Point the MCP server at the
output with ``WHATSAPP_MCP_DB`` so it never has access to the full store:

    python projector.py --source ../whatsapp-bridge/store/messages.db \\
        --dest ~/.local/share/whatsapp-mcp/projection.db --watch 30

Each pass reloads the policy (failing closed), copies chats that hold any
permission, copies messages only for chats with read permission, and deletes
everything else. ``secure_delete`` overwrites removed rows on disk.
"""

import argparse
import logging
import sqlite3
import sys
import time
from pathlib import Path
from typing import Dict

from access_policy import READ, Policy, load_policy

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS chats (
    jid TEXT PRIMARY KEY,
    name TEXT,
    last_message_time TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
    id TEXT,
    chat_jid TEXT,
    sender TEXT,
    content TEXT,
    timestamp TIMESTAMP,
    is_from_me BOOLEAN,
    media_type TEXT,
    filename TEXT,
    PRIMARY KEY (id, chat_jid)
);
"""


def _open_dest(dest: Path) -> sqlite3.Connection:
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # URI mode on the main connection lets ATTACH open the source read-only.
    conn = sqlite3.connect(dest.resolve().as_uri(), uri=True)
    conn.execute("PRAGMA secure_delete = ON")
    conn.executescript(_SCHEMA)
    dest.chmod(0o600)
    return conn


def _delete_unauthorized(conn: sqlite3.Connection, policy: Policy) -> Dict[str, int]:
    any_perm = policy.allowed_chat_ids()
    readable = policy.allowed_chat_ids(READ)
    msg_sql = "DELETE FROM messages"
    chat_sql = "DELETE FROM chats"
    if readable:
        msg_sql += f" WHERE chat_jid NOT IN ({', '.join('?' for _ in readable)})"
    if any_perm:
        chat_sql += f" WHERE jid NOT IN ({', '.join('?' for _ in any_perm)})"
    removed_messages = conn.execute(msg_sql, tuple(readable)).rowcount
    removed_chats = conn.execute(chat_sql, tuple(any_perm)).rowcount
    return {"removed_chats": removed_chats, "removed_messages": removed_messages}


def prune(dest: Path, policy: Policy) -> Dict[str, int]:
    """Remove everything the policy no longer allows. Used on revoke."""
    if not dest.exists():
        return {"removed_chats": 0, "removed_messages": 0}
    conn = _open_dest(dest)
    try:
        with conn:
            stats = _delete_unauthorized(conn, policy)
        return stats
    finally:
        conn.close()


def project(source: Path, dest: Path, policy: Policy) -> Dict[str, int]:
    """One full projection pass. Runs in a single transaction on the destination."""
    any_perm = policy.allowed_chat_ids()
    readable = policy.allowed_chat_ids(READ)
    conn = _open_dest(dest)
    try:
        conn.execute("ATTACH DATABASE ? AS src", (source.resolve().as_uri() + "?mode=ro",))
        with conn:
            stats = _delete_unauthorized(conn, policy)
            copied_chats = copied_messages = 0
            if any_perm:
                copied_chats = conn.execute(
                    f"""
                    INSERT OR REPLACE INTO main.chats (jid, name, last_message_time)
                    SELECT jid, name, last_message_time FROM src.chats
                    WHERE jid IN ({', '.join('?' for _ in any_perm)})
                    """,
                    tuple(any_perm),
                ).rowcount
            if readable:
                copied_messages = conn.execute(
                    f"""
                    INSERT OR REPLACE INTO main.messages
                        (id, chat_jid, sender, content, timestamp, is_from_me, media_type, filename)
                    SELECT id, chat_jid, sender, content, timestamp, is_from_me, media_type, filename
                    FROM src.messages
                    WHERE chat_jid IN ({', '.join('?' for _ in readable)})
                    """,
                    tuple(readable),
                ).rowcount
        conn.execute("DETACH DATABASE src")
        stats.update({"copied_chats": copied_chats, "copied_messages": copied_messages})
        return stats
    finally:
        conn.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, required=True, help="bridge messages.db (full store)")
    parser.add_argument("--dest", type=Path, required=True, help="filtered projection database to write")
    parser.add_argument("--watch", type=float, default=0, help="repeat every N seconds (default: run once)")
    args = parser.parse_args(argv)
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    dest = args.dest.expanduser()
    source = args.source.expanduser()
    while True:
        # Counts only; never chat names, JIDs or content.
        try:
            stats = project(source, dest, load_policy())
            logger.info("projection pass complete: %s", stats)
        except sqlite3.Error as e:
            logger.error("projection pass failed: %s", type(e).__name__)
            if not args.watch:
                return 1
        if not args.watch:
            return 0
        time.sleep(args.watch)


if __name__ == "__main__":
    sys.exit(main())
