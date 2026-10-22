"""Local admin CLI for the scoped WhatsApp MCP access policy.

This is the ONLY way to change what the assistant can see or send to. It is
never exposed as an MCP tool. Run it yourself in a terminal:

    uv run admin.py init
    uv run admin.py discover --query family
    uv run admin.py allow --jid 120363000000000000@g.us
    uv run admin.py allow --jid 15551234567@s.whatsapp.net --send
    uv run admin.py revoke --jid 15551234567@s.whatsapp.net
    uv run admin.py list
    uv run admin.py check
    uv run admin.py gui          # pick chats in a local web page

Granting access asks for confirmation on an interactive terminal. Revoking
never does: reducing access is always safe.
"""

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional

import admin_gui
import projector
import whatsapp
from access_policy import (
    POLICY_VERSION,
    READ,
    SEND,
    PolicyError,
    canonical_jid,
    load_policy_strict,
    parse_policy,
    policy_path,
)


def _empty_policy() -> Dict[str, Any]:
    return {"version": POLICY_VERSION, "default": "deny", "chats": []}


def read_policy_document(path: Path) -> Dict[str, Any]:
    """Load the raw policy document for editing. Validates it first."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    parse_policy(data)
    return data


def write_policy_document(path: Path, data: Dict[str, Any]) -> None:
    """Validate, then atomically replace the policy file with mode 0600."""
    parse_policy(data)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=".access.", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def set_chat(data: Dict[str, Any], jid: str, permissions: List[str], label: Optional[str]) -> Dict[str, Any]:
    chats = [c for c in data.get("chats", []) if c.get("jid") != jid]
    entry: Dict[str, Any] = {"jid": jid, "permissions": permissions}
    if label:
        entry["label"] = label
    chats.append(entry)
    return {**data, "chats": chats}


def remove_chat(data: Dict[str, Any], jid: str) -> Dict[str, Any]:
    return {**data, "chats": [c for c in data.get("chats", []) if c.get("jid") != jid]}


def revoke_cleanup(jid: str, policy) -> List[str]:
    """Remove exported media and projected rows for a revoked chat."""
    done = []
    export = whatsapp.media_export_dir() / whatsapp.safe_name(jid)
    if export.is_dir():
        shutil.rmtree(export)
        done.append(f"deleted exported media in {export}")
    projection = os.environ.get("WHATSAPP_MCP_PROJECTION")
    if projection:
        stats = projector.prune(Path(projection).expanduser(), policy)
        done.append(f"pruned projection {projection}: {stats}")
    return done


def _confirm(prompt: str) -> bool:
    if not sys.stdin.isatty():
        print("Refusing to grant access without an interactive terminal.", file=sys.stderr)
        return False
    return input(f"{prompt} Type 'yes' to confirm: ").strip() == "yes"


def _full_store_rows(query: Optional[str], limit: int) -> List[tuple]:
    """Local discovery over the full bridge store. Admin terminal only."""
    uri = Path(os.environ.get("WHATSAPP_BRIDGE_DB") or whatsapp.DEFAULT_DB_PATH).expanduser().resolve().as_uri()
    conn = sqlite3.connect(uri + "?mode=ro", uri=True)
    try:
        sql = "SELECT jid, name, last_message_time FROM chats"
        params: List[Any] = []
        if query:
            sql += " WHERE LOWER(name) LIKE LOWER(?) OR jid LIKE ?"
            params = [f"%{query}%", f"%{query}%"]
        sql += " ORDER BY last_message_time DESC LIMIT ?"
        params.append(limit)
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def _chat_exists(jid: str) -> bool:
    uri = Path(os.environ.get("WHATSAPP_BRIDGE_DB") or whatsapp.DEFAULT_DB_PATH).expanduser().resolve().as_uri()
    try:
        conn = sqlite3.connect(uri + "?mode=ro", uri=True)
    except sqlite3.Error:
        return False
    try:
        return conn.execute("SELECT 1 FROM chats WHERE jid = ?", (jid,)).fetchone() is not None
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--policy", type=Path, help="policy file (default: $WHATSAPP_MCP_POLICY or ~/.config/whatsapp-mcp/access.json)"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create an empty deny-all policy")
    d = sub.add_parser("discover", help="list chats in the full local store with their JIDs")
    d.add_argument("--query")
    d.add_argument("--limit", type=int, default=50)
    a = sub.add_parser("allow", help="grant access to one chat")
    a.add_argument("--jid", required=True)
    a.add_argument("--send", action="store_true", help="also allow sending to this chat")
    a.add_argument("--no-read", action="store_true", help="send-only: do not allow reading")
    a.add_argument("--label", help="local note for yourself; never shown to the assistant")
    a.add_argument("--force", action="store_true", help="allow a JID not yet seen in the local store")
    r = sub.add_parser("revoke", help="remove all access to one chat")
    r.add_argument("--jid", required=True)
    sub.add_parser("list", help="show the policy")
    sub.add_parser("check", help="validate the policy file")
    g = sub.add_parser("gui", help="choose chats in a local web page (127.0.0.1 only)")
    g.add_argument("--port", type=int, default=0, help="port to listen on (default: random)")
    g.add_argument("--no-browser", action="store_true", help="print the link instead of opening a browser")
    args = parser.parse_args(argv)

    path = (args.policy or policy_path()).expanduser()

    if args.command == "init":
        if path.exists():
            print(f"{path} already exists")
            return 1
        write_policy_document(path, _empty_policy())
        print(f"Created deny-all policy at {path}")
        return 0

    if args.command == "check":
        try:
            policy = load_policy_strict(path)
        except PolicyError as e:
            print(f"INVALID: {e}")
            return 1
        mode = path.stat().st_mode & 0o777
        print(f"OK: {len(policy.chats)} chat(s) allowed")
        if mode & 0o022:
            print(f"WARNING: {path} is writable by group/others (mode {mode:o}); run chmod 600")
        return 0

    if args.command == "gui":
        gui = admin_gui.AdminGUI(path, args.port)
        print("Admin page (keep this link private; it works only while this command runs):")
        print(f"  {gui.url}")
        print("Press Ctrl+C to stop.", flush=True)
        if not args.no_browser:
            webbrowser.open(gui.url)
        try:
            gui.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")
        finally:
            gui.close()
        return 0

    if args.command == "discover":
        allowed = load_policy_strict(path).chats if path.exists() else {}
        for jid, name, last in _full_store_rows(args.query, args.limit):
            kind = "group" if jid.endswith("@g.us") else "dm"
            perms = ",".join(sorted(allowed.get(jid, []))) or "-"
            print(f"{kind:5}  {perms:10}  {jid:40}  {name or ''}  ({last or 'no activity'})")
        return 0

    data = read_policy_document(path) if path.exists() else _empty_policy()

    if args.command == "list":
        for c in data["chats"]:
            print(f"{c['jid']:40}  {','.join(c['permissions']):10}  {c.get('label', '')}")
        if not data["chats"]:
            print("(no chats allowed)")
        return 0

    jid = canonical_jid(args.jid)
    if jid is None:
        print("Not a valid chat JID (expected e.g. 15551234567@s.whatsapp.net or 1203...@g.us)", file=sys.stderr)
        return 2

    if args.command == "allow":
        if not args.force and not _chat_exists(jid):
            print("That JID is not in the local store. Check `discover`, or pass --force.", file=sys.stderr)
            return 2
        perms = ([] if args.no_read else [READ]) + ([SEND] if args.send else [])
        if not perms:
            print("Nothing to allow: --no-read without --send", file=sys.stderr)
            return 2
        if not _confirm(f"Allow the assistant {'+'.join(perms)} access to {jid}?"):
            return 1
        write_policy_document(path, set_chat(data, jid, perms, args.label))
        print(f"Allowed {jid}: {','.join(perms)}")
        return 0

    if args.command == "revoke":
        new = remove_chat(data, jid)
        write_policy_document(path, new)
        print(f"Revoked {jid}")
        for line in revoke_cleanup(jid, parse_policy(new)):
            print(line)
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
