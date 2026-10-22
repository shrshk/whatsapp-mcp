"""Scoped access to the WhatsApp message store and bridge.

Every public function takes the current ``Policy`` explicitly and enforces it
twice: once up front (``require_read`` / ``require_send``) and again inside
the SQL, where every query is constrained to ``chat_jid = ?`` or
``chat_jid IN (...)`` built from the policy. There is no unscoped query path.
"""

import logging
import os
import re
import shutil
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

import requests

import audio
from access_policy import READ, AccessDenied, Policy, canonical_jid, jid_from_recipient

logger = logging.getLogger(__name__)

_HERE = Path(__file__).resolve().parent
DEFAULT_DB_PATH = _HERE.parent / "whatsapp-bridge" / "store" / "messages.db"
DEFAULT_BRIDGE_MEDIA_DIR = _HERE.parent / "whatsapp-bridge" / "store"
DEFAULT_MEDIA_EXPORT_DIR = Path.home() / ".local" / "share" / "whatsapp-mcp" / "media"
DEFAULT_API_BASE_URL = "http://127.0.0.1:8080/api"

MAX_LIMIT = 100
MAX_PAGE = 1000
MAX_CONTEXT = 10
MAX_QUERY_LEN = 256
MAX_MESSAGE_ID_LEN = 128
MAX_MESSAGE_LEN = 65536
BRIDGE_TIMEOUT_SECONDS = 60

_MESSAGE_COLUMNS = (
    "m.timestamp, m.sender, c.name, m.content, m.is_from_me, m.chat_jid, m.id, m.media_type"
)
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9@._-]")


# ---------------------------------------------------------------------------
# Configuration (read at call time so tests and deployments can override it)
# ---------------------------------------------------------------------------

def db_path() -> Path:
    return Path(os.environ.get("WHATSAPP_MCP_DB") or DEFAULT_DB_PATH).expanduser()


def api_base_url() -> str:
    return (os.environ.get("WHATSAPP_API_BASE_URL") or DEFAULT_API_BASE_URL).rstrip("/")


def bridge_media_dir() -> Path:
    return Path(os.environ.get("WHATSAPP_BRIDGE_MEDIA_DIR") or DEFAULT_BRIDGE_MEDIA_DIR).expanduser()


def media_export_dir() -> Path:
    return Path(os.environ.get("WHATSAPP_MCP_MEDIA_DIR") or DEFAULT_MEDIA_EXPORT_DIR).expanduser()


def outbox_dir() -> Optional[Path]:
    value = os.environ.get("WHATSAPP_MCP_OUTBOX")
    return Path(value).expanduser() if value else None


def safe_name(value: str) -> str:
    """Filesystem-safe single path component. Mirrors safeName in the bridge."""
    cleaned = _SAFE_NAME_RE.sub("_", value)
    if cleaned in ("", ".", ".."):
        return "_"
    return cleaned


# ---------------------------------------------------------------------------
# Input clamping
# ---------------------------------------------------------------------------

def _clamp(value: Any, low: int, high: int, default: int) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def _like_pattern(query: str) -> str:
    """Substring pattern with LIKE metacharacters escaped (used with ESCAPE '\\')."""
    escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _parse_iso(value: Optional[str], name: str) -> Optional[str]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid date format for '{name}'. Please use ISO-8601 format.") from None
    return parsed.isoformat(sep=" ")


def _placeholders(values: Sequence[Any]) -> str:
    return ", ".join("?" for _ in values)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """Open the message store read-only. The MCP server never writes to it."""
    uri = db_path().resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        yield conn
    finally:
        conn.close()


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value)
    # Go's time.Time string form: "2006-01-02 15:04:05.999999999 -0700 MST"
    # or the sqlite3 driver's "2006-01-02 15:04:05.999999999-07:00".
    match = re.match(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})(\.\d+)?\s*([+-]\d{2}:?\d{2}|Z)?", text)
    if not match:
        return None
    base, frac, tz = match.groups()
    frac = (frac or "")[:7]
    tz = tz or ""
    if tz and tz != "Z" and ":" not in tz:
        tz = tz[:3] + ":" + tz[3:]
    try:
        return datetime.fromisoformat(base + frac + tz)
    except ValueError:
        return None


def _iso(value: Any) -> Optional[str]:
    parsed = _parse_ts(value)
    return parsed.isoformat() if parsed else None


def _chat_names(conn: sqlite3.Connection, allowed: Sequence[str]) -> Dict[str, str]:
    """Display names for authorized chats only; used to label senders."""
    if not allowed:
        return {}
    rows = conn.execute(
        f"SELECT jid, name FROM chats WHERE jid IN ({_placeholders(allowed)})", tuple(allowed)
    ).fetchall()
    return {jid: name for jid, name in rows if name}


def _sender_name(sender: Optional[str], names: Dict[str, str]) -> Optional[str]:
    """Resolve a sender's display name from authorized chats only, by exact JID.

    Names are never looked up in chats outside the policy, so a group member's
    name only shows when their DM is also authorized.
    """
    if not sender:
        return sender
    candidates = [sender] if "@" in sender else [f"{sender}@s.whatsapp.net", f"{sender}@lid"]
    for jid in candidates:
        if jid in names:
            return names[jid]
    return sender


def _message_dict(row: Sequence[Any], names: Dict[str, str]) -> Dict[str, Any]:
    timestamp, sender, chat_name, content, is_from_me, chat_jid, msg_id, media_type = row
    return {
        "id": msg_id,
        "chat_jid": chat_jid,
        "chat_name": chat_name,
        "timestamp": _iso(timestamp),
        "sender": "me" if is_from_me else sender,
        "sender_name": "Me" if is_from_me else _sender_name(sender, names),
        "is_from_me": bool(is_from_me),
        "content": content,
        "media_type": media_type or None,
    }


def _last_message(conn: sqlite3.Connection, chat_jid: str, names: Dict[str, str]) -> Optional[Dict[str, Any]]:
    row = conn.execute(
        f"""
        SELECT {_MESSAGE_COLUMNS}
        FROM messages m JOIN chats c ON c.jid = m.chat_jid
        WHERE m.chat_jid = ?
        ORDER BY m.timestamp DESC, m.id DESC
        LIMIT 1
        """,
        (chat_jid,),
    ).fetchone()
    return _message_dict(row, names) if row else None


def _chat_dict(
    row: Sequence[Any], policy: Policy, conn: sqlite3.Connection, names: Dict[str, str], include_last_message: bool
) -> Dict[str, Any]:
    jid, name, last_message_time = row
    chat: Dict[str, Any] = {
        "jid": jid,
        "name": name,
        "is_group": jid.endswith("@g.us"),
        "permissions": sorted(policy.chats.get(jid, frozenset())),
    }
    # Activity metadata and content are read data; send-only chats get neither.
    if policy.can_read(jid):
        chat["last_message_time"] = _iso(last_message_time)
        if include_last_message:
            chat["last_message"] = _last_message(conn, jid, names)
    return chat


def _context(
    conn: sqlite3.Connection, chat_jid: str, timestamp: Any, msg_id: str, before: int, after: int,
    names: Dict[str, str],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Messages around (timestamp, id) in the same chat, with (timestamp, id) tie-breaking."""
    before_rows = conn.execute(
        f"""
        SELECT {_MESSAGE_COLUMNS}
        FROM messages m JOIN chats c ON c.jid = m.chat_jid
        WHERE m.chat_jid = ? AND (m.timestamp < ? OR (m.timestamp = ? AND m.id < ?))
        ORDER BY m.timestamp DESC, m.id DESC
        LIMIT ?
        """,
        (chat_jid, timestamp, timestamp, msg_id, before),
    ).fetchall()
    after_rows = conn.execute(
        f"""
        SELECT {_MESSAGE_COLUMNS}
        FROM messages m JOIN chats c ON c.jid = m.chat_jid
        WHERE m.chat_jid = ? AND (m.timestamp > ? OR (m.timestamp = ? AND m.id > ?))
        ORDER BY m.timestamp ASC, m.id ASC
        LIMIT ?
        """,
        (chat_jid, timestamp, timestamp, msg_id, after),
    ).fetchall()
    return (
        [_message_dict(r, names) for r in reversed(before_rows)],
        [_message_dict(r, names) for r in after_rows],
    )


def _require_message_id(message_id: Any) -> str:
    if not isinstance(message_id, str) or not message_id or len(message_id) > MAX_MESSAGE_ID_LEN:
        raise AccessDenied()
    return message_id


# ---------------------------------------------------------------------------
# Read tools
# ---------------------------------------------------------------------------

def list_chats(
    policy: Policy,
    query: Optional[str] = None,
    limit: int = 20,
    page: int = 0,
    include_last_message: bool = True,
    sort_by: str = "last_active",
) -> List[Dict[str, Any]]:
    """Authorized chats only. Chats without read permission show no activity."""
    allowed = policy.allowed_chat_ids()
    if not allowed:
        return []
    limit = _clamp(limit, 1, MAX_LIMIT, 20)
    page = _clamp(page, 0, MAX_PAGE, 0)

    sql = f"SELECT c.jid, c.name, c.last_message_time FROM chats c WHERE c.jid IN ({_placeholders(allowed)})"
    params: List[Any] = list(allowed)
    if query:
        pattern = _like_pattern(str(query)[:MAX_QUERY_LEN])
        sql += " AND (LOWER(c.name) LIKE LOWER(?) ESCAPE '\\' OR c.jid LIKE ? ESCAPE '\\')"
        params.extend([pattern, pattern])
    sql += " ORDER BY c.name, c.jid" if sort_by == "name" else " ORDER BY c.last_message_time DESC, c.jid"
    sql += " LIMIT ? OFFSET ?"
    params.extend([limit, page * limit])

    with _connect() as conn:
        names = _chat_names(conn, policy.allowed_chat_ids(READ))
        rows = conn.execute(sql, tuple(params)).fetchall()
        return [_chat_dict(r, policy, conn, names, include_last_message) for r in rows]


def get_chat(policy: Policy, chat_jid: str, include_last_message: bool = True) -> Dict[str, Any]:
    """Metadata for one authorized chat. Raises AccessDenied otherwise."""
    jid = canonical_jid(chat_jid)
    if jid is None or jid not in policy.chats:
        raise AccessDenied()
    with _connect() as conn:
        row = conn.execute(
            "SELECT c.jid, c.name, c.last_message_time FROM chats c WHERE c.jid = ?", (jid,)
        ).fetchone()
        if not row:
            raise AccessDenied()
        names = _chat_names(conn, policy.allowed_chat_ids(READ))
        return _chat_dict(row, policy, conn, names, include_last_message)


def get_direct_chat_by_contact(policy: Policy, sender_phone_number: str) -> Dict[str, Any]:
    """Exact ``<phone>@s.whatsapp.net`` lookup, then the usual authorization."""
    jid = jid_from_recipient(sender_phone_number)
    if jid is None or not jid.endswith("@s.whatsapp.net"):
        raise AccessDenied()
    return get_chat(policy, jid)


def get_contact_chats(policy: Policy, jid: str, limit: int = 20, page: int = 0) -> List[Dict[str, Any]]:
    """Readable chats that are the contact's DM or contain messages from them."""
    allowed = policy.allowed_chat_ids(READ)
    if not allowed or not isinstance(jid, str) or not jid.strip():
        return []
    jid = jid.strip()
    user = jid.split("@", 1)[0]
    limit = _clamp(limit, 1, MAX_LIMIT, 20)
    page = _clamp(page, 0, MAX_PAGE, 0)
    with _connect() as conn:
        rows = conn.execute(
            f"""
            SELECT c.jid, c.name, c.last_message_time
            FROM chats c
            WHERE c.jid IN ({_placeholders(allowed)})
              AND (c.jid = ? OR EXISTS (
                    SELECT 1 FROM messages m WHERE m.chat_jid = c.jid AND m.sender IN (?, ?)))
            ORDER BY c.last_message_time DESC, c.jid
            LIMIT ? OFFSET ?
            """,
            (*allowed, jid, jid, user, limit, page * limit),
        ).fetchall()
        names = _chat_names(conn, allowed)
        return [_chat_dict(r, policy, conn, names, True) for r in rows]


def get_last_interaction(policy: Policy, chat_jid: str) -> Optional[Dict[str, Any]]:
    """Most recent message in one readable chat."""
    jid = policy.require_read(chat_jid)
    with _connect() as conn:
        return _last_message(conn, jid, _chat_names(conn, policy.allowed_chat_ids(READ)))


def list_messages(
    policy: Policy,
    after: Optional[str] = None,
    before: Optional[str] = None,
    sender_phone_number: Optional[str] = None,
    chat_jid: Optional[str] = None,
    query: Optional[str] = None,
    limit: int = 20,
    page: int = 0,
    include_context: bool = True,
    context_before: int = 1,
    context_after: int = 1,
) -> List[Dict[str, Any]]:
    """Messages from readable chats. With no chat_jid, searches every readable chat."""
    if chat_jid is not None and chat_jid != "":
        scope = [policy.require_read(chat_jid)]
    else:
        scope = policy.allowed_chat_ids(READ)
    if not scope:
        return []

    limit = _clamp(limit, 1, MAX_LIMIT, 20)
    page = _clamp(page, 0, MAX_PAGE, 0)
    context_before = _clamp(context_before, 0, MAX_CONTEXT, 1)
    context_after = _clamp(context_after, 0, MAX_CONTEXT, 1)

    where = [f"m.chat_jid IN ({_placeholders(scope)})"]
    params: List[Any] = list(scope)
    after_ts = _parse_iso(after, "after")
    before_ts = _parse_iso(before, "before")
    if after_ts:
        where.append("m.timestamp > ?")
        params.append(after_ts)
    if before_ts:
        where.append("m.timestamp < ?")
        params.append(before_ts)
    if sender_phone_number:
        where.append("m.sender = ?")
        params.append(str(sender_phone_number))
    if query:
        where.append("LOWER(m.content) LIKE LOWER(?) ESCAPE '\\'")
        params.append(_like_pattern(str(query)[:MAX_QUERY_LEN]))
    params.extend([limit, page * limit])

    with _connect() as conn:
        names = _chat_names(conn, policy.allowed_chat_ids(READ))
        rows = conn.execute(
            f"""
            SELECT {_MESSAGE_COLUMNS}
            FROM messages m JOIN chats c ON c.jid = m.chat_jid
            WHERE {" AND ".join(where)}
            ORDER BY m.timestamp DESC, m.id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        ).fetchall()
        if not include_context:
            return [_message_dict(r, names) for r in rows]
        result = []
        for row in rows:
            before_msgs, after_msgs = _context(conn, row[5], row[0], row[6], context_before, context_after, names)
            result.append({"message": _message_dict(row, names), "before": before_msgs, "after": after_msgs})
        return result


def get_message_context(
    policy: Policy, message_id: str, chat_jid: str, before: int = 5, after: int = 5
) -> Dict[str, Any]:
    """Context around (chat_jid, message_id); never crosses into another chat."""
    jid = policy.require_read(chat_jid)
    message_id = _require_message_id(message_id)
    before = _clamp(before, 0, MAX_CONTEXT, 5)
    after = _clamp(after, 0, MAX_CONTEXT, 5)
    with _connect() as conn:
        row = conn.execute(
            f"""
            SELECT {_MESSAGE_COLUMNS}
            FROM messages m JOIN chats c ON c.jid = m.chat_jid
            WHERE m.chat_jid = ? AND m.id = ?
            """,
            (jid, message_id),
        ).fetchone()
        if not row:
            raise AccessDenied()
        names = _chat_names(conn, policy.allowed_chat_ids(READ))
        before_msgs, after_msgs = _context(conn, jid, row[0], row[6], before, after, names)
        return {"message": _message_dict(row, names), "before": before_msgs, "after": after_msgs}


# ---------------------------------------------------------------------------
# Bridge access (send and download)
# ---------------------------------------------------------------------------

def _bridge_post(endpoint: str, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    headers = {}
    token = os.environ.get("WHATSAPP_BRIDGE_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = requests.post(
            f"{api_base_url()}/{endpoint}", json=payload, headers=headers, timeout=BRIDGE_TIMEOUT_SECONDS
        )
    except requests.RequestException as e:
        logger.warning("bridge request failed: endpoint=%s error=%s", endpoint, type(e).__name__)
        return False, {"message": "WhatsApp bridge is not reachable"}
    try:
        body = response.json()
    except ValueError:
        body = {"message": f"Bridge returned HTTP {response.status_code}"}
    if not isinstance(body, dict):
        body = {"message": f"Bridge returned HTTP {response.status_code}"}
    return response.status_code == 200 and bool(body.get("success")), body


def _send_target(policy: Policy, recipient: Any) -> Optional[str]:
    jid = jid_from_recipient(recipient)
    if jid is None or not policy.can_send(jid):
        return None
    return jid


def resolve_outbound_path(media_path: Any) -> Path:
    """Resolve a file to send, confined to WHATSAPP_MCP_OUTBOX.

    Relative paths are taken relative to the outbox. Symlinks are resolved
    first, so a link pointing outside the outbox is rejected.
    """
    outbox = outbox_dir()
    if outbox is None:
        raise PermissionError("Sending files is disabled: WHATSAPP_MCP_OUTBOX is not configured")
    if not isinstance(media_path, str) or not media_path or "\x00" in media_path:
        raise PermissionError("Media path must be a file inside the outbox directory")
    outbox_real = outbox.resolve(strict=True)
    candidate = Path(media_path).expanduser()
    if not candidate.is_absolute():
        candidate = outbox_real / candidate
    real = candidate.resolve()
    if real == outbox_real or not real.is_relative_to(outbox_real) or not real.is_file():
        raise PermissionError("Media path must be a file inside the outbox directory")
    return real


def send_message(policy: Policy, recipient: str, message: str) -> Tuple[bool, str]:
    jid = _send_target(policy, recipient)
    if jid is None:
        return False, "Recipient not authorized for sending"
    if not isinstance(message, str) or not message or len(message) > MAX_MESSAGE_LEN:
        return False, "Message must be non-empty text"
    ok, body = _bridge_post("send", {"recipient": jid, "message": message})
    return ok, str(body.get("message", "Unknown response"))[:500]


def send_file(policy: Policy, recipient: str, media_path: str) -> Tuple[bool, str]:
    jid = _send_target(policy, recipient)
    if jid is None:
        return False, "Recipient not authorized for sending"
    try:
        path = resolve_outbound_path(media_path)
    except (PermissionError, OSError) as e:
        return False, str(e) if isinstance(e, PermissionError) else "Outbox directory is not available"
    ok, body = _bridge_post("send", {"recipient": jid, "media_path": str(path)})
    return ok, str(body.get("message", "Unknown response"))[:500]


def send_audio_message(policy: Policy, recipient: str, media_path: str) -> Tuple[bool, str]:
    jid = _send_target(policy, recipient)
    if jid is None:
        return False, "Recipient not authorized for sending"
    try:
        path = resolve_outbound_path(media_path)
    except (PermissionError, OSError) as e:
        return False, str(e) if isinstance(e, PermissionError) else "Outbox directory is not available"

    converted = None
    if path.suffix.lower() != ".ogg":
        try:
            converted = audio.convert_to_opus_ogg_temp(str(path))
        except (OSError, RuntimeError):
            return False, "Error converting file to opus ogg. You likely need to install ffmpeg."
    try:
        ok, body = _bridge_post("send", {"recipient": jid, "media_path": converted or str(path)})
    finally:
        if converted and os.path.exists(converted):
            os.unlink(converted)
    return ok, str(body.get("message", "Unknown response"))[:500]


def download_media(policy: Policy, message_id: str, chat_jid: str) -> Dict[str, Any]:
    """Download media for (chat_jid, message_id) after authorizing the chat.

    The bridge's file must sit in that chat's folder under the bridge media
    directory; it is then copied into the export directory, which is the only
    path handed back to the assistant.
    """
    jid = policy.require_read(chat_jid)
    message_id = _require_message_id(message_id)
    with _connect() as conn:
        row = conn.execute(
            "SELECT media_type, filename FROM messages WHERE chat_jid = ? AND id = ?", (jid, message_id)
        ).fetchone()
    if not row:
        raise AccessDenied()
    media_type, filename = row
    if not media_type:
        return {"success": False, "message": "Message has no media"}

    ok, body = _bridge_post("download", {"message_id": message_id, "chat_jid": jid})
    if not ok:
        return {"success": False, "message": "Failed to download media"}

    chat_dir = (bridge_media_dir() / safe_name(jid)).resolve()
    try:
        source = Path(str(body.get("path", ""))).resolve(strict=True)
    except (OSError, RuntimeError):
        return {"success": False, "message": "Downloaded media is not available"}
    if not source.is_relative_to(chat_dir) or not source.is_file():
        logger.warning("bridge returned media path outside the chat media folder; refusing")
        return {"success": False, "message": "Downloaded media is not available"}

    export_dir = media_export_dir() / safe_name(jid)
    export_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = export_dir / f"{safe_name(message_id)}_{safe_name(Path(filename or source.name).name)}"
    shutil.copyfile(source, target)
    return {"success": True, "message": f"Downloaded {media_type}", "file_path": str(target)}
