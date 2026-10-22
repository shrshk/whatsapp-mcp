"""Access policy for the scoped WhatsApp MCP server.

The policy is a small JSON file owned by the local admin. The MCP server only
ever reads it; it is mutated exclusively by ``admin.py``. Every tool call
reloads it, so allow/revoke takes effect on the next call. Any problem reading
or validating the file results in an empty policy (deny everything).

Example::

    {
      "version": 1,
      "default": "deny",
      "chats": [
        {"jid": "120363000000000000@g.us", "permissions": ["read"]},
        {"jid": "15551234567@s.whatsapp.net", "permissions": ["read", "send"]}
      ]
    }
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional

logger = logging.getLogger(__name__)

POLICY_VERSION = 1
READ = "read"
SEND = "send"
PERMISSIONS = frozenset({READ, SEND})

DEFAULT_POLICY_PATH = Path.home() / ".config" / "whatsapp-mcp" / "access.json"
POLICY_PATH_ENV = "WHATSAPP_MCP_POLICY"

# Chat JIDs as stored by the bridge: a numeric user part (legacy groups use
# "creator-timestamp") and one of the chat servers. Device suffixes (":12"),
# broadcast lists, status and newsletters are not chats we grant access to.
_JID_RE = re.compile(r"^[0-9]{1,32}(-[0-9]{1,32})?@(s\.whatsapp\.net|g\.us|lid)$")
_PHONE_RE = re.compile(r"^[0-9]{5,20}$")


class PolicyError(ValueError):
    """The policy file is missing, unreadable or invalid."""


class AccessDenied(PermissionError):
    """Raised when a chat is not authorized. The message never reveals whether
    the chat exists."""

    def __init__(self) -> None:
        super().__init__("Chat not found or not authorized")


def canonical_jid(value: object) -> Optional[str]:
    """Return ``value`` if it is a well-formed chat JID, else None.

    Matching is exact: no case folding, trimming of inner content, prefix or
    substring matching. Surrounding whitespace is the only thing tolerated.
    """
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not _JID_RE.match(value):
        return None
    return value


def jid_from_recipient(recipient: object) -> Optional[str]:
    """Turn a send recipient into a chat JID.

    A bare phone number maps to exactly ``<digits>@s.whatsapp.net``; it is
    then subject to the same exact policy match as any JID.
    """
    if isinstance(recipient, str) and _PHONE_RE.match(recipient.strip()):
        return f"{recipient.strip()}@s.whatsapp.net"
    return canonical_jid(recipient)


@dataclass(frozen=True)
class Policy:
    chats: Dict[str, FrozenSet[str]] = field(default_factory=dict)

    def can_read(self, chat_jid: object) -> bool:
        jid = canonical_jid(chat_jid)
        return jid is not None and READ in self.chats.get(jid, frozenset())

    def can_send(self, chat_jid: object) -> bool:
        jid = canonical_jid(chat_jid)
        return jid is not None and SEND in self.chats.get(jid, frozenset())

    def require_read(self, chat_jid: object) -> str:
        if not self.can_read(chat_jid):
            raise AccessDenied()
        return canonical_jid(chat_jid)

    def require_send(self, chat_jid: object) -> str:
        if not self.can_send(chat_jid):
            raise AccessDenied()
        return canonical_jid(chat_jid)

    def allowed_chat_ids(self, permission: Optional[str] = None) -> List[str]:
        """Sorted chat JIDs that hold ``permission`` (any permission if None)."""
        if permission is not None and permission not in PERMISSIONS:
            raise ValueError(f"unknown permission: {permission}")
        return sorted(jid for jid, perms in self.chats.items() if permission is None or permission in perms)


DENY_ALL = Policy()


def parse_policy(data: object) -> Policy:
    """Validate decoded JSON and build a Policy. Raises PolicyError."""
    if not isinstance(data, dict):
        raise PolicyError("policy must be a JSON object")
    unknown = set(data) - {"version", "default", "chats"}
    if unknown:
        raise PolicyError(f"unknown top-level keys: {sorted(unknown)}")
    if data.get("version") != POLICY_VERSION:
        raise PolicyError(f"unsupported policy version: {data.get('version')!r}")
    if data.get("default") != "deny":
        raise PolicyError("policy must set \"default\": \"deny\"")
    chats = data.get("chats", [])
    if not isinstance(chats, list):
        raise PolicyError("\"chats\" must be a list")

    result: Dict[str, FrozenSet[str]] = {}
    for i, entry in enumerate(chats):
        if not isinstance(entry, dict) or set(entry) - {"jid", "permissions", "label"}:
            raise PolicyError(f"chats[{i}] must be an object with jid, permissions and optional label")
        jid = canonical_jid(entry.get("jid"))
        if jid is None:
            raise PolicyError(f"chats[{i}].jid is not a valid chat JID")
        if jid in result:
            raise PolicyError(f"chats[{i}].jid is duplicated")
        perms = entry.get("permissions")
        if not isinstance(perms, list) or not perms or not all(isinstance(p, str) for p in perms):
            raise PolicyError(f"chats[{i}].permissions must be a non-empty list")
        if set(perms) - PERMISSIONS:
            raise PolicyError(f"chats[{i}].permissions has unknown values")
        result[jid] = frozenset(perms)
    return Policy(chats=result)


def policy_path() -> Path:
    return Path(os.environ.get(POLICY_PATH_ENV) or DEFAULT_POLICY_PATH).expanduser()


def load_policy_strict(path: Optional[Path] = None) -> Policy:
    """Load and validate the policy, raising PolicyError on any problem."""
    path = Path(path) if path is not None else policy_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as e:
        raise PolicyError(f"policy file not found: {path}") from e
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise PolicyError(f"cannot read policy file {path}: {type(e).__name__}") from e
    return parse_policy(data)


def load_policy(path: Optional[Path] = None) -> Policy:
    """Load the policy, failing closed: any error yields DENY_ALL."""
    try:
        return load_policy_strict(path)
    except PolicyError as e:
        # The reason names the file and error class only, never file contents.
        logger.warning("access policy unavailable, denying all access: %s", e)
        return DENY_ALL
