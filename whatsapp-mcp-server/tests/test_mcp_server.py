"""MCP-level checks: tool discovery and end-to-end calls through FastMCP."""

import asyncio
import json
import logging

import main
from conftest import DM_D, GROUP_A, GROUP_C, SECRET

EXPECTED_TOOLS = {
    "list_chats",
    "get_chat",
    "get_direct_chat_by_contact",
    "get_contact_chats",
    "get_last_interaction",
    "list_messages",
    "get_message_context",
    "send_message",
    "send_file",
    "send_audio_message",
    "download_media",
}


def _tools():
    return asyncio.run(main.mcp.list_tools())


def _call(name, args):
    result = asyncio.run(main.mcp.call_tool(name, args))
    # Different mcp versions return content blocks or (blocks, structured).
    blocks = result[0] if isinstance(result, tuple) else result
    return " ".join(getattr(b, "text", "") for b in blocks)


def test_tool_discovery_has_no_admin_or_unrestricted_tools():
    names = {t.name for t in _tools()}
    assert names == EXPECTED_TOOLS
    for forbidden in ["search_contacts", "allow", "revoke", "admin", "policy", "sql", "query", "discover"]:
        assert not any(forbidden == n or n.startswith(forbidden) for n in names)


def test_message_context_requires_chat_jid():
    tool = next(t for t in _tools() if t.name == "get_message_context")
    assert "chat_jid" in tool.inputSchema.get("required", [])


def test_end_to_end_denials_leak_nothing(env, caplog):
    with caplog.at_level(logging.DEBUG):
        outputs = [
            _call("list_chats", {}),
            _call("list_messages", {"query": "FORBIDDEN"}),
            _call("list_messages", {"chat_jid": GROUP_C}),
            _call("get_chat", {"chat_jid": GROUP_C}),
            _call("get_message_context", {"message_id": "c1", "chat_jid": GROUP_C}),
            _call("get_last_interaction", {"chat_jid": DM_D}),
            _call("get_contact_chats", {"jid": DM_D}),
            _call("get_direct_chat_by_contact", {"sender_phone_number": "15550000004"}),
            _call("download_media", {"message_id": "c2", "chat_jid": GROUP_C}),
            _call("send_message", {"recipient": GROUP_C, "message": "hi"}),
        ]
    joined = " ".join(outputs)
    assert SECRET not in joined and "Forbidden Group C" not in joined and "Dave" not in joined
    assert SECRET not in caplog.text and "Forbidden Group C" not in caplog.text
    assert env.bridge.calls == []


def test_end_to_end_allowed_read(env):
    out = _call("list_messages", {"chat_jid": GROUP_A, "include_context": False})
    assert "hello group A" in out
    chats = json.loads(_call("get_chat", {"chat_jid": GROUP_A}))
    assert chats["jid"] == GROUP_A
