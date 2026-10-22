import json
import sqlite3

import pytest

import admin
import projector
import whatsapp
from access_policy import AccessDenied, load_policy
from conftest import DM_B, DM_D, GROUP_A, GROUP_C, SECRET, dump, write_policy


def test_revoke_takes_effect_on_next_call(env):
    assert whatsapp.get_chat(load_policy(), GROUP_A)
    write_policy(env.policy, [{"jid": DM_B, "permissions": ["read", "send"]}])
    with pytest.raises(AccessDenied):
        whatsapp.get_chat(load_policy(), GROUP_A)
    assert GROUP_A not in dump(whatsapp.list_chats(load_policy()))


def test_allow_takes_effect_on_next_call(env):
    with pytest.raises(AccessDenied):
        whatsapp.get_chat(load_policy(), GROUP_C)
    write_policy(env.policy, [{"jid": GROUP_C, "permissions": ["read"]}])
    assert whatsapp.get_chat(load_policy(), GROUP_C)["jid"] == GROUP_C


def test_admin_allow_and_revoke(env, monkeypatch):
    monkeypatch.setenv("WHATSAPP_BRIDGE_DB", str(env.db))
    monkeypatch.setattr(admin, "_confirm", lambda prompt: True)
    assert admin.main(["--policy", str(env.policy), "allow", "--jid", GROUP_C]) == 0
    assert load_policy().can_read(GROUP_C) and not load_policy().can_send(GROUP_C)
    assert admin.main(["--policy", str(env.policy), "allow", "--jid", GROUP_C, "--send"]) == 0
    assert load_policy().can_send(GROUP_C)
    assert admin.main(["--policy", str(env.policy), "revoke", "--jid", GROUP_C]) == 0
    assert not load_policy().can_read(GROUP_C)
    assert (env.policy.stat().st_mode & 0o777) == 0o600


def test_admin_rejects_bad_input(env, monkeypatch):
    monkeypatch.setenv("WHATSAPP_BRIDGE_DB", str(env.db))
    monkeypatch.setattr(admin, "_confirm", lambda prompt: True)
    before = env.policy.read_text()
    assert admin.main(["--policy", str(env.policy), "allow", "--jid", "*"]) == 2
    assert admin.main(["--policy", str(env.policy), "allow", "--jid", "120363999999999999@g.us"]) == 2
    assert env.policy.read_text() == before


def test_admin_allow_requires_interactive_confirmation(env, monkeypatch):
    monkeypatch.setenv("WHATSAPP_BRIDGE_DB", str(env.db))
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    before = env.policy.read_text()
    assert admin.main(["--policy", str(env.policy), "allow", "--jid", GROUP_C]) == 1
    assert env.policy.read_text() == before


def test_admin_init_creates_deny_all(env, tmp_path):
    path = tmp_path / "new" / "access.json"
    assert admin.main(["--policy", str(path), "init"]) == 0
    assert json.loads(path.read_text()) == {"version": 1, "default": "deny", "chats": []}
    assert (path.stat().st_mode & 0o777) == 0o600


def test_revoke_deletes_exported_media(env, monkeypatch):
    assert whatsapp.download_media(load_policy(), "a3", GROUP_A)["success"]
    assert (env.export / GROUP_A).exists()
    assert admin.main(["--policy", str(env.policy), "revoke", "--jid", GROUP_A]) == 0
    assert not (env.export / GROUP_A).exists()


def test_projection_contains_only_allowed(env, tmp_path):
    dest = tmp_path / "projection.db"
    projector.project(env.db, dest, load_policy())
    conn = sqlite3.connect(dest)
    chats = {r[0] for r in conn.execute("SELECT jid FROM chats")}
    msgs = {r[0] for r in conn.execute("SELECT chat_jid FROM messages")}
    content = " ".join(r[0] for r in conn.execute("SELECT content FROM messages"))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(messages)")]
    conn.close()
    assert chats == {GROUP_A, DM_B} and msgs == {GROUP_A, DM_B}
    assert SECRET not in content
    assert "media_key" not in cols and "url" not in cols


def test_mcp_reads_from_projection(env, tmp_path, monkeypatch):
    dest = tmp_path / "projection.db"
    projector.project(env.db, dest, load_policy())
    monkeypatch.setenv("WHATSAPP_MCP_DB", str(dest))
    assert sorted(c["jid"] for c in whatsapp.list_chats(load_policy())) == sorted([GROUP_A, DM_B])
    assert whatsapp.list_messages(load_policy(), chat_jid=GROUP_A, include_context=False)


def test_projection_revoke_prunes(env, tmp_path, monkeypatch):
    dest = tmp_path / "projection.db"
    projector.project(env.db, dest, load_policy())
    monkeypatch.setenv("WHATSAPP_MCP_PROJECTION", str(dest))
    assert admin.main(["--policy", str(env.policy), "revoke", "--jid", GROUP_A]) == 0
    conn = sqlite3.connect(dest)
    assert conn.execute("SELECT COUNT(*) FROM messages WHERE chat_jid = ?", (GROUP_A,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM chats WHERE jid = ?", (GROUP_A,)).fetchone()[0] == 0
    conn.close()
    # A later sync pass must not bring it back.
    projector.project(env.db, dest, load_policy())
    conn = sqlite3.connect(dest)
    assert conn.execute("SELECT COUNT(*) FROM messages WHERE chat_jid = ?", (GROUP_A,)).fetchone()[0] == 0
    conn.close()


def test_projection_fails_closed(env, tmp_path):
    dest = tmp_path / "projection.db"
    projector.project(env.db, dest, load_policy())
    env.policy.write_text("{broken")
    projector.project(env.db, dest, load_policy())
    conn = sqlite3.connect(dest)
    assert conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM chats").fetchone()[0] == 0
    conn.close()


def test_projection_send_only_has_no_messages(env, tmp_path):
    write_policy(env.policy, [{"jid": DM_D, "permissions": ["send"]}])
    dest = tmp_path / "projection.db"
    projector.project(env.db, dest, load_policy())
    conn = sqlite3.connect(dest)
    assert {r[0] for r in conn.execute("SELECT jid FROM chats")} == {DM_D}
    assert conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 0
    conn.close()
