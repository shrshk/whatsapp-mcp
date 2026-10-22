import http.client
import json
import threading

import pytest

import admin_gui
from access_policy import load_policy
from conftest import DM_B, DM_D, GROUP_A, GROUP_C


@pytest.fixture
def gui(env, monkeypatch):
    monkeypatch.setenv("WHATSAPP_BRIDGE_DB", str(env.db))
    g = admin_gui.AdminGUI(env.policy, 0)
    t = threading.Thread(target=g.serve_forever, daemon=True)
    t.start()
    yield g
    g.shutdown()


def request(gui, method, path, body=None, token=True, host=None, origin=True, content_type="application/json"):
    conn = http.client.HTTPConnection("127.0.0.1", gui.port, timeout=5)
    headers = {"Host": host or f"127.0.0.1:{gui.port}"}
    if token:
        headers["X-Admin-Token"] = gui.token if token is True else token
    if origin:
        headers["Origin"] = f"http://127.0.0.1:{gui.port}" if origin is True else origin
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = content_type
    conn.request(method, path, body=data, headers=headers)
    res = conn.getresponse()
    payload = res.read()
    conn.close()
    return res, payload


def set_perms(gui, jid, perms, **kw):
    res, payload = request(gui, "POST", "/api/chat", {"jid": jid, "permissions": perms}, **kw)
    return res.status, json.loads(payload)


def test_page_requires_token(gui):
    res, body = request(gui, "GET", "/", token=False)
    assert res.status == 403
    res, body = request(gui, "GET", "/?token=wrong", token=False)
    assert res.status == 403
    res, body = request(gui, "GET", f"/?token={gui.token}", token=False)
    assert res.status == 200 and b"WhatsApp Access" in body


def test_page_security_headers(gui):
    res, body = request(gui, "GET", f"/?token={gui.token}", token=False)
    csp = res.getheader("Content-Security-Policy")
    assert "default-src 'none'" in csp and "'unsafe-inline'" not in csp and "frame-ancestors 'none'" in csp
    nonce = csp.split("'nonce-")[1].split("'")[0]
    assert f'nonce="{nonce}"'.encode() in body
    assert res.getheader("X-Frame-Options") == "DENY"
    assert res.getheader("Cache-Control") == "no-store"
    assert b"innerHTML" not in body


def test_api_requires_token(gui):
    for token in [False, "wrong", ""]:
        res, _ = request(gui, "GET", "/api/chats", token=token)
        assert res.status == 403
    assert set_perms(gui, GROUP_C, ["read"], token="wrong")[0] == 403
    assert not load_policy().can_read(GROUP_C)


def test_dns_rebinding_host_rejected(gui):
    for host in ["evil.example", f"evil.example:{gui.port}", "127.0.0.1:1"]:
        res, _ = request(gui, "GET", "/api/chats", host=host)
        assert res.status == 403
        res, _ = request(gui, "GET", f"/?token={gui.token}", token=False, host=host)
        assert res.status == 403


def test_cross_origin_writes_rejected(gui):
    for origin in [False, "http://evil.example", "null", f"http://127.0.0.1:{gui.port + 1}"]:
        assert set_perms(gui, GROUP_C, ["read"], origin=origin)[0] == 403
    res, _ = request(gui, "POST", "/api/chat", {"jid": GROUP_C, "permissions": ["read"]}, content_type="text/plain")
    assert res.status == 415
    assert not load_policy().can_read(GROUP_C)


def test_lists_full_store_with_permissions(gui):
    res, body = request(gui, "GET", "/api/chats")
    data = json.loads(body)
    by_jid = {c["jid"]: c for c in data["chats"]}
    assert set(by_jid) == {GROUP_A, DM_B, GROUP_C, DM_D}
    assert by_jid[GROUP_A]["permissions"] == ["read"]
    assert by_jid[DM_B]["permissions"] == ["read", "send"]
    assert by_jid[GROUP_C]["permissions"] == []
    assert by_jid[GROUP_C]["kind"] == "group" and by_jid[DM_D]["kind"] == "dm"
    assert data["policy_error"] is None


def test_grant_change_and_revoke(gui, env):
    assert set_perms(gui, GROUP_C, ["read"]) == (200, {"jid": GROUP_C, "permissions": ["read"]})
    assert load_policy().can_read(GROUP_C) and not load_policy().can_send(GROUP_C)
    assert set_perms(gui, GROUP_C, ["send", "read"])[1]["permissions"] == ["read", "send"]
    assert load_policy().can_send(GROUP_C)
    assert set_perms(gui, GROUP_C, ["send"])[1]["permissions"] == ["send"]
    assert not load_policy().can_read(GROUP_C)
    assert set_perms(gui, GROUP_C, [])[1]["permissions"] == []
    assert GROUP_C not in load_policy().chats
    assert (env.policy.stat().st_mode & 0o777) == 0o600


def test_revoke_keeps_label_and_runs_cleanup(gui, env):
    data = json.loads(env.policy.read_text())
    data["chats"][0]["label"] = "my note"
    env.policy.write_text(json.dumps(data))
    set_perms(gui, GROUP_A, ["read", "send"])
    entry = next(c for c in json.loads(env.policy.read_text())["chats"] if c["jid"] == GROUP_A)
    assert entry["label"] == "my note"
    (env.export / GROUP_A).mkdir(parents=True)
    set_perms(gui, GROUP_A, [])
    assert not (env.export / GROUP_A).exists()


@pytest.mark.parametrize(
    "jid,perms",
    [("*", ["read"]), ("120363999999999999@g.us", ["read"]), (GROUP_C, ["admin"]), (GROUP_C, "read"),
     (None, ["read"]), (f"{GROUP_C}x", ["read"])],
)
def test_invalid_writes_rejected(gui, env, jid, perms):
    before = env.policy.read_text()
    status, body = set_perms(gui, jid, perms)
    assert status == 400 and "error" in body
    assert env.policy.read_text() == before


def test_oversized_body_rejected(gui):
    res, _ = request(gui, "POST", "/api/chat", {"jid": GROUP_C, "permissions": ["read"], "pad": "x" * 5000})
    assert res.status == 413


def test_broken_policy_is_not_overwritten(gui, env):
    env.policy.write_text("{broken")
    status, body = set_perms(gui, GROUP_C, ["read"])
    assert status == 409
    assert env.policy.read_text() == "{broken"
    res, payload = request(gui, "GET", "/api/chats")
    assert json.loads(payload)["policy_error"]


def test_missing_policy_is_created(gui, env):
    env.policy.unlink()
    assert set_perms(gui, GROUP_C, ["read"])[0] == 200
    assert load_policy().allowed_chat_ids() == [GROUP_C]


def test_binds_loopback_only(gui):
    assert gui.httpd.server_address[0] == "127.0.0.1"
