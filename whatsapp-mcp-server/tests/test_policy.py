import json
import os
import stat

import pytest

from access_policy import (
    DENY_ALL,
    AccessDenied,
    PolicyError,
    canonical_jid,
    jid_from_recipient,
    load_policy,
    load_policy_strict,
    parse_policy,
)
from conftest import DM_B, GROUP_A, GROUP_C


def doc(chats, **extra):
    return {"version": 1, "default": "deny", "chats": chats, **extra}


@pytest.mark.parametrize(
    "value",
    [GROUP_A, DM_B, "123456789012345@lid", "15551234567-1600000000@g.us", f"  {GROUP_A}  "],
)
def test_valid_jids(value):
    assert canonical_jid(value) == value.strip()


@pytest.mark.parametrize(
    "value",
    [
        "", "*", "%", "@g.us", "abc@g.us", "15551234567", "15551234567:12@s.whatsapp.net",
        "status@broadcast", "123@newsletter", "15551234567@S.WHATSAPP.NET", "1555@s.whatsapp.net.evil",
        f"{GROUP_A}x", f"x{GROUP_A}", "1' OR '1'='1@g.us", None, 123, ["x"],
    ],
)
def test_invalid_jids(value):
    assert canonical_jid(value) is None


def test_phone_recipient_maps_to_exact_dm_jid():
    assert jid_from_recipient("15550000002") == DM_B
    assert jid_from_recipient("+15550000002") is None
    assert jid_from_recipient("1555 0000002") is None


def test_parse_valid_policy():
    policy = parse_policy(doc([{"jid": GROUP_A, "permissions": ["read"]},
                               {"jid": DM_B, "permissions": ["read", "send"], "label": "Bob"}]))
    assert policy.can_read(GROUP_A) and not policy.can_send(GROUP_A)
    assert policy.can_read(DM_B) and policy.can_send(DM_B)
    assert not policy.can_read(GROUP_C)
    assert policy.allowed_chat_ids("read") == sorted([GROUP_A, DM_B])
    assert policy.allowed_chat_ids("send") == [DM_B]


def test_send_only_chat():
    policy = parse_policy(doc([{"jid": GROUP_A, "permissions": ["send"]}]))
    assert policy.can_send(GROUP_A) and not policy.can_read(GROUP_A)
    assert policy.allowed_chat_ids("read") == []
    assert policy.allowed_chat_ids() == [GROUP_A]


@pytest.mark.parametrize(
    "data",
    [
        [],
        "x",
        {"version": 2, "default": "deny", "chats": []},
        {"version": 1, "default": "allow", "chats": []},
        {"version": 1, "chats": []},
        doc([], extra_key=1),
        doc({"jid": GROUP_A}),
        doc([{"jid": "*", "permissions": ["read"]}]),
        doc([{"jid": GROUP_A, "permissions": []}]),
        doc([{"jid": GROUP_A, "permissions": ["read", "admin"]}]),
        doc([{"jid": GROUP_A, "permissions": "read"}]),
        doc([{"jid": GROUP_A, "permissions": ["read"]}, {"jid": GROUP_A, "permissions": ["send"]}]),
        doc([{"jid": GROUP_A, "permissions": ["read"], "extra": True}]),
    ],
)
def test_invalid_policies_rejected(data):
    with pytest.raises(PolicyError):
        parse_policy(data)


def test_missing_or_invalid_file_denies_all(tmp_path):
    assert load_policy(tmp_path / "missing.json") is DENY_ALL
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert load_policy(bad) is DENY_ALL
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps(doc([{"jid": "*", "permissions": ["read"]}])))
    assert load_policy(wrong) is DENY_ALL
    with pytest.raises(PolicyError):
        load_policy_strict(wrong)


def test_unreadable_file_denies_all(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root can read anything")
    path = tmp_path / "locked.json"
    path.write_text(json.dumps(doc([{"jid": GROUP_A, "permissions": ["read"]}])))
    path.chmod(0)
    try:
        assert load_policy(path) is DENY_ALL
    finally:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_require_raises_uniform_error():
    policy = parse_policy(doc([{"jid": GROUP_A, "permissions": ["read"]}]))
    assert policy.require_read(GROUP_A) == GROUP_A
    messages = set()
    for jid in [GROUP_C, "nonsense", "", None]:
        with pytest.raises(AccessDenied) as e:
            policy.require_read(jid)
        messages.add(str(e.value))
    with pytest.raises(AccessDenied) as e:
        policy.require_send(GROUP_A)
    messages.add(str(e.value))
    assert messages == {"Chat not found or not authorized"}


def test_policy_failure_log_does_not_leak_contents(tmp_path, caplog):
    path = tmp_path / "bad.json"
    path.write_text('{"chats": "120363000000000003@g.us SECRET"')
    with caplog.at_level("WARNING"):
        load_policy(path)
    assert "SECRET" not in caplog.text and GROUP_C not in caplog.text


def test_example_config_is_valid():
    from pathlib import Path

    example = Path(__file__).resolve().parents[2] / "config" / "access.example.json"
    policy = load_policy_strict(example)
    assert policy.can_read("120363000000000000@g.us")
    assert policy.can_send("15551234567@s.whatsapp.net")
