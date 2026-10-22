import pytest

import whatsapp
from access_policy import load_policy
from conftest import DM_B, DM_D, GROUP_A, GROUP_C, write_policy


def test_send_to_allowed_dm(env):
    ok, _ = whatsapp.send_message(load_policy(), DM_B, "hello")
    assert ok
    assert env.bridge.calls == [{"url": "http://bridge.test/api/send",
                                 "json": {"recipient": DM_B, "message": "hello"}, "headers": {}}]


def test_phone_number_resolves_to_allowed_jid(env):
    ok, _ = whatsapp.send_message(load_policy(), "15550000002", "hello")
    assert ok
    assert env.bridge.calls[0]["json"]["recipient"] == DM_B


@pytest.mark.parametrize(
    "recipient",
    [GROUP_A, GROUP_C, DM_D, "15550000004", "15559999999", "15559999999@s.whatsapp.net",
     "15550000002:3@s.whatsapp.net", "15550000002@lid", "+15550000002", "*", "", None,
     "15550000002@s.whatsapp.net,15550000004@s.whatsapp.net"],
)
def test_send_denied_before_any_bridge_request(env, recipient):
    ok, message = whatsapp.send_message(load_policy(), recipient, "hello")
    assert not ok and message == "Recipient not authorized for sending"
    assert env.bridge.calls == []


def test_no_policy_no_sends(env):
    env.policy.unlink()
    assert not whatsapp.send_message(load_policy(), DM_B, "hi")[0]
    assert not whatsapp.send_file(load_policy(), DM_B, "photo.jpg")[0]
    assert env.bridge.calls == []


def test_send_file_inside_outbox(env):
    ok, _ = whatsapp.send_file(load_policy(), DM_B, "photo.jpg")
    assert ok
    sent = env.bridge.calls[0]["json"]["media_path"]
    assert sent == str((env.outbox / "photo.jpg").resolve())
    ok, _ = whatsapp.send_file(load_policy(), DM_B, str(env.outbox / "photo.jpg"))
    assert ok


def test_send_file_to_unauthorized_recipient(env):
    for recipient in [GROUP_A, GROUP_C, DM_D]:
        assert not whatsapp.send_file(load_policy(), recipient, "photo.jpg")[0]
        assert not whatsapp.send_audio_message(load_policy(), recipient, "voice.ogg")[0]
    assert env.bridge.calls == []


def test_unsafe_media_paths_rejected(env):
    secret = env.tmp / "secret.txt"
    secret.write_text("secret")
    (env.outbox / "link.jpg").symlink_to(secret)
    (env.outbox / "dirlink").symlink_to(env.tmp)
    (env.outbox / "sub").mkdir()
    bad = [
        "../secret.txt",
        "sub/../../secret.txt",
        str(secret),
        "/etc/passwd",
        "link.jpg",
        "dirlink/secret.txt",
        str(env.db),
        "",
        ".",
        "sub",
        "missing.jpg",
        "photo.jpg\x00.txt",
        "~/.ssh/id_rsa",
    ]
    for path in bad:
        ok, message = whatsapp.send_file(load_policy(), DM_B, path)
        assert not ok, path
        ok, _ = whatsapp.send_audio_message(load_policy(), DM_B, path)
        assert not ok, path
    assert env.bridge.calls == []


def test_file_sends_disabled_without_outbox(env, monkeypatch):
    monkeypatch.delenv("WHATSAPP_MCP_OUTBOX")
    ok, message = whatsapp.send_file(load_policy(), DM_B, str(env.outbox / "photo.jpg"))
    assert not ok and "disabled" in message
    assert env.bridge.calls == []


def test_send_audio_ogg(env):
    ok, _ = whatsapp.send_audio_message(load_policy(), DM_B, "voice.ogg")
    assert ok
    assert env.bridge.calls[0]["json"]["media_path"] == str((env.outbox / "voice.ogg").resolve())


def test_send_audio_conversion_temp_file_is_removed(env, monkeypatch, tmp_path):
    (env.outbox / "voice.mp3").write_bytes(b"mp3")
    converted = tmp_path / "converted.ogg"

    def fake_convert(path):
        converted.write_bytes(b"ogg")
        return str(converted)

    monkeypatch.setattr(whatsapp.audio, "convert_to_opus_ogg_temp", fake_convert)
    ok, _ = whatsapp.send_audio_message(load_policy(), DM_B, "voice.mp3")
    assert ok
    assert env.bridge.calls[0]["json"]["media_path"] == str(converted)
    assert not converted.exists()


def test_bridge_token_header(env, monkeypatch):
    monkeypatch.setenv("WHATSAPP_BRIDGE_TOKEN", "t0ken")
    whatsapp.send_message(load_policy(), DM_B, "hi")
    assert env.bridge.calls[0]["headers"] == {"Authorization": "Bearer t0ken"}


def test_revoked_send_permission_applies_immediately(env):
    assert whatsapp.send_message(load_policy(), DM_B, "one")[0]
    write_policy(env.policy, [{"jid": DM_B, "permissions": ["read"]}])
    assert not whatsapp.send_message(load_policy(), DM_B, "two")[0]
    assert len(env.bridge.calls) == 1
