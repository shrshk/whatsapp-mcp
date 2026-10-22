import pytest

import whatsapp
from access_policy import AccessDenied, load_policy
from conftest import DM_B, GROUP_A, GROUP_C


def test_download_authorized_media(env):
    result = whatsapp.download_media(load_policy(), "a3", GROUP_A)
    assert result["success"]
    path = result["file_path"]
    assert path.startswith(str(env.export / GROUP_A))
    assert open(path, "rb").read() == b"media-bytes"
    assert env.bridge.calls[0]["json"] == {"message_id": "a3", "chat_jid": GROUP_A}


@pytest.mark.parametrize("message_id,chat", [("c2", GROUP_C), ("c2", GROUP_A), ("dup", GROUP_C),
                                             ("missing", GROUP_A), ("", GROUP_A)])
def test_download_denied_before_bridge_request(env, message_id, chat):
    with pytest.raises(AccessDenied):
        whatsapp.download_media(load_policy(), message_id, chat)
    assert env.bridge.calls == []


def test_non_media_message(env):
    assert whatsapp.download_media(load_policy(), "a1", GROUP_A)["success"] is False
    assert env.bridge.calls == []


def test_bridge_path_outside_chat_folder_rejected(env):
    # A compromised or buggy bridge must not make us hand out arbitrary files.
    secret = env.tmp / "secret.txt"
    secret.write_text("secret")
    other_chat = env.bridge_media / DM_B
    other_chat.mkdir(parents=True)
    (other_chat / "x.jpg").write_bytes(b"x")
    for path in [secret, env.db, other_chat / "x.jpg", env.bridge_media / GROUP_A / ".." / "messages.db"]:
        env.bridge.download_path_override = path
        result = whatsapp.download_media(load_policy(), "a3", GROUP_A)
        assert result["success"] is False
    assert not (env.export / GROUP_A).exists() or not any((env.export / GROUP_A).iterdir())


def test_bridge_symlink_escape_rejected(env):
    secret = env.tmp / "secret.txt"
    secret.write_text("secret")
    chat_dir = env.bridge_media / GROUP_A
    chat_dir.mkdir(parents=True)
    (chat_dir / "evil.jpg").symlink_to(secret)
    env.bridge.download_path_override = chat_dir / "evil.jpg"
    assert whatsapp.download_media(load_policy(), "a3", GROUP_A)["success"] is False


def test_export_filename_is_sanitized(env):
    import sqlite3
    conn = sqlite3.connect(env.db)
    conn.execute("UPDATE messages SET filename = '../../../evil.sh' WHERE id = 'a3'")
    conn.commit()
    conn.close()
    result = whatsapp.download_media(load_policy(), "a3", GROUP_A)
    assert result["success"]
    assert result["file_path"].startswith(str(env.export / GROUP_A) + "/")
    assert result["file_path"].endswith("a3_evil.sh")
