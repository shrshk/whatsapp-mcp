import sqlite3

import pytest

import whatsapp
from access_policy import AccessDenied, load_policy
from conftest import DM_B, DM_D, GROUP_A, GROUP_C, INJECTION, NEW_E, SECRET, dump, write_policy


def ids(messages):
    return [(m["chat_jid"], m["id"]) for m in messages]


def test_list_chats_only_allowed(env):
    chats = whatsapp.list_chats(load_policy())
    assert sorted(c["jid"] for c in chats) == sorted([GROUP_A, DM_B])
    out = dump(chats)
    assert SECRET not in out and GROUP_C not in out and DM_D not in out and "Dave" not in out


def test_list_chats_query_cannot_widen_scope(env):
    for query in ["Forbidden", "%", "_", "' OR 1=1 --", GROUP_C, "@"]:
        out = dump(whatsapp.list_chats(load_policy(), query=query))
        assert GROUP_C not in out and "Forbidden" not in out and DM_D not in out


def test_list_chats_query_is_literal(env):
    assert whatsapp.list_chats(load_policy(), query="%") == []
    assert [c["jid"] for c in whatsapp.list_chats(load_policy(), query="bob")] == [DM_B]


def test_list_chats_sort_by_is_not_injectable(env):
    chats = whatsapp.list_chats(load_policy(), sort_by="name; DROP TABLE chats")
    assert len(chats) == 2


def test_empty_policy_returns_nothing(env):
    write_policy(env.policy, [])
    policy = load_policy()
    assert whatsapp.list_chats(policy) == []
    assert whatsapp.list_messages(policy) == []
    assert whatsapp.list_messages(policy, query="hello") == []
    assert whatsapp.get_contact_chats(policy, "15550000004") == []
    with pytest.raises(AccessDenied):
        whatsapp.get_chat(policy, GROUP_A)


@pytest.mark.parametrize("content", ["", "{", '{"version": 1, "default": "allow", "chats": []}'])
def test_invalid_policy_returns_nothing(env, content):
    env.policy.write_text(content)
    policy = load_policy()
    assert whatsapp.list_chats(policy) == []
    assert whatsapp.list_messages(policy) == []


def test_missing_policy_returns_nothing(env):
    env.policy.unlink()
    assert whatsapp.list_chats(load_policy()) == []
    assert whatsapp.list_messages(load_policy()) == []


def test_cross_chat_search_only_allowed(env):
    messages = whatsapp.list_messages(load_policy(), include_context=False, limit=100)
    assert {m["chat_jid"] for m in messages} == {GROUP_A, DM_B}
    assert SECRET not in dump(messages)
    hits = whatsapp.list_messages(load_policy(), query="hello group A", include_context=False)
    assert ids(hits) == [(GROUP_A, "a1")]


def test_search_with_context_stays_in_chat(env):
    results = whatsapp.list_messages(load_policy(), query="shared id", context_before=10, context_after=10)
    assert len(results) == 1
    assert results[0]["message"]["chat_jid"] == GROUP_A
    every = [results[0]["message"], *results[0]["before"], *results[0]["after"]]
    assert {m["chat_jid"] for m in every} == {GROUP_A}
    assert SECRET not in dump(results)


@pytest.mark.parametrize("jid", [GROUP_C, DM_D, NEW_E, "120363999999999999@g.us", "*", "%", "", "  "])
def test_filter_to_forbidden_chat_denied_uniformly(env, jid):
    if jid == "":
        # Empty means "no filter": still scoped to allowed chats.
        out = whatsapp.list_messages(load_policy(), chat_jid=jid)
        assert SECRET not in dump(out)
        return
    with pytest.raises(AccessDenied) as e:
        whatsapp.list_messages(load_policy(), chat_jid=jid)
    assert str(e.value) == "Chat not found or not authorized"


def test_search_metacharacters_and_huge_limits(env):
    for query in ["%", "_", "\\", "' OR '1'='1", "%' OR chat_jid LIKE '%", SECRET]:
        out = whatsapp.list_messages(load_policy(), query=query, limit=10**9, page=-5,
                                     context_before=10**6, context_after=10**6)
        assert SECRET not in dump(out)
    huge = whatsapp.list_messages(load_policy(), limit=10**9, include_context=False)
    assert len(huge) <= whatsapp.MAX_LIMIT
    literal = whatsapp.list_messages(load_policy(), query="100% done_", include_context=False)
    assert ids(literal) == [(GROUP_A, "a4")]


def test_sender_filter_cannot_reach_forbidden(env):
    out = whatsapp.list_messages(load_policy(), sender_phone_number="15550000004")
    assert out == []


def test_get_chat(env):
    chat = whatsapp.get_chat(load_policy(), GROUP_A)
    assert chat["jid"] == GROUP_A and chat["name"] == "Group A (renamed)"
    for jid in [GROUP_C, DM_D, "bogus", f"{GROUP_A} ", GROUP_A.upper()]:
        if jid == f"{GROUP_A} ":
            continue  # surrounding whitespace is tolerated by design
        with pytest.raises(AccessDenied):
            whatsapp.get_chat(load_policy(), jid)


def test_message_context_requires_chat_and_stays_in_chat(env):
    ctx = whatsapp.get_message_context(load_policy(), "dup", GROUP_A, before=10, after=10)
    assert ctx["message"]["content"] == "A shared id message"
    every = [ctx["message"], *ctx["before"], *ctx["after"]]
    assert {m["chat_jid"] for m in every} == {GROUP_A}
    # a2 shares dup's timestamp; the (timestamp, id) tie-break puts it just before.
    assert ctx["before"][-1]["id"] == "a2"
    assert ctx["after"][0]["id"] == "a3"
    assert SECRET not in dump(ctx)


@pytest.mark.parametrize("message_id,chat", [("dup", GROUP_C), ("c1", GROUP_C), ("d1", DM_D),
                                             ("c1", GROUP_A), ("missing", GROUP_A), ("", GROUP_A),
                                             ("x" * 1000, GROUP_A)])
def test_message_context_denied(env, message_id, chat):
    with pytest.raises(AccessDenied) as e:
        whatsapp.get_message_context(load_policy(), message_id, chat)
    assert str(e.value) == "Chat not found or not authorized"


def test_last_interaction(env):
    assert whatsapp.get_last_interaction(load_policy(), DM_B)["id"] == "b2"
    for jid in [GROUP_C, DM_D, "15550000004"]:
        with pytest.raises(AccessDenied):
            whatsapp.get_last_interaction(load_policy(), jid)


def test_contact_chats_only_allowed(env):
    chats = whatsapp.get_contact_chats(load_policy(), "15550000002@s.whatsapp.net")
    assert sorted(c["jid"] for c in chats) == sorted([GROUP_A, DM_B])
    assert whatsapp.get_contact_chats(load_policy(), "15550000004@s.whatsapp.net") == []
    assert whatsapp.get_contact_chats(load_policy(), DM_D) == []


def test_direct_chat_by_contact_exact_match(env):
    assert whatsapp.get_direct_chat_by_contact(load_policy(), "15550000002")["jid"] == DM_B
    for phone in ["15550000004", "5550000002", "1555000000", "%", "0000002"]:
        with pytest.raises(AccessDenied):
            whatsapp.get_direct_chat_by_contact(load_policy(), phone)


def test_sender_names_only_from_allowed_chats(env):
    messages = whatsapp.list_messages(load_policy(), chat_jid=GROUP_A, include_context=False, limit=100)
    by_id = {m["id"]: m for m in messages}
    assert by_id["dup"]["sender_name"] == "Bob"  # Bob's DM is authorized
    assert by_id["a1"]["sender_name"] == "15550000009"  # unknown contact: number only
    write_policy(env.policy, [{"jid": GROUP_A, "permissions": ["read"]}])
    messages = whatsapp.list_messages(load_policy(), chat_jid=GROUP_A, include_context=False, limit=100)
    assert "Bob" not in dump(messages)


def test_send_only_chat_shows_no_activity(env):
    write_policy(env.policy, [{"jid": GROUP_A, "permissions": ["send"]}])
    chats = whatsapp.list_chats(load_policy())
    assert chats == [{"jid": GROUP_A, "name": "Group A (renamed)", "is_group": True, "permissions": ["send"]}]
    with pytest.raises(AccessDenied):
        whatsapp.list_messages(load_policy(), chat_jid=GROUP_A)
    assert whatsapp.list_messages(load_policy()) == []


def test_new_chats_stay_denied(env):
    conn = sqlite3.connect(env.db)
    conn.execute("INSERT INTO chats VALUES (?, ?, ?)", (NEW_E, "Brand new group", "2025-01-02 00:00:00+00:00"))
    conn.execute(
        "INSERT INTO messages (id, chat_jid, sender, content, timestamp, is_from_me) VALUES (?, ?, ?, ?, ?, ?)",
        ("e1", NEW_E, "15550000007", f"{SECRET} new", "2025-01-02 00:00:00+00:00", 0),
    )
    conn.commit()
    conn.close()
    out = dump([whatsapp.list_chats(load_policy()), whatsapp.list_messages(load_policy(), limit=100)])
    assert NEW_E not in out and SECRET not in out
    with pytest.raises(AccessDenied):
        whatsapp.get_chat(load_policy(), NEW_E)


def test_prompt_injection_is_returned_as_data(env):
    before = env.policy.read_bytes()
    out = whatsapp.list_messages(load_policy(), query="SYSTEM", include_context=False)
    assert out[0]["content"] == INJECTION
    assert env.policy.read_bytes() == before
    with pytest.raises(AccessDenied):
        whatsapp.list_messages(load_policy(), chat_jid=GROUP_C)


def test_store_is_opened_read_only(env):
    with whatsapp._connect() as conn:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM messages")
