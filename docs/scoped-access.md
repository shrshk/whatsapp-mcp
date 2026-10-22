# Scoped access: design, inventory and threat model

This fork lets you give an AI assistant access to **chosen** WhatsApp chats only.
Access is enforced in code on every tool call. It is not an instruction in a prompt.

## What it guarantees

- Every read the MCP server returns comes from a chat on the allowlist with `read`.
- Every send goes to a chat on the allowlist with `send`. The check runs before any request to the bridge.
- New chats, including chats the bridge discovers later, are denied until you allow them.
- If the policy file is missing, unreadable or invalid, the server denies everything.
- The policy is re-read on every tool call. Allow and revoke apply to the next call. You do not need to restart anything.
- The MCP server cannot change the policy. Only `admin.py`, run by you in a terminal, can.

## What it does not guarantee

- **WhatsApp itself has no per-chat linking.** The bridge is a linked device with access to your whole account. This project scopes what the **assistant** sees. It does not limit what the bridge sees.
- **Python checks do not stop an agent that has a shell or network tool on the same machine.** That agent can read the bridge's `messages.db` directly or call the bridge's HTTP API. Use the deployment layers below to close those paths.
- **Allowed chats can contain prompt injection.** Anyone in an allowed group can write text aimed at the assistant. Tools return it as data, and no tool can change access. The assistant can still be misled within its allowed scope. One example: it could send a misleading message to a chat that has `send`. Keep `send` off unless you need it. Use your MCP host's per-call approval for send tools.

## Inventory (upstream HEAD `7d6a06d`, before this change)

### Storage

`whatsapp-bridge/store/messages.db`, written by the Go bridge:

- `chats(jid PK, name, last_message_time)`
- `messages(id, chat_jid, sender, content, timestamp, is_from_me, media_type, filename, url, media_key, file_sha256, file_enc_sha256, file_length)`. The primary key is `(id, chat_jid)`, so **a message id alone is not unique**.

`whatsapp-bridge/store/whatsapp.db` holds the whatsmeow session and keys. These are account credentials. The MCP server never touches this file.

### Go bridge HTTP routes

| Route | Before | After |
| --- | --- | --- |
| `POST /api/send` | Listened on `:8080` (all interfaces), no auth, any recipient. Logged message text. | Listens on `127.0.0.1:8080` by default (`WHATSAPP_BRIDGE_ADDR`). Optional bearer token (`WHATSAPP_BRIDGE_TOKEN`). When `WHATSAPP_POLICY_FILE` is set, the recipient must have `send`. Does not log text or paths. |
| `POST /api/download` | Same exposure. Wrote to `store/<chat>/<filename>`, where the filename came from the sender: `../../whatsapp.db` escaped the folder. | Same listener, token and policy (`read`). Chat folder and file name are reduced to one safe path component. Media root is configurable (`WHATSAPP_BRIDGE_MEDIA_DIR`). |

### MCP tools

| Tool | Before | After |
| --- | --- | --- |
| `search_contacts` | Substring search over every chat | **Removed.** The global contact list is outside any chat scope. |
| `list_chats` | Every chat | Allowlisted chats only. Chats without `read` show no last message or activity time. |
| `get_chat` | Any JID | Allowlisted chats only. Last message only with `read`. |
| `list_messages` | All chats when `chat_jid` was omitted | `chat_jid` must have `read`. Without it, the search covers only chats with `read`, through an explicit `IN (...)` predicate. Context stays in the same chat. Limits are capped. |
| `get_message_context` | Looked up the message by id only, across all chats | **Breaking:** now requires `chat_jid`. Looks up `(chat_jid, id)` after the `read` check. Context is the same chat, with `(timestamp, id)` tie-breaking. |
| `get_last_interaction` | Contact JID, any chat | **Breaking:** takes `chat_jid` and needs `read`. |
| `get_contact_chats` | Every chat containing the contact | Only chats with `read` |
| `get_direct_chat_by_contact` | `LIKE '%phone%'`, so a partial number matched other chats | Exact `<phone>@s.whatsapp.net`, then the normal check |
| `download_media` | Passed any `(message_id, chat_jid)` to the bridge | Checks `read` and that `(chat_jid, id)` exists **before** the bridge call. The returned file must be in that chat's media folder. It is copied to an export folder, and that copy is the only path returned. |
| `send_message` | Any phone number or JID | The canonical recipient JID must have `send`. A bare phone number counts only as exactly `<phone>@s.whatsapp.net`. |
| `send_file` / `send_audio_message` | Any file path on the host | Recipient needs `send`. The file must resolve, after following symlinks, to a regular file inside `WHATSAPP_MCP_OUTBOX`. If that variable is unset, file sending is off. |

### Other fixes

- Upstream `print()`ed to stdout, which is the MCP stdio channel. Logs now go to stderr. They hold no message text, chat names or JIDs.
- Sender display names were found with `LIKE '%number%'` over all chats. That leaked names from chats outside the allowlist. Names now come from exact JID matches against **authorized** chats only. A group member's name shows only if their DM is also authorized. Otherwise you see their number.
- The message store is opened read-only (`mode=ro`).
- Errors for a missing chat and a forbidden chat are the same: `Chat not found or not authorized`.

## JIDs

Access is keyed on the exact chat JID. It is never keyed on a display name, which changes when a group is renamed.

Accepted forms:

- `<digits>@s.whatsapp.net`: a DM by phone number
- `<digits>@lid`: a DM that WhatsApp keys by Linked ID
- `<digits>@g.us` or `<digits>-<digits>@g.us` (legacy): a group

Rejected forms: device-suffixed JIDs (`…:12@…`), `status@broadcast`, newsletters, wildcards and anything else.

A phone-number JID and a LID JID for the same person are **separate** entries. Neither one implies the other. If whatsmeow stores a DM under `@lid`, allow that JID. `admin.py discover` shows the exact JIDs in your store.

Deleted messages and stale JIDs simply return nothing. If you unlink the bridge, the stored history stays readable for allowed chats until you revoke them.

## Policy file

The file is JSON (default path `~/.config/whatsapp-mcp/access.json`, override with `WHATSAPP_MCP_POLICY`). See [`config/access.example.json`](../config/access.example.json).

JSON was chosen over YAML so that the Python server and the Go bridge can parse the same file with their standard libraries. No new dependency is needed.

Rules:

- `version` must be `1` and `default` must be `"deny"`.
- Permissions are `read` and `send`. `send` without `read` is allowed: the assistant can post to the chat but not read it.
- Unknown keys, duplicates, wildcards and malformed JIDs make the **whole file** invalid. An invalid file means deny all.
- `label` is a note for you. The MCP server never returns it.

`admin.py` writes the file atomically with mode `0600`. Granting access needs a typed `yes` on an interactive terminal. Revoking never asks.

### Admin page (`admin.py gui`)

A local web page for choosing chats. It uses the same validated, atomic write path and the same revoke cleanup as the CLI. Safeguards:

- It listens on `127.0.0.1` on a random port, and only while the command runs.
- Every request needs a token that is random for each launch. The token is printed in the terminal and carried in the link.
- The `Host` header must be the loopback address, which blocks DNS rebinding.
- Writes must come from the page's own `Origin`, with a JSON body of at most 4 KB.
- It sets a strict Content-Security-Policy with a per-response nonce, plus `no-referrer` and `frame-ancestors 'none'`. The page makes no external requests.
- Chat names are written by other people. The page inserts them as text and never parses them as HTML.
- If the policy file on disk is invalid, the page refuses to overwrite it (HTTP 409).
- It does not log requests, because request lines contain JIDs.

Turning on **Send** asks for confirmation first. The page works for anyone holding the token, which also means any local process that can read your terminal output. It is a convenience for the human at the keyboard, not a boundary against an agent with a shell. The threat model below covers that case.

## Deployment layers

Pick the layer that matches the tools your assistant has.

**Layer 1 (assistant has MCP tools only, e.g. Claude Desktop with no shell):** the default setup is enough. The assistant can reach WhatsApp only through the scoped tools.

**Layer 2 (bridge enforcement):** start the bridge with `WHATSAPP_POLICY_FILE` pointing at the same policy and with `WHATSAPP_BRIDGE_TOKEN` set. Give the token to the MCP server through its env config. Any local process that skips the MCP server now meets the same allowlist at the bridge.

**Layer 3 (projection, stronger isolation):** run `projector.py` as a trusted process. It writes a separate database that holds only allowed chats, with no media keys or URLs. Point the MCP server at it with `WHATSAPP_MCP_DB`. Then run the MCP server as a different OS user, or in a container, that **cannot read** `whatsapp-bridge/store/`, apart from the media folder if you use `download_media`. Set `WHATSAPP_MCP_PROJECTION` when you run `admin.py revoke`. The revoked chat is then deleted from the projection straight away. `secure_delete` overwrites the deleted rows on disk.

Revocation in each layer:

| | Takes effect | Data left behind |
| --- | --- | --- |
| MCP tools | Next call | Full store keeps everything (by design) |
| Bridge (Layer 2) | Next request | Same |
| Projection (Layer 3) | Next call (the policy is still checked), and rows are deleted on `revoke` or the next pass | No rows. Backups of the projection file are your responsibility. |
| Exported media | `revoke` deletes `~/.local/share/whatsapp-mcp/media/<jid>/` | Bridge's own media cache under `store/<jid>/` |

## Tests

```bash
cd whatsapp-mcp-server && uv run pytest -q
cd whatsapp-bridge && go test ./...
```

The Python tests build a small SQLite store with:

- allowed group A (`read`)
- allowed DM B (`read`, `send`)
- forbidden group C
- forbidden DM D
- a chat that appears after sync

The fixtures also include:

- the same message id in A and C
- messages that share a timestamp
- a sender file name with path traversal
- a prompt-injection message

The tests run against a mock bridge. They never touch a real WhatsApp session.

## Known limits and follow-ups

- There is a small time-of-check/time-of-use gap on outbound files. The server checks the resolved path, then the bridge opens it. A process that can write inside the outbox could swap the file in between. Only write-trusted tools should touch the outbox.
- The bridge's media cache under `store/<jid>/` is not removed on revoke.
- There is no Docker Compose file yet. The local process setup is in the README.
- Participant names in groups are hidden unless the participant's DM is authorized. An opt-in setting could relax this.
