# WhatsApp MCP Server (scoped access fork)

This is a Model Context Protocol (MCP) server for WhatsApp.

> **This fork adds scoped access.** The assistant sees only the chats you allow. It can send only to chats you allow with `send`. Everything else is denied by default, new chats included. See [Scoped Access](#scoped-access) and [docs/scoped-access.md](docs/scoped-access.md). Forked from [lharries/whatsapp-mcp](https://github.com/lharries/whatsapp-mcp).

With this you can search and read your personal Whatsapp messages (including images, videos, documents, and audio messages), search your contacts and send messages to either individuals or groups. You can also send media files including images, videos, documents, and audio messages.

It connects to your **personal WhatsApp account** directly via the Whatsapp web multidevice API (using the [whatsmeow](https://github.com/tulir/whatsmeow) library). All your messages are stored locally in a SQLite database and only sent to an LLM (such as Claude) when the agent accesses them through tools (which you control).

Here's an example of what you can do when it's connected to Claude.

![WhatsApp MCP](./example-use.png)

> To get updates on this and other projects I work on [enter your email here](https://docs.google.com/forms/d/1rTF9wMBTN0vPfzWuQa2BjfGKdKIpTbyeKxhPMcEzgyI/preview)

> *Caution:* as with many MCP servers, the WhatsApp MCP is subject to [the lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/). This means that project injection could lead to private data exfiltration.

## Installation

### Prerequisites

- Go
- Python 3.6+
- Anthropic Claude Desktop app (or Cursor)
- UV (Python package manager), install with `curl -LsSf https://astral.sh/uv/install.sh | sh`
- FFmpeg (_optional_) - Only needed for audio messages. If you want to send audio files as playable WhatsApp voice messages, they must be in `.ogg` Opus format. With FFmpeg installed, the MCP server will automatically convert non-Opus audio files. Without FFmpeg, you can still send raw audio files using the `send_file` tool.

### Steps

1. **Clone this repository**

   ```bash
   git clone https://github.com/shrshk/whatsapp-mcp.git
   cd whatsapp-mcp
   ```

2. **Run the WhatsApp bridge**

   Navigate to the whatsapp-bridge directory and run the Go application:

   ```bash
   cd whatsapp-bridge
   go run .
   ```

   The first time you run it, you will be prompted to scan a QR code. Scan the QR code with your WhatsApp mobile app to authenticate.

   After approximately 20 days, you will might need to re-authenticate.

3. **Choose which chats the assistant may use**

   Nothing is visible until you allow it. The easiest way is the local admin page:

   ```bash
   cd whatsapp-mcp-server
   uv run admin.py gui
   ```

   It opens a page in your browser that lists every chat. Turn on **Read** or **Send** for each chat you want. Changes save at once. The page listens on `127.0.0.1` only and needs the one-time link printed in your terminal. It stops when you press Ctrl+C.

   Or use the terminal:

   ```bash
   cd whatsapp-mcp-server
   uv run admin.py init                      # creates ~/.config/whatsapp-mcp/access.json (deny all)
   uv run admin.py discover --query family   # find the exact JID of a chat
   uv run admin.py allow --jid 120363000000000000@g.us          # read only
   uv run admin.py allow --jid 15551234567@s.whatsapp.net --send # read + send
   uv run admin.py list
   ```

4. **Connect to the MCP server**

   Copy the below json with the appropriate {{PATH}} values:

   ```json
   {
     "mcpServers": {
       "whatsapp": {
         "command": "{{PATH_TO_UV}}", // Run `which uv` and place the output here
         "args": [
           "--directory",
           "{{PATH_TO_SRC}}/whatsapp-mcp/whatsapp-mcp-server", // cd into the repo, run `pwd` and enter the output here + "/whatsapp-mcp-server"
           "run",
           "main.py"
         ]
       }
     }
   }
   ```

   For **Claude**, save this as `claude_desktop_config.json` in your Claude Desktop configuration directory at:

   ```
   ~/Library/Application Support/Claude/claude_desktop_config.json
   ```

   For **Cursor**, save this as `mcp.json` in your Cursor configuration directory at:

   ```
   ~/.cursor/mcp.json
   ```

5. **Restart Claude Desktop / Cursor**

   Open Claude Desktop and you should now see WhatsApp as an available integration.

   Or restart Cursor.

### Windows Compatibility

If you're running this project on Windows, be aware that `go-sqlite3` requires **CGO to be enabled** in order to compile and work properly. By default, **CGO is disabled on Windows**, so you need to explicitly enable it and have a C compiler installed.

#### Steps to get it working:

1. **Install a C compiler**  
   We recommend using [MSYS2](https://www.msys2.org/) to install a C compiler for Windows. After installing MSYS2, make sure to add the `ucrt64\bin` folder to your `PATH`.  
   → A step-by-step guide is available [here](https://code.visualstudio.com/docs/cpp/config-mingw).

2. **Enable CGO and run the app**

   ```bash
   cd whatsapp-bridge
   go env -w CGO_ENABLED=1
   go run .
   ```

Without this setup, you'll likely run into errors like:

> `Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to work.`

## Scoped Access

**What this protects.** It filters what the *assistant* can reach. WhatsApp has no per-chat device linking. The bridge is a linked device that syncs your whole account. This fork guarantees that the MCP tools expose only the chats you choose.

**Default deny.** The policy file is `~/.config/whatsapp-mcp/access.json` (or `$WHATSAPP_MCP_POLICY`). It lists chats by exact JID, never by display name. Each chat gets `read`, `send` or both. Any chat not on the list is invisible, including chats synced later. A missing or invalid file denies everything.

**Read-only by default.** `admin.py allow` grants `read`. Add `--send` to allow outbound messages to that chat. Sending files also needs an outbox folder. Set `WHATSAPP_MCP_OUTBOX` and only files inside it can be sent. Your MCP host's per-call approval for send tools is a good extra layer. This server does not provide that layer.

**Changes are immediate.** The policy is re-read on every tool call. `admin.py revoke --jid …` takes effect on the next call, with no restart. It also deletes media you had exported from that chat.

**The assistant cannot change access.** Admin commands and the admin page are not MCP tools. The server only reads the policy. In the CLI, granting access needs a typed `yes` in an interactive terminal. The admin page runs only while you keep `admin.py gui` open, and only the link with its one-time token works.

**Prompt injection.** Anyone in an allowed group can write messages aimed at the assistant. Tools return messages as data and cannot change access. The assistant can still be misled within its allowed scope. Treat chat content as untrusted, and keep `send` off where you don't need it.

### Isolating the bridge

The checks in the MCP server protect you when the assistant only has MCP tools. If the assistant also has a shell or a network tool on the same machine, it could skip the MCP server. It could read `whatsapp-bridge/store/` or call the bridge API. Close those paths:

1. **Loopback only.** The bridge now listens on `127.0.0.1:8080` by default. Never expose it with `WHATSAPP_BRIDGE_ADDR=0.0.0.0:…`.
2. **Bridge enforcement.** Start the bridge with the same policy and a shared token. Pass the token to the MCP server:

   ```bash
   cd whatsapp-bridge
   WHATSAPP_POLICY_FILE=~/.config/whatsapp-mcp/access.json WHATSAPP_BRIDGE_TOKEN=<random> go run .
   ```

   ```json
   "env": { "WHATSAPP_BRIDGE_TOKEN": "<random>", "WHATSAPP_MCP_OUTBOX": "/Users/you/whatsapp-outbox" }
   ```

3. **Filtered database.** Run the projector. It writes a copy that holds only allowed chats. Point the MCP server at that copy:

   ```bash
   cd whatsapp-mcp-server
   uv run projector.py --source ../whatsapp-bridge/store/messages.db \
       --dest ~/.local/share/whatsapp-mcp/projection.db --watch 30
   ```

   Then set `"WHATSAPP_MCP_DB": "~/.local/share/whatsapp-mcp/projection.db"` in the MCP server env. When you revoke, set `WHATSAPP_MCP_PROJECTION` to the same path so `admin.py revoke` prunes the copy at once. For full isolation, run the MCP server as a separate macOS user, or in a container, that cannot read `whatsapp-bridge/store/`.

Do not use privileged containers, host networking or broad volume mounts. The MCP server needs only:

- the policy file (read-only)
- the message DB or projection (read-only)
- the outbox
- the media export folder

### Configuration

| Variable | Used by | Default |
| --- | --- | --- |
| `WHATSAPP_MCP_POLICY` | MCP server, admin | `~/.config/whatsapp-mcp/access.json` |
| `WHATSAPP_MCP_DB` | MCP server | `whatsapp-bridge/store/messages.db` |
| `WHATSAPP_MCP_OUTBOX` | MCP server | unset (file sending off) |
| `WHATSAPP_MCP_MEDIA_DIR` | MCP server, admin | `~/.local/share/whatsapp-mcp/media` |
| `WHATSAPP_MCP_PROJECTION` | admin (`revoke`) | unset |
| `WHATSAPP_API_BASE_URL` | MCP server | `http://127.0.0.1:8080/api` |
| `WHATSAPP_BRIDGE_TOKEN` | MCP server, bridge | unset (no token) |
| `WHATSAPP_BRIDGE_MEDIA_DIR` | MCP server, bridge | `whatsapp-bridge/store` |
| `WHATSAPP_POLICY_FILE` | bridge | unset (bridge trusts its caller) |
| `WHATSAPP_BRIDGE_ADDR` | bridge | `127.0.0.1:8080` |
| `WHATSAPP_BRIDGE_DB` | admin (`discover`) | `whatsapp-bridge/store/messages.db` |

### Verifying

```bash
cd whatsapp-mcp-server && uv run pytest -q   # policy, scoped reads/writes, media, revocation, MCP discovery
cd whatsapp-bridge && go test ./...          # bridge policy, token, path sanitising
uv run admin.py check                        # validate your policy file
```

The tests use a small fixture store and a mock bridge. They never read your real messages. For a manual check without sharing chat content:

1. Allow one test group.
2. Ask the assistant to `list_chats`. Confirm only that group appears.
3. Revoke the group. Confirm it disappears on the next call.

## Architecture Overview

This application consists of two main components:

1. **Go WhatsApp Bridge** (`whatsapp-bridge/`): A Go application that connects to WhatsApp's web API, handles authentication via QR code, and stores message history in SQLite. It serves as the bridge between WhatsApp and the MCP server.

2. **Python MCP Server** (`whatsapp-mcp-server/`): A Python server implementing the Model Context Protocol (MCP), which provides standardized tools for Claude to interact with WhatsApp data and send/receive messages.

### Data Storage

- All message history is stored in a SQLite database within the `whatsapp-bridge/store/` directory
- The database maintains tables for chats and messages
- Messages are indexed for efficient searching and retrieval

## Usage

Once connected, you can interact with your WhatsApp contacts through Claude, leveraging Claude's AI capabilities in your WhatsApp conversations.

### MCP Tools

Claude can access the following tools. Every tool is limited to the chats in your access policy:

- **list_messages**: Retrieve messages from allowed chats with optional filters and context
- **list_chats**: List allowed chats with metadata
- **get_chat**: Get information about an allowed chat
- **get_direct_chat_by_contact**: Find an allowed direct chat by exact phone number
- **get_contact_chats**: List allowed chats involving a specific contact
- **get_last_interaction**: Get the most recent message in an allowed chat (takes `chat_jid`)
- **get_message_context**: Retrieve context around a message (takes `message_id` **and** `chat_jid`)
- **send_message**: Send a message to a chat allowed with `send`
- **send_file**: Send a file from the outbox folder to a chat allowed with `send`
- **send_audio_message**: Send an outbox audio file as a voice message (requires an .ogg opus file or ffmpeg)
- **download_media**: Download media from a message in an allowed chat and get a local file path

`search_contacts` was removed: your full contact list is outside any chat scope.

### Media Handling Features

The MCP server supports both sending and receiving various media types:

#### Media Sending

You can send various media types to your WhatsApp contacts:

- **Images, Videos, Documents**: Use the `send_file` tool to share any supported media type.
- **Voice Messages**: Use the `send_audio_message` tool to send audio files as playable WhatsApp voice messages.
  - For optimal compatibility, audio files should be in `.ogg` Opus format.
  - With FFmpeg installed, the system will automatically convert other audio formats (MP3, WAV, etc.) to the required format.
  - Without FFmpeg, you can still send raw audio files using the `send_file` tool, but they won't appear as playable voice messages.

#### Media Downloading

By default, just the metadata of the media is stored in the local database. The message will indicate that media was sent. To access this media you need to use the download_media tool which takes the `message_id` and `chat_jid` (which are shown when printing messages containing the meda), this downloads the media and then returns the file path which can be then opened or passed to another tool.

## Technical Details

1. Claude sends requests to the Python MCP server
2. The MCP server queries the Go bridge for WhatsApp data or directly to the SQLite database
3. The Go accesses the WhatsApp API and keeps the SQLite database up to date
4. Data flows back through the chain to Claude
5. When sending messages, the request flows from Claude through the MCP server to the Go bridge and to WhatsApp

## Troubleshooting

- If you encounter permission issues when running uv, you may need to add it to your PATH or use the full path to the executable.
- Make sure both the Go application and the Python server are running for the integration to work properly.

### Authentication Issues

- **QR Code Not Displaying**: If the QR code doesn't appear, try restarting the authentication script. If issues persist, check if your terminal supports displaying QR codes.
- **WhatsApp Already Logged In**: If your session is already active, the Go bridge will automatically reconnect without showing a QR code.
- **Device Limit Reached**: WhatsApp limits the number of linked devices. If you reach this limit, you'll need to remove an existing device from WhatsApp on your phone (Settings > Linked Devices).
- **No Messages Loading**: After initial authentication, it can take several minutes for your message history to load, especially if you have many chats.
- **WhatsApp Out of Sync**: If your WhatsApp messages get out of sync with the bridge, delete both database files (`whatsapp-bridge/store/messages.db` and `whatsapp-bridge/store/whatsapp.db`) and restart the bridge to re-authenticate.

For additional Claude Desktop integration troubleshooting, see the [MCP documentation](https://modelcontextprotocol.io/quickstart/server#claude-for-desktop-integration-issues). The documentation includes helpful tips for checking logs and resolving common issues.
