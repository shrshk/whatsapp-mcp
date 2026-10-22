"""Local web GUI for choosing which chats the assistant may use.

Started by ``admin.py gui``. Like the CLI, it is an admin tool for the human
at the keyboard and is never exposed through MCP. Safeguards:

- binds 127.0.0.1 on a random port and runs only while the command runs;
- every request needs a per-launch random token (printed in the terminal and
  carried in the URL the browser opens);
- the Host header must be the loopback address (blocks DNS rebinding) and
  writes must come from the page's own Origin with a JSON body;
- a strict Content-Security-Policy; chat names (written by other people) are
  rendered as text, never HTML;
- writes go through the same validated, atomic path as the CLI, and revoking
  runs the same cleanup.
"""

import json
import secrets
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

import admin
from access_policy import PERMISSIONS, PolicyError, canonical_jid, parse_policy

MAX_BODY = 4096
MAX_CHATS = 10000


class AdminGUI:
    def __init__(self, policy_path: Path, port: int = 0):
        self.policy_path = policy_path
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(self))
        self.port = self.httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/?token={self.token}"

    @property
    def allowed_hosts(self) -> set:
        return {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}

    @property
    def allowed_origins(self) -> set:
        return {f"http://{h}" for h in self.allowed_hosts}

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def shutdown(self) -> None:
        """Stop a server running serve_forever() in another thread."""
        self.httpd.shutdown()
        self.close()

    def close(self) -> None:
        """Release the socket once serve_forever() has returned."""
        self.httpd.server_close()

    # -- data -------------------------------------------------------------

    def _load_document(self) -> Dict[str, Any]:
        if not self.policy_path.exists():
            return admin._empty_policy()
        try:
            return admin.read_policy_document(self.policy_path)
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise PolicyError(f"not valid JSON: {type(e).__name__}") from e

    def chats(self) -> Dict[str, Any]:
        try:
            doc = self._load_document()
            policy_error = None
        except (OSError, ValueError, PolicyError) as e:
            doc, policy_error = admin._empty_policy(), f"{type(e).__name__}: {e}"
        perms = {c["jid"]: sorted(c["permissions"]) for c in doc["chats"]}
        try:
            rows = admin._full_store_rows(None, MAX_CHATS)
            store_error = None
        except sqlite3.Error as e:
            rows, store_error = [], f"Cannot open the message store: {type(e).__name__}"
        seen = set()
        chats: List[Dict[str, Any]] = []
        for jid, name, last in rows:
            seen.add(jid)
            chats.append({
                "jid": jid,
                "name": name or "",
                "kind": "group" if jid.endswith("@g.us") else "dm",
                "last_active": str(last)[:16] if last else None,
                "permissions": perms.get(jid, []),
                "allowable": canonical_jid(jid) == jid,
            })
        # Allowed JIDs that are not (yet) in the store still need a revoke button.
        for jid, p in perms.items():
            if jid not in seen:
                chats.append({"jid": jid, "name": "", "kind": "group" if jid.endswith("@g.us") else "dm",
                              "last_active": None, "permissions": p, "allowable": True})
        return {
            "policy_path": str(self.policy_path),
            "policy_error": policy_error,
            "store_error": store_error,
            "chats": chats,
        }

    def set_permissions(self, jid: Any, permissions: Any) -> Dict[str, Any]:
        jid = canonical_jid(jid)
        if jid is None:
            raise ValueError("Not a valid chat JID")
        if not isinstance(permissions, list) or set(permissions) - PERMISSIONS:
            raise ValueError("permissions must be a list of 'read' and/or 'send'")
        perms = [p for p in ("read", "send") if p in permissions]
        with self.lock:
            doc = self._load_document()  # refuses to overwrite an invalid file
            current = {c["jid"]: c for c in doc["chats"]}
            if not perms:
                new = admin.remove_chat(doc, jid)
                admin.write_policy_document(self.policy_path, new)
                admin.revoke_cleanup(jid, parse_policy(new))
            else:
                if jid not in current and not admin._chat_exists(jid):
                    raise ValueError("That JID is not in the local store")
                label = current.get(jid, {}).get("label")
                admin.write_policy_document(self.policy_path, admin.set_chat(doc, jid, perms, label))
        return {"jid": jid, "permissions": perms}


def _make_handler(gui: AdminGUI):
    class Handler(BaseHTTPRequestHandler):
        server_version = "whatsapp-mcp-admin"
        sys_version = ""

        def log_message(self, format, *args):  # noqa: A002 - stdlib signature
            pass  # request lines would contain JIDs

        def _send(self, status: int, body: bytes, content_type: str, nonce: Optional[str] = None) -> None:
            src = f"'nonce-{nonce}'" if nonce else "'none'"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                f"default-src 'none'; script-src {src}; style-src {src}; connect-src 'self'; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, data: Any) -> None:
            self._send(status, json.dumps(data).encode(), "application/json")

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in gui.allowed_hosts

        def _token_ok(self, token: Optional[str]) -> bool:
            return bool(token) and secrets.compare_digest(token, gui.token)

        def do_GET(self) -> None:
            if not self._host_ok():
                return self._json(403, {"error": "forbidden"})
            url = urlparse(self.path)
            if url.path == "/":
                token = parse_qs(url.query).get("token", [None])[0]
                if not self._token_ok(token):
                    return self._send(403, b"Open the link printed in your terminal.", "text/plain; charset=utf-8")
                nonce = secrets.token_urlsafe(16)
                return self._send(200, PAGE.replace("__NONCE__", nonce).encode(), "text/html; charset=utf-8", nonce)
            if url.path == "/api/chats":
                if not self._token_ok(self.headers.get("X-Admin-Token")):
                    return self._json(403, {"error": "forbidden"})
                return self._json(200, gui.chats())
            return self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if not self._host_ok() or self.headers.get("Origin") not in gui.allowed_origins:
                return self._json(403, {"error": "forbidden"})
            if not self._token_ok(self.headers.get("X-Admin-Token")):
                return self._json(403, {"error": "forbidden"})
            if urlparse(self.path).path != "/api/chat":
                return self._json(404, {"error": "not found"})
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                return self._json(415, {"error": "JSON body required"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                return self._json(413, {"error": "body too large"})
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("JSON object required")
                return self._json(200, gui.set_permissions(body.get("jid"), body.get("permissions")))
            except PolicyError as e:
                return self._json(409, {"error": f"Policy file is invalid; fix it first ({e})"})
            except (ValueError, json.JSONDecodeError) as e:
                return self._json(400, {"error": str(e)})
            except OSError as e:
                return self._json(500, {"error": f"Could not write the policy: {type(e).__name__}"})

    return Handler


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WhatsApp Access</title>
<style nonce="__NONCE__">
:root {
  --bg: #f6f7f5; --surface: #ffffff; --text: #1b1f1c; --muted: #5d665f; --line: #e1e5e0;
  --accent: #1f8a5b; --accent-ink: #ffffff; --warn: #a15c00; --warn-bg: #fff4e0; --danger: #b3261e;
  --focus: #1f8a5b55;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #111412; --surface: #1a1e1b; --text: #e6ebe7; --muted: #9aa59d; --line: #2c322e;
    --accent: #3fbf85; --accent-ink: #0b1a12; --warn: #f0b45a; --warn-bg: #2e2412; --danger: #ff8a80;
    --focus: #3fbf8555;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
main { max-width: 860px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { font-size: 22px; margin: 0 0 4px; }
.sub { color: var(--muted); margin: 0 0 20px; font-size: 13px; word-break: break-all; }
.note { background: var(--warn-bg); color: var(--warn); border-radius: 10px; padding: 10px 14px;
  margin: 0 0 16px; font-size: 14px; }
.controls { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; position: sticky; top: 0;
  background: var(--bg); padding: 8px 0; z-index: 1; }
input[type=search] { flex: 1 1 220px; min-width: 0; padding: 9px 12px; border-radius: 10px;
  border: 1px solid var(--line); background: var(--surface); color: var(--text); font: inherit; }
input[type=search]:focus { outline: 3px solid var(--focus); border-color: var(--accent); }
.seg { display: inline-flex; border: 1px solid var(--line); border-radius: 10px; overflow: hidden;
  background: var(--surface); }
.seg button { border: 0; background: none; color: var(--muted); padding: 8px 12px; font: inherit; cursor: pointer; }
.seg button[aria-pressed=true] { background: var(--accent); color: var(--accent-ink); }
.summary { color: var(--muted); font-size: 13px; margin: 0 0 8px; }
ul { list-style: none; margin: 0; padding: 0; background: var(--surface); border: 1px solid var(--line);
  border-radius: 12px; overflow: hidden; }
li { display: flex; align-items: center; gap: 12px; padding: 12px 14px; border-top: 1px solid var(--line);
  flex-wrap: wrap; }
li:first-child { border-top: 0; }
li.on { box-shadow: inset 3px 0 0 var(--accent); }
.who { flex: 1 1 260px; min-width: 0; }
.name { font-weight: 600; overflow-wrap: anywhere; }
.name.empty { color: var(--muted); font-weight: 400; font-style: italic; }
.meta { color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
.tag { display: inline-block; font-size: 11px; padding: 1px 7px; border-radius: 999px;
  border: 1px solid var(--line); margin-right: 6px; color: var(--muted); }
.perms { display: flex; gap: 16px; }
label.sw { display: inline-flex; align-items: center; gap: 6px; cursor: pointer; user-select: none; font-size: 14px; }
label.sw input { appearance: none; width: 36px; height: 20px; border-radius: 999px; background: var(--line);
  position: relative; cursor: pointer; margin: 0; transition: background .15s; }
label.sw input::after { content: ""; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px;
  border-radius: 50%; background: var(--surface); transition: transform .15s; }
label.sw input:checked { background: var(--accent); }
label.sw input:checked::after { transform: translateX(16px); }
label.sw input:focus-visible { outline: 3px solid var(--focus); }
label.sw input:disabled { opacity: .4; cursor: not-allowed; }
.send-on { color: var(--warn); }
.empty-state { padding: 28px; text-align: center; color: var(--muted); }
#toast { position: fixed; left: 50%; bottom: 20px; transform: translateX(-50%); background: var(--text);
  color: var(--bg); padding: 10px 16px; border-radius: 10px; font-size: 14px; opacity: 0;
  transition: opacity .2s; pointer-events: none; max-width: calc(100% - 32px); }
#toast.show { opacity: 1; }
#toast.err { background: var(--danger); color: #fff; }
</style>
</head>
<body>
<main>
  <h1>WhatsApp Access</h1>
  <p class="sub" id="path">Loading…</p>
  <p class="note" id="problem" hidden></p>
  <p class="note">Everything starts denied. <strong>Read</strong> lets the assistant read a chat.
    <strong>Send</strong> lets it post as you. Changes save immediately and apply on the assistant's next call.</p>
  <div class="controls">
    <input type="search" id="q" placeholder="Search name or JID" aria-label="Search chats" autocomplete="off">
    <div class="seg" role="group" aria-label="Filter">
      <button data-f="all" aria-pressed="true">All</button>
      <button data-f="group" aria-pressed="false">Groups</button>
      <button data-f="dm" aria-pressed="false">Direct</button>
      <button data-f="allowed" aria-pressed="false">Allowed</button>
    </div>
  </div>
  <p class="summary" id="summary"></p>
  <ul id="list" aria-live="polite"></ul>
</main>
<div id="toast" role="status"></div>
<script nonce="__NONCE__">
(() => {
  // The token stays in the URL so a refresh keeps working; it is per-launch and
  // never sent elsewhere (Referrer-Policy: no-referrer, no external requests).
  const token = new URLSearchParams(location.search).get("token") || "";
  let chats = [], filter = "all", query = "";
  const $ = (id) => document.getElementById(id);

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;  // text only, never parsed as HTML: names come from other people
    return n;
  }

  let toastTimer;
  function toast(msg, err) {
    const t = $("toast");
    t.textContent = msg; t.className = "show" + (err ? " err" : "");
    clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.className = ""), 2600);
  }

  async function api(method, path, body) {
    const res = await fetch(path, {
      method, headers: { "X-Admin-Token": token, ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "HTTP " + res.status);
    return data;
  }

  function label(c) { return c.name || (c.kind === "group" ? "Unnamed group" : c.jid.split("@")[0]); }

  function matches(c) {
    if (filter === "allowed" && !c.permissions.length) return false;
    if ((filter === "group" || filter === "dm") && c.kind !== filter) return false;
    if (!query) return true;
    return c.name.toLowerCase().includes(query) || c.jid.includes(query);
  }

  function render() {
    const list = $("list");
    list.replaceChildren();
    const shown = chats.filter(matches);
    const allowed = chats.filter((c) => c.permissions.length).length;
    $("summary").textContent = `${allowed} allowed · showing ${shown.length} of ${chats.length} chats`;
    if (!shown.length) { list.append(el("li", "empty-state", "No chats match.")); return; }
    for (const c of shown.slice(0, 500)) list.append(row(c));
    if (shown.length > 500) list.append(el("li", "empty-state", "Showing the first 500. Refine your search."));
  }

  function row(c) {
    const li = el("li", c.permissions.length ? "on" : "");
    const who = el("div", "who");
    who.append(el("div", "name" + (c.name ? "" : " empty"), label(c)));
    const meta = el("div", "meta");
    meta.append(el("span", "tag", c.kind === "group" ? "group" : "direct"));
    meta.append(document.createTextNode(c.jid + (c.last_active ? " · active " + c.last_active : "")));
    who.append(meta);
    const perms = el("div", "perms");
    for (const p of ["read", "send"]) {
      const lab = el("label", "sw" + (p === "send" && c.permissions.includes("send") ? " send-on" : ""));
      const box = document.createElement("input");
      box.type = "checkbox"; box.role = "switch"; box.checked = c.permissions.includes(p);
      box.disabled = !c.allowable;
      box.setAttribute("aria-label", `${p} access for ${label(c)}`);
      box.addEventListener("change", () => toggle(c, p, box));
      lab.append(box, el("span", null, p === "read" ? "Read" : "Send"));
      perms.append(lab);
    }
    li.append(who, perms);
    return li;
  }

  async function toggle(c, p, box) {
    const next = new Set(c.permissions);
    box.checked ? next.add(p) : next.delete(p);
    if (p === "send" && box.checked &&
        !confirm(`Let the assistant send WhatsApp messages as you to "${label(c)}"?`)) {
      box.checked = false; return;
    }
    box.disabled = true;
    try {
      const res = await api("POST", "/api/chat", { jid: c.jid, permissions: [...next] });
      c.permissions = res.permissions;
      toast(res.permissions.length ? `${label(c)}: ${res.permissions.join(" + ")}` : `${label(c)}: access removed`);
    } catch (e) {
      toast(e.message, true);
    }
    render();
  }

  async function load() {
    try {
      const data = await api("GET", "/api/chats");
      chats = data.chats;
      $("path").textContent = "Policy: " + data.policy_path;
      const problem = data.policy_error || data.store_error;
      $("problem").hidden = !problem;
      $("problem").textContent = problem ? "Problem: " + problem : "";
      render();
    } catch (e) {
      $("path").textContent = "Could not load chats: " + e.message;
    }
  }

  $("q").addEventListener("input", (e) => { query = e.target.value.trim().toLowerCase(); render(); });
  document.querySelectorAll(".seg button").forEach((b) => b.addEventListener("click", () => {
    filter = b.dataset.f;
    document.querySelectorAll(".seg button").forEach((x) => x.setAttribute("aria-pressed", x === b));
    render();
  }));
  load();
})();
</script>
</body>
</html>
"""
