package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const testPolicy = `{"version": 1, "default": "deny", "chats": [
  {"jid": "120363000000000001@g.us", "permissions": ["read"]},
  {"jid": "15550000002@s.whatsapp.net", "permissions": ["read", "send"], "label": "Bob"}
]}`

func TestParsePolicy(t *testing.T) {
	p, err := parsePolicy([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		jid, perm string
		want      bool
	}{
		{"120363000000000001@g.us", "read", true},
		{"120363000000000001@g.us", "send", false},
		{"15550000002@s.whatsapp.net", "send", true},
		{"120363000000000003@g.us", "read", false},
		{"*", "read", false},
	}
	for _, c := range cases {
		if got := p.allows(c.jid, c.perm); got != c.want {
			t.Errorf("allows(%q, %q) = %v, want %v", c.jid, c.perm, got, c.want)
		}
	}
}

func TestParsePolicyRejectsInvalid(t *testing.T) {
	bad := []string{
		`{`,
		`{"version": 2, "default": "deny", "chats": []}`,
		`{"version": 1, "default": "allow", "chats": []}`,
		`{"version": 1, "default": "deny", "chats": [], "extra": 1}`,
		`{"version": 1, "default": "deny", "chats": [{"jid": "*", "permissions": ["read"]}]}`,
		`{"version": 1, "default": "deny", "chats": [{"jid": "1@g.us", "permissions": []}]}`,
		`{"version": 1, "default": "deny", "chats": [{"jid": "1@g.us", "permissions": ["admin"]}]}`,
		`{"version": 1, "default": "deny", "chats": [{"jid": "1@g.us", "permissions": ["read"]}, {"jid": "1@g.us", "permissions": ["send"]}]}`,
	}
	for _, doc := range bad {
		if _, err := parsePolicy([]byte(doc)); err == nil {
			t.Errorf("expected error for %s", doc)
		}
	}
}

func TestRecipientJID(t *testing.T) {
	if jid, ok := recipientJID("15550000002"); !ok || jid != "15550000002@s.whatsapp.net" {
		t.Errorf("phone mapping: %q %v", jid, ok)
	}
	for _, bad := range []string{"", "+1555", "15550000002:3@s.whatsapp.net", "x@g.us", "status@broadcast"} {
		if _, ok := recipientJID(bad); ok {
			t.Errorf("recipientJID(%q) should fail", bad)
		}
	}
}

func TestAuthorizeChatFailsClosed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WHATSAPP_POLICY_FILE", filepath.Join(dir, "missing.json"))
	if authorizeChat("15550000002@s.whatsapp.net", "send") {
		t.Error("missing policy must deny")
	}
	path := filepath.Join(dir, "access.json")
	os.WriteFile(path, []byte("{broken"), 0600)
	t.Setenv("WHATSAPP_POLICY_FILE", path)
	if authorizeChat("15550000002@s.whatsapp.net", "send") {
		t.Error("invalid policy must deny")
	}
	os.WriteFile(path, []byte(testPolicy), 0600)
	if !authorizeChat("15550000002@s.whatsapp.net", "send") {
		t.Error("allowed send denied")
	}
	if authorizeChat("120363000000000001@g.us", "send") {
		t.Error("read-only chat allowed to send")
	}
	// Revocation applies to the next request.
	os.WriteFile(path, []byte(`{"version": 1, "default": "deny", "chats": []}`), 0600)
	if authorizeChat("15550000002@s.whatsapp.net", "send") {
		t.Error("revoked chat still allowed")
	}
}

func TestRequireToken(t *testing.T) {
	handler := requireToken(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	t.Setenv("WHATSAPP_BRIDGE_TOKEN", "secret")
	for header, want := range map[string]int{"": 401, "Bearer wrong": 401, "secret": 200, "Bearer secret": 200} {
		req := httptest.NewRequest(http.MethodPost, "/api/send", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != want {
			t.Errorf("Authorization %q: got %d, want %d", header, rec.Code, want)
		}
	}
}

func TestSafeName(t *testing.T) {
	cases := map[string]string{
		"../../whatsapp.db":       ".._.._whatsapp.db",
		"..":                      "_",
		"":                        "_",
		"report.pdf":              "report.pdf",
		"120363000000000001@g.us": "120363000000000001@g.us",
		"a/b\\c:d":                "a_b_c_d",
	}
	for in, want := range cases {
		if got := safeName(in); got != want {
			t.Errorf("safeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestListenAddrDefaultsToLoopback(t *testing.T) {
	t.Setenv("WHATSAPP_BRIDGE_ADDR", "")
	if got := listenAddr(8080); got != "127.0.0.1:8080" {
		t.Errorf("listenAddr = %q", got)
	}
}
