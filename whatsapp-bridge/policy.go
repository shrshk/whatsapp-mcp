package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// Same rules as whatsapp-mcp-server/access_policy.py. The bridge enforces the
// policy on /api/send and /api/download when WHATSAPP_POLICY_FILE is set, so a
// process that reaches the bridge directly still cannot leave the allowlist.

var (
	chatJIDPattern = regexp.MustCompile(`^[0-9]{1,32}(-[0-9]{1,32})?@(s\.whatsapp\.net|g\.us|lid)$`)
	phonePattern   = regexp.MustCompile(`^[0-9]{5,20}$`)
	unsafeChars    = regexp.MustCompile(`[^A-Za-z0-9@._-]`)
)

type policyEntry struct {
	JID         string   `json:"jid"`
	Permissions []string `json:"permissions"`
	Label       string   `json:"label,omitempty"`
}

type policyFile struct {
	Version int           `json:"version"`
	Default string        `json:"default"`
	Chats   []policyEntry `json:"chats"`
}

type accessPolicy struct {
	chats map[string]map[string]bool
}

// canonicalChatJID returns the trimmed JID if it is a well-formed chat JID.
func canonicalChatJID(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if !chatJIDPattern.MatchString(value) {
		return "", false
	}
	return value, true
}

// recipientJID maps a send recipient to a chat JID; a bare phone number maps to
// exactly <digits>@s.whatsapp.net.
func recipientJID(recipient string) (string, bool) {
	recipient = strings.TrimSpace(recipient)
	if phonePattern.MatchString(recipient) {
		return recipient + "@s.whatsapp.net", true
	}
	return canonicalChatJID(recipient)
}

func parsePolicy(data []byte) (*accessPolicy, error) {
	var doc policyFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("invalid policy JSON")
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version")
	}
	if doc.Default != "deny" {
		return nil, fmt.Errorf("policy must set default to deny")
	}
	p := &accessPolicy{chats: map[string]map[string]bool{}}
	for i, entry := range doc.Chats {
		jid, ok := canonicalChatJID(entry.JID)
		if !ok {
			return nil, fmt.Errorf("chats[%d].jid is not a valid chat JID", i)
		}
		if _, dup := p.chats[jid]; dup {
			return nil, fmt.Errorf("chats[%d].jid is duplicated", i)
		}
		if len(entry.Permissions) == 0 {
			return nil, fmt.Errorf("chats[%d].permissions must be non-empty", i)
		}
		perms := map[string]bool{}
		for _, perm := range entry.Permissions {
			if perm != "read" && perm != "send" {
				return nil, fmt.Errorf("chats[%d].permissions has unknown values", i)
			}
			perms[perm] = true
		}
		p.chats[jid] = perms
	}
	return p, nil
}

func (p *accessPolicy) allows(jid, permission string) bool {
	if p == nil {
		return false
	}
	return p.chats[jid][permission]
}

// currentPolicy reloads the policy on every request. It returns (nil, true)
// when enforcement is off, and (nil, false) when enforcement is on but the
// policy cannot be loaded: callers must then deny.
func currentPolicy() (*accessPolicy, bool) {
	path := os.Getenv("WHATSAPP_POLICY_FILE")
	if path == "" {
		return nil, true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Access policy unreadable; denying bridge request")
		return nil, false
	}
	p, err := parsePolicy(data)
	if err != nil {
		fmt.Printf("Access policy invalid (%v); denying bridge request\n", err)
		return nil, false
	}
	return p, true
}

// authorizeChat reports whether the bridge may act on jid with permission.
func authorizeChat(jid, permission string) bool {
	p, ok := currentPolicy()
	if !ok {
		return false
	}
	if p == nil {
		return true // enforcement disabled
	}
	return p.allows(jid, permission)
}

// requireToken wraps a handler with a bearer-token check when
// WHATSAPP_BRIDGE_TOKEN is set.
func requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := os.Getenv("WHATSAPP_BRIDGE_TOKEN")
		if token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

// safeName turns a value into a single safe path component.
func safeName(value string) string {
	cleaned := unsafeChars.ReplaceAllString(value, "_")
	if cleaned == "" || cleaned == "." || cleaned == ".." {
		return "_"
	}
	return cleaned
}

// mediaRoot is where downloaded media is written, one folder per chat.
func mediaRoot() string {
	if dir := os.Getenv("WHATSAPP_BRIDGE_MEDIA_DIR"); dir != "" {
		return dir
	}
	return "store"
}

// listenAddr defaults to loopback so the bridge is never reachable from the network.
func listenAddr(port int) string {
	if addr := os.Getenv("WHATSAPP_BRIDGE_ADDR"); addr != "" {
		return addr
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}
