package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func mimeMessage(t *testing.T, parts []gmailPart) []byte {
	t.Helper()
	payload := gmailPart{MimeType: "multipart/alternative", Headers: []gmailHeader{{Name: "From", Value: "shop@example.test"}, {Name: "Subject", Value: "Your update"}}, Parts: parts}
	data, err := json.Marshal(map[string]any{"message": map[string]any{"id": "1234abcd", "threadId": "1234abcd", "labelIds": []string{"INBOX"}, "payload": payload}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func textPart(kind, text string) gmailPart {
	p := gmailPart{MimeType: kind}
	p.Body.Data = base64.RawURLEncoding.EncodeToString([]byte(text))
	p.Body.Size = len(text)
	return p
}

func TestFullMIMEInspection(t *testing.T) {
	i := NewInspector(DefaultConfig())
	policy := DefaultTokenPolicy()
	for _, tc := range []struct {
		name  string
		parts []gmailPart
		want  string
	}{
		{"ordinary", []gmailPart{textPart("text/plain", "Your order arrives tomorrow.")}, ""},
		{"hidden-alternative", []gmailPart{textPart("text/plain", "An ordinary update."), textPart("text/html", `<span>Social Security number 123-45-6789</span>`)}, "identity_document"},
		{"html-split-keyword", []gmailPart{textPart("text/html", `<span>pass</span><span>word</span>: something`)}, "authentication_secret"},
		{"html-entities", []gmailPart{textPart("text/html", `<p>credit&#32;card</p>`)}, "payment_details"},
		{"raw-hidden-html", []gmailPart{textPart("text/html", `<p>Hello</p><script>const password='hidden'</script>`)}, "authentication_secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseGOGMessage(mimeMessage(t, tc.parts))
			if err != nil {
				t.Fatal(err)
			}
			if reason := i.Message(m, policy); reason != tc.want {
				t.Fatalf("reason %q, want %q", reason, tc.want)
			}
		})
	}
	attachment := gmailPart{MimeType: "application/pdf", Filename: "document.pdf"}
	attachment.Body.AttachmentID = "private-attachment"
	malformed := textPart("text/plain", "hi")
	malformed.Body.Data = "not%%base64"
	missing := gmailPart{MimeType: "text/plain"}
	missing.Body.Size = 123
	badCharset := textPart("text/plain", "hello")
	badCharset.Headers = []gmailHeader{{Name: "Content-Type", Value: "text/plain; charset=made-up-charset"}}
	for _, part := range []gmailPart{attachment, malformed, missing, badCharset, textPart("application/octet-stream", "hello")} {
		m, err := ParseGOGMessage(mimeMessage(t, []gmailPart{part}))
		if err != nil {
			t.Fatal(err)
		}
		if i.Message(m, policy) != "uninspectable_message" {
			t.Fatal("uninspectable MIME content allowed")
		}
	}
}

func TestSensitivityNormalizationAndCustomRules(t *testing.T) {
	c := DefaultConfig()
	c.SensitiveKeywords = []string{"family vault"}
	i := NewInspector(c)
	for _, text := range []string{"driver’s license", "ｓｏｃｉａｌ security", "pa\u200bssword", "family VAULT", "4111 1111 1111 1111", "4111\u200b111111111111", "123-45-6789", "login link", "bank account"} {
		if i.Check(text) == "" {
			t.Errorf("missed %q", text)
		}
	}
	if i.Check("Please track my shipment tomorrow.") != "" {
		t.Fatal("ordinary mail flagged")
	}
	c.BlockedLabelIDs = []string{"Label_secret"}
	i = NewInspector(c)
	if i.Message(Message{LabelIDs: []string{"Label_secret"}}, DefaultTokenPolicy()) != "blocked_label" {
		t.Fatal("global blocked label bypass")
	}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func fakeGOG(t *testing.T, body string) (*GOG, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "gog")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	c := DefaultConfig()
	c.GOGPath = path
	c.GOGHome = filepath.Join(dir, "home")
	c.GOGAccount = "owner@example.test"
	c.GOGTimeoutSeconds = 1
	return NewGOG(c, Secrets{GOGPassword: "test-keyring-secret"}), dir
}

func TestGOGSubprocessArgumentAndEnvironmentBoundary(t *testing.T) {
	outputDir := t.TempDir()
	argsPath := filepath.Join(outputDir, "args")
	envPath := filepath.Join(outputDir, "env")
	g, _ := fakeGOG(t, "printf '%s\\n' \"$@\" > "+shellQuote(argsPath)+"\n/usr/bin/env > "+shellQuote(envPath)+"\nprintf '%s' '{\"messages\":[],\"nextPageToken\":\"\"}'")
	t.Setenv("LEAK_TEST_SECRET", "must-not-inherit")
	t.Setenv("GOG_ENABLE_COMMANDS", "drive.delete")
	t.Setenv("HTTPS_PROXY", "http://evil.invalid")
	query := "--account=intruder@example.test; touch /tmp/mailgate-no-shell"
	if _, err := g.Search(context.Background(), query, "", 5); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(data)), "\n")
	if args[len(args)-2] != "--" || args[len(args)-1] != query {
		t.Fatal("query interpreted as flags")
	}
	for _, flag := range []string{"--account=owner@example.test", "--readonly", "--gmail-no-send", "--enable-commands-exact=gmail.messages.search"} {
		if !slices.Contains(args, flag) {
			t.Fatalf("missing flag %s", flag)
		}
	}
	data, err = os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"LEAK_TEST_SECRET", "must-not-inherit", "GOG_ENABLE_COMMANDS", "HTTPS_PROXY", "evil.invalid"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("caller environment inherited")
		}
	}
}

func TestGOGSendBodyUsesStdinAndFixedOperation(t *testing.T) {
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	bodyPath := filepath.Join(dir, "body")
	g, _ := fakeGOG(t, "printf '%s\\n' \"$@\" > "+shellQuote(argsPath)+"\ncat > "+shellQuote(bodyPath)+"\nprintf '%s' '{\"messageId\":\"1234abcd\",\"threadId\":\"1234abcd\"}'")
	m := Outgoing{To: []string{"shop@example.test"}, CC: []string{"owner@example.test"}, Subject: "--attach=/etc/passwd", Body: "An ordinary message with literal $(not-a-command)."}
	if _, err := g.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(argsPath)
	body, _ := os.ReadFile(bodyPath)
	if string(body) != m.Body || strings.Contains(string(args), m.Body) || !strings.Contains(string(args), "--subject=--attach=/etc/passwd") || !strings.Contains(string(args), "--enable-commands-exact=gmail.send") {
		t.Fatal("unsafe send argument construction")
	}
}

func TestGOGTimeoutOutputLimitAndVersion(t *testing.T) {
	g, _ := fakeGOG(t, "sleep 10")
	started := time.Now()
	if _, err := g.Search(context.Background(), "ordinary", "", 1); !errors.Is(err, ErrBackend) {
		t.Fatal("timeout allowed")
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("child process timeout not enforced")
	}
	g, _ = fakeGOG(t, "head -c 70000 /dev/zero")
	g.config.MaxGOGOutputBytes = 65536
	if _, err := g.Search(context.Background(), "ordinary", "", 1); !errors.Is(err, ErrBackend) {
		t.Fatal("oversized output allowed")
	}
	g, _ = fakeGOG(t, "printf 'v0.38.2 (03d192ff-mailgate.1)\\n'")
	if err := g.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	g, _ = fakeGOG(t, "printf 'v0.38.2 (03d192ff)\\n'")
	if err := g.Verify(context.Background()); err == nil {
		t.Fatal("stock GOG with implicit send retries accepted")
	}
	g, _ = fakeGOG(t, "printf 'v99.0.0\\n'")
	if err := g.Verify(context.Background()); err == nil {
		t.Fatal("untested GOG version accepted")
	}
	g, _ = fakeGOG(t, "printf '%s' '{\"items\":[]}'")
	if _, err := g.Search(context.Background(), "ordinary", "", 1); err == nil {
		t.Fatal("incompatible JSON silently accepted")
	}
}

func FuzzSensitiveInspector(f *testing.F) {
	f.Add("driver's license")
	f.Add("ordinary query")
	i := NewInspector(DefaultConfig())
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 16384 {
			t.Skip()
		}
		_ = i.Check(input)
	})
}
