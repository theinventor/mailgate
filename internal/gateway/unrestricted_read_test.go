package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestUnrestrictedReadSearchReadAndPolicyChanges(t *testing.T) {
	a, s, f := testAPI(t)
	a.inspector = NewInspector(Config{BlockedLabelIDs: []string{"PRIVATE"}})
	restricted := DefaultTokenPolicy()
	_, restrictedRaw := issue(t, s, restricted)
	full := DefaultTokenPolicy()
	full.Scopes = append(full.Scopes, ScopeSend)
	full.UnrestrictedRead = true
	// Full read deliberately overrides mailbox restrictions as well as content rules.
	full.AllowedLabelIDs = []string{"OTHER"}
	full.AllowedSenders = []string{"someone@example.test"}
	token, raw := issue(t, s, full)
	f.messages = map[string]Message{
		"1234abcd": {ID: "1234abcd", From: "shop@example.test", Subject: "Your verification code", Body: "Example login code: 654321. We do not ask for credit card details.", LabelIDs: []string{"INBOX"}},
		"2234abcd": {ID: "2234abcd", From: "bank@example.test", Subject: "Account documents", Body: "Social Security number 123-45-6789", LabelIDs: []string{"PRIVATE"}},
		"3234abcd": {ID: "3234abcd", From: "shop@example.test", Subject: "Receipt attachment", Body: "The available plain-text receipt.", Uninspectable: true},
	}
	f.page = SearchPage{IDs: []string{"1234abcd", "2234abcd", "3234abcd"}}
	for _, query := range []string{"verification code", "newer_than:1d"} {
		body := mustJSON(t, map[string]any{"query": query})
		w := request(a, "POST", "/v1/messages/search", restrictedRaw, body, nil)
		wantStatus(t, w, 200)
		if strings.TrimSpace(w.Body.String()) != `{"messages":[]}` {
			t.Fatal("restricted search disclosed content")
		}
		w = request(a, "POST", "/v1/messages/search", raw, body, nil)
		wantStatus(t, w, 200)
		var result searchResponse
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Messages) != 3 {
			t.Fatal("full read search withheld messages")
		}
		for _, m := range result.Messages {
			if m.Body != "" || !m.Untrusted {
				t.Fatal("search body or trust boundary changed")
			}
		}
	}
	for id, m := range f.messages {
		wantStatus(t, request(a, "GET", "/v1/messages/"+id, restrictedRaw, "", nil), 404)
		w := request(a, "GET", "/v1/messages/"+id, raw, "", nil)
		wantStatus(t, w, 200)
		if !strings.Contains(w.Body.String(), m.Body) {
			t.Fatal("full read body withheld")
		}
	}
	wantStatus(t, request(a, "POST", "/v1/messages/search", restrictedRaw, `{"query":"verification code","unrestricted_read":true}`, nil), 400)
	wantStatus(t, request(a, "POST", "/v1/messages/send", raw, `{"to":["shop@example.test"],"subject":"Verification code","body":"Example code: 654321"}`, map[string]string{"Idempotency-Key": "example-send-operation-001"}), 403)
	if f.sends != 0 {
		t.Fatal("full read widened outbound permission")
	}
	events, err := s.Events(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	audit := mustJSON(t, events)
	if !strings.Contains(audit, `"unrestricted_read":true`) {
		t.Fatal("full read access not attributed in audit")
	}
	// Filtered-token alerts may now describe the phrase being searched, but
	// credential values and the actual protected numbers still stay private.
	for _, secret := range []string{raw, "654321", "123-45-6789"} {
		if strings.Contains(audit, secret) {
			t.Fatal("mail content or credential logged")
		}
	}
	full.UnrestrictedRead = false
	if err := s.UpdateToken(context.Background(), token.ID, token.Name, full, token.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, request(a, "GET", "/v1/messages/1234abcd", raw, "", nil), 404)
	full.UnrestrictedRead = true
	if err := s.UpdateToken(context.Background(), token.ID, token.Name, full, token.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, request(a, "GET", "/v1/messages/1234abcd", raw, "", nil), 200)
	if err := s.Revoke(context.Background(), token.ID); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, request(a, "GET", "/v1/messages/1234abcd", raw, "", nil), 401)
}

func TestUnrestrictedReadStillEnforcesQuotasAndScopes(t *testing.T) {
	a, s, f := testAPI(t)
	p := DefaultTokenPolicy()
	p.UnrestrictedRead = true
	p.Scopes = []string{ScopeRead}
	p.ReadsPerDay = 1
	_, raw := issue(t, s, p)
	f.messages["1234abcd"] = Message{ID: "1234abcd", Subject: "Verification code", Body: "Example code: 654321"}
	wantStatus(t, request(a, "POST", "/v1/messages/search", raw, `{"query":"verification code"}`, nil), 403)
	wantStatus(t, request(a, "POST", "/v1/messages/send", raw, `{"to":["shop@example.test"],"subject":"Hello","body":"Hello"}`, nil), 403)
	wantStatus(t, request(a, "GET", "/v1/messages/1234abcd", raw, "", nil), 200)
	wantStatus(t, request(a, "GET", "/v1/messages/1234abcd", raw, "", nil), 429)
	if f.reads != 1 {
		t.Fatal("quota bypass")
	}
	p.Scopes = []string{ScopeSearch}
	if p.Validate() == nil {
		t.Fatal("full read accepted without read scope")
	}
}

func TestUnrestrictedReadReturnsAvailableTextWithAttachments(t *testing.T) {
	attachment := gmailPart{MimeType: "application/pdf", Filename: "receipt.pdf"}
	attachment.Body.AttachmentID = "private-attachment"
	m, err := ParseGOGMessage(mimeMessage(t, []gmailPart{textPart("text/plain", "Example verification code: 654321"), attachment}))
	if err != nil {
		t.Fatal(err)
	}
	i := NewInspector(DefaultConfig())
	p := DefaultTokenPolicy()
	if !m.Uninspectable || i.Message(m, p) != "uninspectable_message" {
		t.Fatal("restricted attachment handling changed")
	}
	p.UnrestrictedRead = true
	if i.Message(m, p) != "" || !strings.Contains(m.Body, "654321") {
		t.Fatal("available message text withheld from full read")
	}
	data := mustJSON(t, m)
	if strings.Contains(data, "private-attachment") || strings.Contains(data, "ScanText") {
		t.Fatal("internal content exposed")
	}
}
