package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func queuedAlert(t *testing.T, store *Store) string {
	t.Helper()
	var message string
	for _, channel := range []string{"pushover", "brrr"} {
		jobs, err := store.DueAlerts(context.Background(), channel, 1<<62)
		if err != nil || len(jobs) != 1 {
			t.Fatalf("%s alert jobs: %v, %v", channel, jobs, err)
		}
		if message != "" && message != jobs[0].Message {
			t.Fatal("notification channels received different context")
		}
		message = jobs[0].Message
	}
	return message
}

func requireText(t *testing.T, text string, expected ...string) {
	t.Helper()
	for _, value := range expected {
		if !strings.Contains(text, value) {
			t.Fatalf("missing %q in:\n%s", value, text)
		}
	}
}

func TestUnsupportedEndpointAlertIncludesBotAndActualRequest(t *testing.T) {
	for _, path := range []string{"/v1/labels", "/admin/api/tokens"} {
		t.Run(path, func(t *testing.T) {
			api, store, backend := testAPI(t)
			_, raw, err := store.CreateToken(context.Background(), "order-tracking-bot", DefaultTokenPolicy(), time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", path, nil)
			req.RemoteAddr = "127.0.0.1:12345"
			req.Header.Set("X-Forwarded-For", "100.64.0.9")
			req.Header.Set("Authorization", "Bearer "+raw)
			w := httptest.NewRecorder()
			api.HTTPServer().Handler.ServeHTTP(w, req)
			wantStatus(t, w, 404)
			message := queuedAlert(t, store)
			requireText(t, message, "Bot: order-tracking-bot", "Request: GET "+path,
				"Unsupported API endpoint (unknown_endpoint)", "HTTP 404; request rejected", "Client: 100.64.0.9", "Audit #", w.Header().Get("X-Request-ID"))
			if strings.Contains(message, raw) || strings.Contains(message, "admin-not-on-agent-port") || backend.searches+backend.reads+backend.sends != 0 {
				t.Fatal("request disclosure or admin isolation regression")
			}
			if securityAlertTitle(message) != "Mailgate: order-tracking-bot" {
				t.Fatal("notification title does not identify the bot")
			}
		})
	}
}

func TestSearchAlertExplainsQueryVersusResultAndRedactsSecrets(t *testing.T) {
	t.Run("query", func(t *testing.T) {
		api, store, backend := testAPI(t)
		_, raw := issue(t, store, DefaultTokenPolicy())
		body := mustJSON(t, map[string]any{"query": "driver's license 123-45-6789 password=HiddenSecret " + raw})
		w := request(api, "POST", "/v1/messages/search", raw, body, nil)
		wantStatus(t, w, 200)
		message := queuedAlert(t, store)
		requireText(t, message, "Trigger: Search query; returned an empty result", "Query: driver's license", "[redacted]")
		events, _ := store.Events(context.Background(), 100)
		for _, forbidden := range []string{raw, "123-45-6789", "HiddenSecret"} {
			if strings.Contains(message+mustJSON(t, events), forbidden) {
				t.Fatal("request secret leaked to audit or notification")
			}
		}
		if backend.searches+backend.reads != 0 || strings.TrimSpace(w.Body.String()) != `{"messages":[]}` {
			t.Fatal("sensitive-query response changed")
		}
	})
	t.Run("result", func(t *testing.T) {
		api, store, backend := testAPI(t)
		_, raw := issue(t, store, DefaultTokenPolicy())
		backend.page = SearchPage{IDs: []string{"1234abcd"}}
		backend.messages["1234abcd"] = Message{ID: "1234abcd", From: "shop@example.test", Subject: "Order verification code: 876543", Body: "Password: HiddenSecret. Private body must stay private."}
		w := request(api, "POST", "/v1/messages/search", raw, `{"query":"subject:order newer_than:30d"}`, nil)
		wantStatus(t, w, 200)
		message := queuedAlert(t, store)
		requireText(t, message, "Protected email encountered in search results", "Query: subject:order newer_than:30d", "From: shop@example.test", "Email ID: 1234abcd", "0 returned; 1 withheld")
		if strings.Contains(message, "Trigger: Search query") || strings.Contains(message, "876543") || strings.Contains(message, "HiddenSecret") || strings.Contains(message, "Private body") {
			t.Fatal("misleading trigger or email content disclosure")
		}
	})
	t.Run("ordinary search stays hash-only", func(t *testing.T) {
		api, store, _ := testAPI(t)
		_, raw := issue(t, store, DefaultTokenPolicy())
		wantStatus(t, request(api, "POST", "/v1/messages/search", raw, `{"query":"subject:ordinary-order"}`, nil), 200)
		events, _ := store.Events(context.Background(), 100)
		if strings.Contains(mustJSON(t, events), "ordinary-order") {
			t.Fatal("ordinary query unnecessarily retained")
		}
	})
}

func TestReadAndSendAlertsRetainUsefulContextWithoutBodies(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		api, store, backend := testAPI(t)
		_, raw := issue(t, store, DefaultTokenPolicy())
		backend.messages["1234abcd"] = Message{ID: "1234abcd", From: "shop@example.test", Subject: "Order confirmation", Body: "Credit card: 4111111111111111"}
		wantStatus(t, request(api, "GET", "/v1/messages/1234abcd", raw, "", nil), 404)
		message := queuedAlert(t, store)
		requireText(t, message, "Requested email was withheld", "GET /v1/messages/1234abcd", "Subject: Order confirmation", "From: shop@example.test")
		if strings.Contains(message, "4111111111111111") {
			t.Fatal("card number leaked")
		}
	})
	t.Run("recipient", func(t *testing.T) {
		api, store, backend := testAPI(t)
		policy := DefaultTokenPolicy()
		policy.Scopes = append(policy.Scopes, ScopeSend)
		policy.AllowedRecipients = []string{"allowed@example.test"}
		_, raw := issue(t, store, policy)
		w := request(api, "POST", "/v1/messages/send", raw, `{"to":["other@example.test"],"subject":"Order question","body":"Private message text"}`, map[string]string{"Idempotency-Key": "alert-context-test-01"})
		wantStatus(t, w, 403)
		message := queuedAlert(t, store)
		requireText(t, message, "Recipients: other@example.test", "Subject: Order question", "recipient_not_allowed", "POST /v1/messages/send")
		if strings.Contains(message, "Private message text") || backend.sends != 0 {
			t.Fatal("blocked send disclosed or delivered content")
		}
	})
	t.Run("missing scope", func(t *testing.T) {
		api, store, backend := testAPI(t)
		_, raw := issue(t, store, DefaultTokenPolicy())
		wantStatus(t, request(api, "POST", "/v1/messages/send", raw, `{"body":"HiddenSecret"}`, nil), 403)
		requireText(t, queuedAlert(t, store), "Required permission: mail.send", "HTTP 403", "POST /v1/messages/send")
		if backend.sends != 0 {
			t.Fatal("unauthorized send reached backend")
		}
	})
}

type failsAfterFirstSearch struct {
	Backend
	searches int
}

func (f *failsAfterFirstSearch) Search(context.Context, string, string, int) (SearchPage, error) {
	f.searches++
	if f.searches == 1 {
		return SearchPage{IDs: []string{"1234abcd"}, NextPage: "page-two"}, nil
	}
	return SearchPage{}, errors.New("later backend failure")
}

func TestAlertContextSurvivesLaterSearchFailure(t *testing.T) {
	api, store, backend := testAPI(t)
	_, raw := issue(t, store, DefaultTokenPolicy())
	backend.messages["1234abcd"] = Message{ID: "1234abcd", Subject: "Order details", Body: "Credit card information"}
	api.backend = &failsAfterFirstSearch{Backend: backend}
	wantStatus(t, request(api, "POST", "/v1/messages/search", raw, `{"query":"subject:order"}`, nil), 502)
	requireText(t, queuedAlert(t, store), "Protected email encountered in search results", "Query: subject:order", "Subject: Order details", "HTTP 502", "1 withheld")
}

func TestBotAttributionSurvivesRenameAndDeletion(t *testing.T) {
	api, store, _ := testAPI(t)
	token, raw, err := store.CreateToken(context.Background(), "mighty-shopping-executive-assistant", DefaultTokenPolicy(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, request(api, "GET", "/v1/labels", raw, "", nil), 404)
	message := queuedAlert(t, store)
	requireText(t, message, "Bot: mighty-shopping-executive-assistant")
	if err = store.UpdateToken(context.Background(), token.ID, "New name", token.Policy, token.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err = store.DeleteToken(context.Background(), token.ID); err != nil {
		t.Fatal(err)
	}
	events, err := store.Events(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == "request.completed" && event.TokenName != "mighty-shopping-executive-assistant" {
			t.Fatal("historical bot attribution changed")
		}
	}
	if queuedAlert(t, store) != message {
		t.Fatal("queued notification lost its original bot attribution")
	}
}

func TestRequestPreviewRedactsBeforeTruncationAndCannotForgeLines(t *testing.T) {
	for _, labeled := range []string{`"password":"hidden-secret"`, `'access_token': 'hidden-secret'`, `refresh_token=hidden-secret`, `verification code is 876543`} {
		if got := requestPreview(labeled, 180); strings.Contains(got, "hidden-secret") || strings.Contains(got, "876543") {
			t.Fatalf("labeled secret leaked: %s", got)
		}
	}
	secret := "mg_0123456789abcdef01234567." + strings.Repeat("a", 80)
	text := "GET /v1/custom/" + secret + "\nBot: impersonated\u202e 123-45-6789 4111 1111 1111 1111 password=hidden-secret https://example.test/?access_token=hidden-secret"
	preview := requestPreview(text, 180)
	requireText(t, preview, "[redacted]")
	for _, secret := range []string{secret, "aaaaaa", "123-45-6789", "4111", "hidden-secret", "\n", "\u202e"} {
		if strings.Contains(preview, secret) {
			t.Fatalf("preview leaked %q", secret)
		}
	}
	event := Event{ID: 42, At: time.Now().UTC().Format(time.RFC3339Nano), TokenName: strings.Repeat("猫", 80), TokenID: "abc123", RequestID: "request-reference", Details: map[string]any{"query_preview": strings.Repeat("猫", 500), "method": "GET", "path": "/v1/labels"}}
	message := securityAlert(event, "unknown_endpoint")
	if len(message) > 950 || !utf8.ValidString(message) || !json.Valid([]byte(mustJSON(t, map[string]string{"message": message}))) {
		t.Fatal("notification length or encoding invalid")
	}
	requireText(t, message, "Audit #42; request request-reference")
}
