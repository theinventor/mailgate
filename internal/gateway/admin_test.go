package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAutomaticSetupAndAdminCRUD(t *testing.T) {
	a, s, _ := testAPI(t)
	ctx := context.Background()
	w := request(a, "GET", "/admin/api/state", "", "", nil)
	wantStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), `"setup_required":true`) {
		t.Fatal("first visit did not detect missing password")
	}
	password := "a long test-only admin password"
	// No setup links or existing secret are needed, but cross-origin requests fail.
	wantStatus(t, request(a, "POST", "/admin/api/setup", "", mustJSON(t, map[string]string{"password": password}), nil), 403)
	h := map[string]string{"Origin": a.config.AdminOrigin}
	w = request(a, "POST", "/admin/api/setup", "", mustJSON(t, map[string]string{"password": password}), h)
	wantStatus(t, w, 200)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing session cookie")
	}
	cookie := cookies[0]
	if cookie.Name != adminCookie || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatal("unsafe admin cookie")
	}
	var session AdminSession
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	h["Cookie"] = cookie.Name + "=" + cookie.Value
	h["X-CSRF-Token"] = session.CSRF
	var hash string
	if err := s.db.QueryRow("SELECT password_hash FROM owner").Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, passwordPrefix) || strings.Contains(hash, password) {
		t.Fatal("plaintext or weak password hash")
	}
	w = request(a, "GET", "/admin/api/state", "", "", nil)
	wantStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), `"setup_required":false`) {
		t.Fatal("setup remained open")
	}
	wantStatus(t, request(a, "POST", "/admin/api/setup", "", mustJSON(t, map[string]string{"password": "attacker replacement password"}), h), 409)
	_, agentRaw := issue(t, s, DefaultTokenPolicy())
	wantStatus(t, request(a, "GET", "/admin/api/tokens", agentRaw, "", nil), 401)
	body := map[string]any{"name": "Shopping agent", "policy": DefaultTokenPolicy(), "expires_at": time.Now().Add(24 * time.Hour)}
	wantStatus(t, request(a, "POST", "/admin/api/tokens", "", mustJSON(t, body), map[string]string{"Cookie": h["Cookie"], "Origin": a.config.AdminOrigin}), 403)
	wantStatus(t, request(a, "POST", "/admin/api/tokens", "", mustJSON(t, body), map[string]string{"Cookie": h["Cookie"], "Origin": "https://evil.example", "X-CSRF-Token": session.CSRF}), 403)
	w = request(a, "POST", "/admin/api/tokens", "", mustJSON(t, body), h)
	wantStatus(t, w, 201)
	var created struct {
		Token  Token  `json:"token"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, created.Secret); err != nil {
		t.Fatal(err)
	}
	w = request(a, "GET", "/admin/api/tokens", "", "", h)
	wantStatus(t, w, 200)
	if strings.Contains(w.Body.String(), created.Secret) || strings.Contains(w.Body.String(), "digest") {
		t.Fatal("token secret redisclosed")
	}
	p := DefaultTokenPolicy()
	p.Scopes = []string{ScopeSearch}
	p.ReadsPerDay = 10
	body["policy"] = p
	body["name"] = "Shopping reader"
	wantStatus(t, request(a, "PUT", "/admin/api/tokens/"+created.Token.ID, "", mustJSON(t, body), h), 200)
	changed, err := s.Authenticate(ctx, created.Secret)
	if err != nil || changed.Policy.Has(ScopeRead) || changed.Policy.ReadsPerDay != 10 {
		t.Fatal("token update ineffective")
	}
	wantStatus(t, request(a, "POST", "/admin/api/tokens/"+created.Token.ID+"/revoke", "", `{}`, h), 200)
	if _, err := s.Authenticate(ctx, created.Secret); !errors.Is(err, ErrDenied) {
		t.Fatal("web revoke ineffective")
	}
	wantStatus(t, request(a, "DELETE", "/admin/api/tokens/"+created.Token.ID, "", `{}`, h), 200)
	remaining, err := s.Tokens(ctx)
	if err != nil || len(remaining) != 1 {
		t.Fatal("web delete failed")
	}
	w = request(a, "GET", "/admin/api/audit", "", "", h)
	wantStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "token.deleted") || strings.Contains(w.Body.String(), password) || strings.Contains(w.Body.String(), created.Secret) {
		t.Fatal("bad audit retention/privacy")
	}
	newPassword := "7" // No minimum length or character-mix requirements.
	w = request(a, "POST", "/admin/api/password", "", mustJSON(t, map[string]string{"current_password": password, "new_password": newPassword}), h)
	wantStatus(t, w, 200)
	wantStatus(t, request(a, "GET", "/admin/api/tokens", "", "", h), 401)
	h = map[string]string{"Origin": a.config.AdminOrigin}
	wantStatus(t, request(a, "POST", "/admin/api/login", "", mustJSON(t, map[string]string{"password": password}), h), 401)
	wantStatus(t, request(a, "POST", "/admin/api/login", "", mustJSON(t, map[string]string{"password": newPassword}), h), 200)
}

func TestAdminSetupAcceptsSingleCharacterPassword(t *testing.T) {
	a, s, _ := testAPI(t)
	ctx := context.Background()
	h := map[string]string{"Origin": a.config.AdminOrigin}
	for _, password := range []string{"", strings.Repeat("x", 1025)} {
		wantStatus(t, request(a, "POST", "/admin/api/setup", "", mustJSON(t, map[string]string{"password": password}), h), 400)
		if ready, err := s.OwnerReady(ctx); err != nil || ready {
			t.Fatal("invalid password initialized the owner")
		}
	}
	wantStatus(t, request(a, "POST", "/admin/api/setup", "", `{"password":"x"}`, h), 200)
	wantStatus(t, request(a, "POST", "/admin/api/login", "", `{"password":"x"}`, h), 200)
	if err := s.ChangeOwnerPassword(ctx, "x", ""); err == nil {
		t.Fatal("empty replacement password accepted")
	}
	if ok, err := s.VerifyOwner(ctx, "x"); err != nil || !ok {
		t.Fatal("rejected password change altered the existing password")
	}
}

func TestOwnerSetupAtomicAndNeverOverwrites(t *testing.T) {
	s := testStore(t)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			err := s.SetupOwner(context.Background(), "concurrent setup test password")
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrDenied) {
				t.Errorf("unexpected setup error: %v", err)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("initialized %d times", successes.Load())
	}
	if err := s.SetupOwner(context.Background(), "subsequent malicious password"); !errors.Is(err, ErrDenied) {
		t.Fatal("setup overwrote existing password")
	}
}

func TestAdminNetworkBoundariesAndHeaders(t *testing.T) {
	a, _, _ := testAPI(t)
	w := request(a.AdminHTTPServer().Handler, "GET", "/admin/", "", "", nil)
	wantStatus(t, w, 200)
	for _, header := range []string{"Content-Security-Policy", "X-Frame-Options", "Cache-Control", "Referrer-Policy"} {
		if w.Header().Get(header) == "" {
			t.Fatalf("missing %s", header)
		}
	}
	if strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-inline") {
		t.Fatal("unsafe CSP")
	}
	// Even a forged Host cannot reach setup through the agents' listener.
	w = request(a.HTTPServer().Handler, "POST", "/admin/api/setup", "", `{"password":"long enough password"}`, map[string]string{"Origin": a.config.AdminOrigin})
	if w.Code == 200 {
		t.Fatal("admin setup exposed on agent port")
	}
	r := httptest.NewRequest("GET", "https://evil.example/admin/api/state", nil)
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	wantStatus(t, w, 403)
	w = request(a.AdminHTTPServer().Handler, "GET", "/v1/messages/1234abcd", "", "", nil)
	if w.Code == 200 {
		t.Fatal("agent endpoint exposed on admin port")
	}
}

func TestAdminLoginRateLimitAndExpiry(t *testing.T) {
	a, s, _ := testAPI(t)
	ctx := context.Background()
	if err := s.SetupOwner(ctx, "correct owner password long"); err != nil {
		t.Fatal(err)
	}
	h := map[string]string{"Origin": a.config.AdminOrigin}
	for range 5 {
		wantStatus(t, request(a, "POST", "/admin/api/login", "", `{"password":"wrong"}`, h), 401)
	}
	wantStatus(t, request(a, "POST", "/admin/api/login", "", `{"password":"wrong"}`, h), 429)
	_, raw, err := s.NewAdminSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE admin_sessions SET expires_at=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdminSession(ctx, raw); !errors.Is(err, ErrDenied) {
		t.Fatal("expired session accepted")
	}
}
