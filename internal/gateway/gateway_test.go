package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeBackend struct {
	mu                     sync.Mutex
	messages               map[string]Message
	page                   SearchPage
	searches, reads, sends int
	out                    Outgoing
	sendErr                error
	onRead                 func()
}

func (f *fakeBackend) Search(context.Context, string, string, int) (SearchPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.searches++
	return f.page, nil
}
func (f *fakeBackend) Read(_ context.Context, id string) (Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.onRead != nil {
		f.onRead()
	}
	m, ok := f.messages[id]
	if !ok {
		return Message{}, ErrNotFound
	}
	return m, nil
}
func (f *fakeBackend) Send(_ context.Context, m Outgoing) (SentMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sends++
	f.out = m
	return SentMessage{ID: "1234abcd", ThreadID: "1234abcd"}, f.sendErr
}
func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func testAPI(t *testing.T) (*API, *Store, *fakeBackend) {
	t.Helper()
	s := testStore(t)
	c := DefaultConfig()
	c.StateDir = s.Dir
	c.OwnerEmail = "owner@example.test"
	c.GOGAccount = c.OwnerEmail
	c.AdminOrigin = "https://mailgate.test:8443"
	c.GlobalRequestsPerMinute = 10000
	f := &fakeBackend{messages: map[string]Message{}}
	a := NewAPI(c, s, f, []string{"pushover", "brrr"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return a, s, f
}
func issue(t *testing.T, s *Store, p TokenPolicy) (Token, string) {
	t.Helper()
	p.RequestsPerMinute = 10000
	token, raw, err := s.CreateToken(context.Background(), "test agent", p, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return token, raw
}
func request(a http.Handler, method, path, raw, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://mailgate.test:8443"+path, strings.NewReader(body))
	if raw != "" {
		r.Header.Set("Authorization", "Bearer "+raw)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func wantStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status %d, want %d: %s", w.Code, status, w.Body.String())
	}
}
func mustJSON(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTokenStorageRevocationAndExpiry(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	token, raw := issue(t, s, DefaultTokenPolicy())
	if _, err := s.Authenticate(ctx, raw); err != nil {
		t.Fatal(err)
	}
	var digest []byte
	if err := s.db.QueryRow("SELECT digest FROM tokens").Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if len(digest) != 32 || strings.Contains(string(digest), raw) {
		t.Fatal("token stored in recoverable form")
	}
	if _, err := s.Authenticate(ctx, raw[:70]+"!"); !errors.Is(err, ErrDenied) {
		t.Fatal("tampered token accepted")
	}
	if err := s.Revoke(ctx, token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, raw); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked token accepted")
	}
	_, raw = issue(t, s, DefaultTokenPolicy())
	if _, err := s.db.Exec("UPDATE tokens SET expires_at=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, raw); !errors.Is(err, ErrDenied) {
		t.Fatal("expired token accepted")
	}
	for _, path := range []string{s.Dir, filepath.Join(s.Dir, "mailgate.db")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("insecure permissions: %s", path)
		}
	}
}

func TestQuotaAtomicAndPersistent(t *testing.T) {
	s := testStore(t)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() {
			err := s.TakeQuota(context.Background(), "limited", time.Hour, 1, 7)
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrQuota) {
				t.Errorf("quota error: %v", err)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 7 {
		t.Fatalf("accepted %d", accepted.Load())
	}
	other, err := OpenStore(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.TakeQuota(context.Background(), "limited", time.Hour, 1, 7); !errors.Is(err, ErrQuota) {
		t.Fatal("quota reset across connection/restart")
	}
}

func TestPermissionBoundaryAndStrictRequests(t *testing.T) {
	a, s, f := testAPI(t)
	p := DefaultTokenPolicy()
	p.Scopes = []string{ScopeSearch}
	_, raw := issue(t, s, p)
	wantStatus(t, request(a, "POST", "/v1/messages/search", "", `{"query":"hello"}`, nil), 401)
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/v1/messages/1234abcd", "", 403},
		{"POST", "/v1/messages/send", `{"to":["x@example.test"]}`, 403},
		{"DELETE", "/v1/messages/1234abcd", "", 405},
		{"POST", "/v1/settings", `{}`, 404},
		{"POST", "/v1/messages/search", `{"query":"hello","Query":"other"}`, 400},
		{"POST", "/v1/messages/search", `{"query":"hello","account":"intruder@example.test"}`, 400},
		{"POST", "/v1/messages/search", `{"query":"hello"} {}`, 400},
		{"POST", "/v1/messages/search?token=abc", `{"query":"hello"}`, 400},
	} {
		wantStatus(t, request(a, tc.method, tc.path, raw, tc.body, nil), tc.status)
	}
	if f.searches+f.reads+f.sends != 0 {
		t.Fatal("denied request reached Google")
	}
}

func TestSensitiveSearchReturnsEmptyAndQueuesBothAlerts(t *testing.T) {
	a, s, f := testAPI(t)
	token, raw := issue(t, s, DefaultTokenPolicy())
	w := request(a, "POST", "/v1/messages/search", raw, `{"query":"driver's license for Example Person"}`, nil)
	wantStatus(t, w, 200)
	if strings.TrimSpace(w.Body.String()) != `{"messages":[]}` {
		t.Fatalf("nonempty or distinguishing response: %s", w.Body.String())
	}
	if f.searches+f.reads != 0 {
		t.Fatal("sensitive query reached backend")
	}
	for _, channel := range []string{"pushover", "brrr"} {
		jobs, err := s.DueAlerts(context.Background(), channel, 1<<62)
		if err != nil || len(jobs) != 1 {
			t.Fatalf("missing %s alert: %v", channel, err)
		}
		if !strings.Contains(jobs[0].Message, token.ID) || strings.Contains(jobs[0].Message, "Example Person") {
			t.Fatal("alert attribution or privacy failure")
		}
	}
	events, err := s.Events(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	logs := mustJSON(t, events)
	if strings.Contains(logs, raw) || strings.Contains(logs, "driver's license for Example Person") {
		t.Fatal("secret/query logged")
	}
}

func TestSearchAndDirectReadsInspectContentAndScope(t *testing.T) {
	a, s, f := testAPI(t)
	p := DefaultTokenPolicy()
	p.AllowedLabelIDs = []string{"INBOX"}
	_, raw := issue(t, s, p)
	f.messages = map[string]Message{
		"1234abcd": {ID: "1234abcd", From: "shop@example.test", Subject: "Delivery update", Body: "Your parcel arrives Tuesday.", LabelIDs: []string{"INBOX"}},
		"2234abcd": {ID: "2234abcd", From: "shop@example.test", Subject: "Documents", Body: "Social Security number 123-45-6789", LabelIDs: []string{"INBOX"}},
		"3234abcd": {ID: "3234abcd", Subject: "Private folder", Body: "Ordinary note", LabelIDs: []string{"PRIVATE"}},
		"4234abcd": {ID: "4234abcd", Subject: "Photo", Uninspectable: true, LabelIDs: []string{"INBOX"}},
	}
	f.page = SearchPage{IDs: []string{"1234abcd", "2234abcd", "3234abcd", "4234abcd"}}
	w := request(a, "POST", "/v1/messages/search", raw, `{"query":"newer_than:1d"}`, nil)
	wantStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "Delivery update") || strings.Contains(w.Body.String(), "parcel") || strings.Contains(w.Body.String(), "2234abcd") || strings.Contains(w.Body.String(), "3234abcd") || strings.Contains(w.Body.String(), "4234abcd") {
		t.Fatalf("leaked withheld content: %s", w.Body.String())
	}
	for _, id := range []string{"2234abcd", "3234abcd", "4234abcd", "9999abcd"} {
		wantStatus(t, request(a, "GET", "/v1/messages/"+id, raw, "", nil), 404)
	}
	w = request(a, "GET", "/v1/messages/1234abcd", raw, "", nil)
	wantStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "parcel") {
		t.Fatal("normal body withheld")
	}
}

func TestCursorBoundToTokenAndQuery(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	cursor, err := s.SaveCursor(ctx, "agent-1", "orders", "GOOGLE_CURSOR_PRIVATE")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cursor, "GOOGLE") {
		t.Fatal("upstream cursor exposed")
	}
	for _, tc := range []struct{ token, query string }{{"agent-2", "orders"}, {"agent-1", "other"}} {
		if _, err := s.LoadCursor(ctx, cursor, tc.token, tc.query); !errors.Is(err, ErrNotFound) {
			t.Fatal("cursor binding bypass")
		}
	}
	page, err := s.LoadCursor(ctx, cursor, "agent-1", "orders")
	if err != nil || page != "GOOGLE_CURSOR_PRIVATE" {
		t.Fatal("valid cursor failed")
	}
	if _, err = s.db.Exec("UPDATE cursors SET expires_at=1"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.LoadCursor(ctx, cursor, "agent-1", "orders"); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired cursor accepted")
	}
}

func TestSendingEnforcesCopiesAndIdempotency(t *testing.T) {
	for _, copyMode := range []string{"cc", "bcc"} {
		t.Run(copyMode, func(t *testing.T) {
			a, s, f := testAPI(t)
			p := DefaultTokenPolicy()
			p.Scopes = []string{ScopeSend}
			p.CopyOwner = copyMode
			p.AllowedRecipients = []string{"shop@example.test"}
			_, raw := issue(t, s, p)
			body := `{"to":["shop@example.test"],"subject":"Order update","body":"Please send the shipping date."}`
			headers := map[string]string{"Idempotency-Key": "order-update-0001"}
			wantStatus(t, request(a, "POST", "/v1/messages/send", raw, body, headers), 200)
			wantStatus(t, request(a, "POST", "/v1/messages/send", raw, body, headers), 200)
			if f.sends != 1 {
				t.Fatal("duplicate send")
			}
			copies := f.out.CC
			if copyMode == "bcc" {
				copies = f.out.BCC
			}
			if !containsAddress(copies, a.config.OwnerEmail) {
				t.Fatal("owner copy omitted")
			}
			wantStatus(t, request(a, "POST", "/v1/messages/send", raw, strings.Replace(body, "shipping date", "delivery date", 1), headers), 409)
			wantStatus(t, request(a, "POST", "/v1/messages/send", raw, strings.Replace(body, "shop@example.test", "outsider@example.test", 1), headers), 403)
			wantStatus(t, request(a, "POST", "/v1/messages/send", raw, `{"to":["shop@example.test"],"bcc":["hidden@example.test"],"subject":"Hi","body":"Hello"}`, headers), 400)
			wantStatus(t, request(a, "POST", "/v1/messages/send", raw, strings.Replace(body, "Order update", `Order\r\nBcc: x@example.test`, 1), headers), 400)
			if f.sends != 1 {
				t.Fatal("invalid request sent")
			}
		})
	}
}

func TestUncertainSendNeverRetriesAfterRestart(t *testing.T) {
	a, s, f := testAPI(t)
	p := DefaultTokenPolicy()
	p.Scopes = []string{ScopeSend}
	_, raw := issue(t, s, p)
	f.sendErr = ErrBackend
	body := `{"to":["shop@example.test"],"subject":"Hi","body":"Hello"}`
	headers := map[string]string{"Idempotency-Key": "uncertain-send-0001"}
	wantStatus(t, request(a, "POST", "/v1/messages/send", raw, body, headers), 502)
	second, err := OpenStore(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	a2 := NewAPI(a.config, second, f, a.channels, a.logger)
	wantStatus(t, request(a2, "POST", "/v1/messages/send", raw, body, headers), 409)
	if f.sends != 1 {
		t.Fatal("uncertain send retried")
	}
	pending, err := second.PendingSends(context.Background())
	if err != nil || len(pending) != 1 || pending[0]["state"] != "uncertain" {
		t.Fatal("uncertain state lost")
	}
}

func TestConcurrentSendAndDailyQuota(t *testing.T) {
	a, s, f := testAPI(t)
	p := DefaultTokenPolicy()
	p.Scopes = []string{ScopeSend}
	p.SendsPerDay = 1
	_, raw := issue(t, s, p)
	body := `{"to":["shop@example.test"],"subject":"Hi","body":"Hello"}`
	headers := map[string]string{"Idempotency-Key": "concurrent-send-1"}
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			w := request(a, "POST", "/v1/messages/send", raw, body, headers)
			if w.Code != 200 && w.Code != 409 {
				t.Errorf("unexpected status %d", w.Code)
			}
		})
	}
	wg.Wait()
	if f.sends != 1 {
		t.Fatalf("sent %d times", f.sends)
	}
	wantStatus(t, request(a, "POST", "/v1/messages/send", raw, body, map[string]string{"Idempotency-Key": "another-send-0001"}), 429)
}

func TestAuditFailurePreventsDisclosureAndSideEffects(t *testing.T) {
	a, s, f := testAPI(t)
	_, raw := issue(t, s, DefaultTokenPolicy())
	f.messages["1234abcd"] = Message{ID: "1234abcd", Body: "Private ordinary email"}
	f.onRead = func() {
		s.db.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'read-only audit'); END")
	}
	w := request(a, "GET", "/v1/messages/1234abcd", raw, "", nil)
	wantStatus(t, w, 503)
	if strings.Contains(w.Body.String(), "Private ordinary") {
		t.Fatal("unlogged data disclosed")
	}
	f.onRead = nil
	wantStatus(t, request(a, "GET", "/v1/messages/1234abcd", raw, "", nil), 503)
	if f.reads != 1 {
		t.Fatal("backend contacted despite failed audit preflight")
	}
}

func TestAlertQueueSurvivesRestartAndDeduplicates(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	event := Event{TokenID: "agent", Action: "request.completed", Route: "messages.search"}
	for range 3 {
		if err := s.Record(ctx, event, []string{"pushover", "brrr"}, "identity_document"); err != nil {
			t.Fatal(err)
		}
	}
	jobs, err := s.DueAlerts(ctx, "pushover", time.Now().Unix())
	if err != nil || len(jobs) != 1 {
		t.Fatal("missing or duplicate jobs")
	}
	if err := s.FinishAlert(ctx, jobs[0], "http_503"); err != nil {
		t.Fatal(err)
	}
	other, err := OpenStore(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	jobs, err = other.DueAlerts(ctx, "pushover", time.Now().Unix())
	if err != nil || len(jobs) != 0 {
		t.Fatal("retry ignored backoff")
	}
	jobs, err = other.DueAlerts(ctx, "pushover", 1<<62)
	if err != nil || len(jobs) != 1 || jobs[0].Attempts != 1 {
		t.Fatal("retry state lost")
	}
	if err := other.FinishAlert(ctx, jobs[0], ""); err != nil {
		t.Fatal(err)
	}
	jobs, err = other.DueAlerts(ctx, "brrr", time.Now().Unix())
	if err != nil || len(jobs) != 1 {
		t.Fatal("other channel lost")
	}
}

func TestBackupIncludesTokenState(t *testing.T) {
	s := testStore(t)
	_, raw := issue(t, s, DefaultTokenPolicy())
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	if err := s.Backup(context.Background(), filepath.Join(dir, "mailgate.db")); err != nil {
		t.Fatal(err)
	}
	copy, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	if _, err := copy.Authenticate(context.Background(), raw); err != nil {
		t.Fatal("backup lost token")
	}
}
