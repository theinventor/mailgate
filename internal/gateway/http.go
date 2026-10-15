package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const maxRequestBody = 64 << 10

type API struct {
	config       Config
	store        *Store
	backend      Backend
	inspector    *Inspector
	channels     []string
	slots        chan struct{}
	adminSlots   chan struct{}
	passwordSlot chan struct{}
	logger       *slog.Logger
}

func NewAPI(c Config, s *Store, b Backend, channels []string, logger *slog.Logger) *API {
	if logger == nil {
		logger = slog.Default()
	}
	return &API{config: c, store: s, backend: b, inspector: NewInspector(c), channels: channels, slots: make(chan struct{}, c.MaxConcurrentRequests), adminSlots: make(chan struct{}, 4), passwordSlot: make(chan struct{}, 1), logger: logger}
}

func (a *API) HTTPServer() *http.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/") {
			// Never expose owner setup or login through the agents' listener.
			r = r.Clone(r.Context())
			r.URL.Path = "/admin-not-on-agent-port"
		}
		a.ServeHTTP(w, r)
	})
	return &http.Server{Addr: a.config.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: time.Duration(a.config.RequestTimeoutSeconds+10) * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
}

func (a *API) AdminHTTPServer() *http.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/admin/") && r.URL.Path != "/admin" {
			r = r.Clone(r.Context())
			r.URL.Path = "/admin/not-found"
		}
		a.serveAdmin(w, r)
	})
	return &http.Server{Addr: a.config.AdminListen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
}

type response struct {
	status  int
	body    any
	reason  string
	details map[string]any
	allow   string
}

func failure(status int, code string) response {
	return response{status: status, body: map[string]string{"error": code}}
}

func routeName(r *http.Request) string {
	switch r.URL.Path {
	case "/healthz":
		return "health"
	case "/v1/messages/search":
		return "messages.search"
	case "/v1/messages/send":
		return "messages.send"
	}
	if strings.HasPrefix(r.URL.Path, "/v1/messages/") && !strings.Contains(strings.TrimPrefix(r.URL.Path, "/v1/messages/"), "/") {
		return "messages.read"
	}
	return "unrecognized"
}

func (a *API) record(e Event, reason string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return a.store.Record(ctx, e, a.channels, reason)
}

// These listeners accept only local reverse proxies. Use the last forwarded
// address (the hop appended by the proxy), never a caller-supplied first hop.
// This is audit metadata only; authorization never depends on these headers.
func requestPeer(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "unknown"
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	if addr.IsLoopback() {
		forwarded := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		if candidate, err := netip.ParseAddr(strings.TrimSpace(forwarded[len(forwarded)-1])); err == nil {
			return candidate.Unmap().String()
		}
	}
	return addr.Unmap().String()
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/") {
		a.serveAdmin(w, r)
		return
	}
	started := time.Now()
	id, err := randomString(18)
	if err != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	route := routeName(r)
	peer := requestPeer(r)
	event := Event{RequestID: id, Route: route, Peer: peer}
	result := failure(500, "internal_error")
	// Everything is buffered until the final audit entry is durable. A failed
	// audit write cannot result in an unlogged disclosure of email contents.
	defer func() {
		if recover() != nil {
			result = failure(500, "internal_error")
			a.logger.Error("request panic", "request_id", id)
		}
		event.Action = "request.completed"
		event.Status = result.status
		event.Details = result.details
		if event.Details == nil {
			event.Details = map[string]any{}
		}
		event.Details["duration_ms"] = time.Since(started).Milliseconds()
		if result.reason != "" {
			event.Details["rule"] = result.reason
		}
		if err := a.record(event, result.reason); err != nil {
			a.logger.Error("audit write failed", "request_id", id)
			result = failure(503, "audit_unavailable")
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Request-ID", id)
		if result.status == 429 {
			w.Header().Set("Retry-After", "60")
		}
		if result.allow != "" {
			w.Header().Set("Allow", result.allow)
		}
		w.WriteHeader(result.status)
		_ = json.NewEncoder(w).Encode(result.body)
	}()
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		result = failure(503, "busy")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(a.config.RequestTimeoutSeconds)*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if err := a.store.TakeQuota(ctx, "global", time.Minute, 1, a.config.GlobalRequestsPerMinute); err != nil {
		result = quotaFailure(err)
		return
	}
	if r.URL.RawQuery != "" {
		result = failure(400, "query_parameters_not_supported")
		return
	}
	if route == "health" {
		if r.Method != http.MethodGet {
			result = failure(405, "method_not_allowed")
			result.allow = "GET"
			return
		}
		if a.store.Ping(ctx) != nil {
			result = failure(503, "unavailable")
			return
		}
		result = response{status: 200, body: map[string]string{"status": "ok"}}
		return
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		result = failure(401, "unauthorized")
		return
	}
	token, err := a.store.Authenticate(ctx, strings.TrimPrefix(values[0], "Bearer "))
	if err != nil {
		if errors.Is(err, ErrDenied) {
			result = failure(401, "unauthorized")
		} else {
			result = failure(503, "unavailable")
		}
		return
	}
	event.TokenID = token.ID
	if err := a.store.TakeQuota(ctx, "requests:"+token.ID, time.Minute, 1, token.Policy.RequestsPerMinute); err != nil {
		result = quotaFailure(err)
		if errors.Is(err, ErrQuota) {
			result.reason = "request_rate_limit"
		}
		return
	}
	event.Action = "request.received"
	if err := a.record(event, ""); err != nil {
		result = failure(503, "audit_unavailable")
		return
	}
	method, scope := "", ""
	switch route {
	case "messages.search":
		method, scope = "POST", ScopeSearch
	case "messages.read":
		method, scope = "GET", ScopeRead
	case "messages.send":
		method, scope = "POST", ScopeSend
	default:
		result = failure(404, "not_found")
		result.reason = "unknown_endpoint"
		return
	}
	if r.Method != method {
		result = failure(405, "method_not_allowed")
		result.allow = method
		result.reason = "disallowed_method"
		return
	}
	if !token.Policy.Has(scope) {
		result = failure(403, "permission_denied")
		result.reason = "permission_denied"
		return
	}
	if route == "messages.read" {
		result = a.read(r, token)
		return
	}
	contentType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		result = failure(415, "application_json_required")
		return
	}
	if enc := r.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		result = failure(415, "content_encoding_not_supported")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	switch route {
	case "messages.search":
		result = a.search(r, token)
	case "messages.send":
		result = a.send(r, token, event)
	}
}

func quotaFailure(err error) response {
	if errors.Is(err, ErrQuota) {
		return failure(429, "rate_limit_exceeded")
	}
	return failure(503, "unavailable")
}

func decodeRequest(r *http.Request, target any) error {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	if err := uniqueJSONKeys(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(target); err != nil {
		return err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return errors.New("expected a single JSON object")
	}
	return nil
}

func uniqueJSONKeys(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var value func(int) error
	value = func(depth int) error {
		if depth > 8 {
			return errors.New("JSON nesting too deep")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				fold := strings.ToLower(key)
				if seen[fold] {
					return errors.New("duplicate JSON key")
				}
				seen[fold] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON")
		}
		_, err = d.Token()
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return errors.New("expected an object")
	}
	if err := value(0); err != nil {
		return err
	}
	_, err := d.Token()
	if err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

type searchRequest struct {
	Query  string `json:"query"`
	Limit  int    `json:"limit"`
	Cursor string `json:"cursor,omitempty"`
}
type searchResponse struct {
	Messages   []Message `json:"messages"`
	NextCursor string    `json:"next_cursor,omitempty"`
}

func (a *API) search(r *http.Request, t Token) (result response) {
	alertReason := ""
	defer func() {
		// A later page failure must not erase a sensitive result already observed.
		if alertReason != "" {
			result.reason = alertReason
		}
	}()
	var input searchRequest
	if err := decodeRequest(r, &input); err != nil {
		return failure(400, "invalid_request")
	}
	if input.Limit == 0 {
		input.Limit = min(10, a.config.MaxSearchResults)
	}
	if strings.TrimSpace(input.Query) == "" || len(input.Query) > 2048 || strings.ContainsRune(input.Query, 0) || input.Limit < 1 || input.Limit > a.config.MaxSearchResults {
		return failure(400, "invalid_request")
	}
	output := searchResponse{Messages: []Message{}}
	details := map[string]any{"query_hash": hashText(input.Query)}
	if reason := a.inspector.Check(input.Query); reason != "" {
		return response{status: 200, body: output, reason: reason, details: details}
	}
	page := ""
	if input.Cursor != "" {
		var err error
		page, err = a.store.LoadCursor(r.Context(), input.Cursor, t.ID, input.Query)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return failure(400, "invalid_cursor")
			}
			return failure(503, "unavailable")
		}
	}
	withheld := 0
	for batch := 0; batch < 3; batch++ {
		found, err := a.backend.Search(r.Context(), input.Query, page, input.Limit-len(output.Messages))
		if err != nil {
			return failure(502, "mail_backend_unavailable")
		}
		if len(found.IDs) > input.Limit-len(output.Messages) {
			return failure(502, "mail_backend_unavailable")
		}
		if len(found.IDs) > 0 {
			if err := a.store.TakeQuota(r.Context(), "reads:"+t.ID, 24*time.Hour, len(found.IDs), t.Policy.ReadsPerDay); err != nil {
				return quotaFailure(err)
			}
		}
		type readResult struct {
			m   Message
			err error
		}
		results := make([]readResult, len(found.IDs))
		var wg sync.WaitGroup
		for index, id := range found.IDs {
			wg.Go(func() { results[index].m, results[index].err = a.backend.Read(r.Context(), id) })
		}
		wg.Wait()
		for _, entry := range results {
			if errors.Is(entry.err, ErrNotFound) {
				continue
			}
			if entry.err != nil {
				return failure(502, "mail_backend_unavailable")
			}
			if reason := a.inspector.Message(entry.m, t.Policy); reason != "" {
				withheld++
				if alertReason == "" && reason != "outside_mailbox_scope" && reason != "uninspectable_message" {
					alertReason = reason
				}
				continue
			}
			m := entry.m
			m.Body = ""
			m.Untrusted = true
			output.Messages = append(output.Messages, m)
		}
		page = found.NextPage
		if page == "" || len(output.Messages) >= input.Limit {
			break
		}
	}
	// Empty pages have exactly the same response shape as a true empty search.
	// Gmail's counts and raw pagination tokens are never exposed.
	if page != "" && len(output.Messages) > 0 {
		var err error
		output.NextCursor, err = a.store.SaveCursor(r.Context(), t.ID, input.Query, page)
		if err != nil {
			return failure(503, "unavailable")
		}
	}
	details["returned"] = len(output.Messages)
	details["withheld"] = withheld
	return response{status: 200, body: output, reason: alertReason, details: details}
}

func (a *API) read(r *http.Request, t Token) response {
	id := strings.TrimPrefix(r.URL.Path, "/v1/messages/")
	if !messageIDPattern.MatchString(id) {
		return failure(404, "not_found")
	}
	if err := a.store.TakeQuota(r.Context(), "reads:"+t.ID, 24*time.Hour, 1, t.Policy.ReadsPerDay); err != nil {
		return quotaFailure(err)
	}
	m, err := a.backend.Read(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		return failure(404, "not_found")
	}
	if err != nil {
		return failure(502, "mail_backend_unavailable")
	}
	if reason := a.inspector.Message(m, t.Policy); reason != "" {
		out := failure(404, "not_found")
		out.reason = reason
		out.details = map[string]any{"message_id": id}
		return out
	}
	m.Untrusted = true
	return response{status: 200, body: map[string]any{"message": m}, details: map[string]any{"message_id": id}}
}

type sendRequest struct {
	To      []string `json:"to"`
	CC      []string `json:"cc,omitempty"`
	Subject string   `json:"subject"`
	Body    string   `json:"body"`
}

var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func (a *API) send(r *http.Request, t Token, event Event) response {
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || !idempotencyPattern.MatchString(keys[0]) {
		return failure(400, "idempotency_key_required")
	}
	key := keys[0]
	var input sendRequest
	if err := decodeRequest(r, &input); err != nil {
		return failure(400, "invalid_request")
	}
	if len(input.To) < 1 || len(input.To)+len(input.CC) > 20 || len(input.Subject) < 1 || len(input.Subject) > 200 || strings.ContainsAny(input.Subject, "\r\n\x00") || len(input.Body) < 1 || len(input.Body) > 32<<10 || strings.ContainsRune(input.Body, 0) {
		return failure(400, "invalid_request")
	}
	out := Outgoing{Subject: input.Subject, Body: input.Body}
	for _, group := range []struct {
		input  []string
		output *[]string
	}{{input.To, &out.To}, {input.CC, &out.CC}} {
		for _, value := range group.input {
			address, err := CanonicalAddress(value)
			if err != nil {
				return failure(400, "invalid_recipient")
			}
			if len(t.Policy.AllowedRecipients) > 0 && !containsAddress(t.Policy.AllowedRecipients, address) {
				result := failure(403, "recipient_not_allowed")
				result.reason = "recipient_not_allowed"
				return result
			}
			if !containsAddress(*group.output, address) {
				*group.output = append(*group.output, address)
			}
		}
	}
	if reason := a.inspector.Check(strings.Join(append(append([]string{input.Subject, input.Body}, out.To...), out.CC...), "\n")); reason != "" {
		result := failure(403, "content_not_allowed")
		result.reason = "outbound_" + reason
		return result
	}
	owner, _ := CanonicalAddress(a.config.OwnerEmail)
	switch t.Policy.CopyOwner {
	case "cc":
		if !containsAddress(out.CC, owner) {
			out.CC = append(out.CC, owner)
		}
	case "bcc":
		out.BCC = []string{owner}
	case "none":
	default:
		return failure(503, "invalid_policy")
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return failure(500, "internal_error")
	}
	event.Details = map[string]any{"to": out.To, "cc": out.CC, "bcc": out.BCC, "body_hash": hashText(out.Body), "subject_hash": hashText(out.Subject), "idempotency_key_hash": hashText(key)}
	record, fresh, err := a.store.BeginSend(r.Context(), t, key, hashText(string(encoded)), event)
	if errors.Is(err, ErrQuota) {
		return failure(429, "send_quota_exceeded")
	}
	if errors.Is(err, ErrConflict) {
		return failure(409, "idempotency_conflict")
	}
	if errors.Is(err, ErrDenied) {
		return failure(401, "unauthorized")
	}
	if err != nil {
		return failure(503, "unavailable")
	}
	if !fresh {
		if record.State == "sent" {
			return response{status: 200, body: map[string]any{"message": record.Result}, details: map[string]any{"replayed": true}}
		}
		return failure(409, "send_status_unknown_check_sent_mail")
	}
	sent, sendErr := a.backend.Send(r.Context(), out)
	// Persist completion even if the HTTP client disconnected. If persistence
	// fails, the pending intent still prevents an automatic duplicate send.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.store.FinishSend(ctx, t.ID, key, sent, sendErr != nil); err != nil {
		result := failure(503, "send_status_unknown_check_sent_mail")
		result.reason = "send_status_unknown"
		return result
	}
	if sendErr != nil {
		result := failure(502, "send_status_unknown_check_sent_mail")
		result.reason = "send_status_unknown"
		return result
	}
	event.Details["message_id"] = sent.ID
	return response{status: 200, body: map[string]any{"message": sent}, details: event.Details}
}
