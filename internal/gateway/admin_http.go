package gateway

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//go:embed web/*
var adminFiles embed.FS

const adminCookie = "__Host-mailgate_admin"

type adminResult struct {
	response
	asset       []byte
	contentType string
	cookie      *http.Cookie
}

func adminFailure(status int, code string) adminResult {
	return adminResult{response: failure(status, code)}
}

func sessionCookie(raw string, expiry time.Time) *http.Cookie {
	return &http.Cookie{Name: adminCookie, Value: raw, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: expiry, MaxAge: 3600}
}

func clearSessionCookie() *http.Cookie {
	c := sessionCookie("", time.Unix(1, 0))
	c.MaxAge = -1
	return c
}

func adminRoute(path string) string {
	switch path {
	case "/admin", "/admin/":
		return "admin.page"
	case "/admin/assets/app.js", "/admin/assets/style.css":
		return "admin.asset"
	case "/admin/api/state":
		return "admin.state"
	case "/admin/api/setup":
		return "admin.setup"
	case "/admin/api/login":
		return "admin.login"
	case "/admin/api/logout":
		return "admin.logout"
	case "/admin/api/password":
		return "admin.password"
	case "/admin/api/session":
		return "admin.session"
	case "/admin/api/overview":
		return "admin.overview"
	case "/admin/api/audit":
		return "admin.audit"
	case "/admin/api/alerts":
		return "admin.alerts"
	case "/admin/api/sends":
		return "admin.sends"
	case "/admin/api/tokens":
		return "admin.tokens"
	}
	if strings.HasPrefix(path, "/admin/api/tokens/") {
		return "admin.token"
	}
	return "admin.unrecognized"
}

func (a *API) serveAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	id, err := randomString(18)
	if err != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	peer := requestPeer(r)
	event := Event{RequestID: id, Peer: peer, Route: adminRoute(r.URL.Path)}
	result := adminFailure(500, "internal_error")
	defer func() {
		if recover() != nil {
			result = adminFailure(500, "internal_error")
			a.logger.Error("admin request panic", "request_id", id)
		}
		event.Action, event.Status, event.Details = "admin.request", result.status, result.details
		if result.reason != "" {
			if event.Details == nil {
				event.Details = map[string]any{}
			}
			event.Details["rule"] = result.reason
		}
		if err := a.record(event, result.reason); err != nil {
			result = adminFailure(503, "audit_unavailable")
		}
		w.Header().Set("X-Request-ID", id)
		if result.cookie != nil {
			http.SetCookie(w, result.cookie)
		}
		if result.status == 429 {
			w.Header().Set("Retry-After", "60")
		}
		if result.asset != nil {
			w.Header().Set("Content-Type", result.contentType)
			w.WriteHeader(result.status)
			_, _ = w.Write(result.asset)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(result.status)
		_ = json.NewEncoder(w).Encode(result.body)
	}()
	if a.config.AdminOrigin == "" {
		result = adminFailure(404, "not_found")
		return
	}
	origin, err := url.Parse(a.config.AdminOrigin)
	if err != nil || !strings.EqualFold(r.Host, origin.Host) {
		result = adminFailure(403, "invalid_host")
		return
	}
	if r.URL.RawQuery != "" {
		result = adminFailure(400, "query_parameters_not_supported")
		return
	}
	select {
	case a.adminSlots <- struct{}{}:
		defer func() { <-a.adminSlots }()
	default:
		result = adminFailure(503, "busy")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if err := a.store.TakeQuota(ctx, "admin", time.Minute, 1, 240); err != nil {
		result = adminResult{response: quotaFailure(err)}
		return
	}
	if r.Method != http.MethodGet {
		// The browser must submit directly from the configured HTTPS admin origin.
		// Proxy headers never establish admin identity or bypass CSRF checks.
		if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.AdminOrigin {
			result = adminFailure(403, "invalid_origin")
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" || r.Header.Get("Content-Encoding") != "" {
			result = adminFailure(415, "application_json_required")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	}
	if r.Method == http.MethodGet {
		var file, contentType string
		switch r.URL.Path {
		case "/admin", "/admin/":
			file, contentType = "web/index.html", "text/html; charset=utf-8"
		case "/admin/assets/app.js":
			file, contentType = "web/app.js", "text/javascript; charset=utf-8"
		case "/admin/assets/style.css":
			file, contentType = "web/style.css", "text/css; charset=utf-8"
		case "/admin/api/state":
			ready, err := a.store.OwnerReady(ctx)
			if err != nil {
				result = adminFailure(503, "unavailable")
				return
			}
			result = adminResult{response: response{status: 200, body: map[string]bool{"setup_required": !ready}}}
			return
		}
		if file != "" {
			data, err := adminFiles.ReadFile(file)
			if err != nil {
				result = adminFailure(500, "internal_error")
				return
			}
			result = adminResult{response: response{status: 200}, asset: data, contentType: contentType}
			return
		}
	}
	if r.Method == http.MethodPost && (r.URL.Path == "/admin/api/setup" || r.URL.Path == "/admin/api/login") {
		result = a.adminLogin(r, event)
		return
	}
	if len(r.CookiesNamed(adminCookie)) != 1 {
		result = adminFailure(401, "unauthorized")
		return
	}
	cookie, _ := r.Cookie(adminCookie)
	session, err := a.store.AdminSession(ctx, cookie.Value)
	if err != nil {
		if errors.Is(err, ErrDenied) {
			result = adminFailure(401, "unauthorized")
		} else {
			result = adminFailure(503, "unavailable")
		}
		return
	}
	event.TokenID = "owner"
	if r.Method != http.MethodGet {
		if len(r.Header.Values("X-CSRF-Token")) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(session.CSRF)) != 1 {
			result = adminFailure(403, "invalid_csrf")
			return
		}
		event.Action = "admin.request_received"
		if err := a.record(event, ""); err != nil {
			result = adminFailure(503, "audit_unavailable")
			return
		}
	}
	result = a.adminAction(r, session, cookie.Value)
}

func (a *API) passwordBudget(ctx context.Context) error {
	if err := a.store.TakeQuota(ctx, "admin-login-minute", time.Minute, 1, 5); err != nil {
		return err
	}
	return a.store.TakeQuota(ctx, "admin-login-hour", time.Hour, 1, 40)
}

func (a *API) adminLogin(r *http.Request, event Event) adminResult {
	ctx := r.Context()
	if err := a.passwordBudget(ctx); err != nil {
		return adminResult{response: quotaFailure(err)}
	}
	select {
	case a.passwordSlot <- struct{}{}:
		defer func() { <-a.passwordSlot }()
	default:
		return adminFailure(429, "password_check_busy")
	}
	var input struct {
		Password string `json:"password"`
	}
	if err := decodeRequest(r, &input); err != nil || len(input.Password) > 1024 {
		return adminFailure(400, "invalid_request")
	}
	if input.Password == "" {
		return adminFailure(400, "password_required")
	}
	event.Action = "admin.request_received"
	if err := a.record(event, ""); err != nil {
		return adminFailure(503, "audit_unavailable")
	}
	if r.URL.Path == "/admin/api/setup" {
		if err := a.store.SetupOwner(ctx, input.Password); err != nil {
			if errors.Is(err, ErrDenied) {
				return adminFailure(409, "setup_already_completed")
			}
			return adminFailure(400, "setup_failed")
		}
	} else {
		ok, err := a.store.VerifyOwner(ctx, input.Password)
		if err != nil {
			return adminFailure(503, "unavailable")
		}
		if !ok {
			result := adminFailure(401, "incorrect_password")
			result.reason = "admin_login_failed"
			return result
		}
	}
	session, raw, err := a.store.NewAdminSession(ctx)
	if err != nil {
		return adminFailure(503, "unavailable")
	}
	return adminResult{response: response{status: 200, body: session}, cookie: sessionCookie(raw, session.ExpiresAt)}
}

func (a *API) adminAction(r *http.Request, session AdminSession, cookie string) adminResult {
	ctx := r.Context()
	ok := func(body any) adminResult { return adminResult{response: response{status: 200, body: body}} }
	if r.Method == http.MethodGet {
		var body any
		var err error
		switch r.URL.Path {
		case "/admin/api/session":
			return ok(map[string]any{"csrf": session.CSRF, "expires_at": session.ExpiresAt, "owner_email": a.config.OwnerEmail})
		case "/admin/api/tokens":
			body, err = a.store.Tokens(ctx)
		case "/admin/api/overview":
			body, err = a.store.Overview(ctx)
		case "/admin/api/audit":
			body, err = a.store.Events(ctx, 150)
		case "/admin/api/sends":
			body, err = a.store.PendingSends(ctx)
		case "/admin/api/alerts":
			jobs := []AlertJob{}
			for _, channel := range []string{"pushover", "brrr"} {
				items, readErr := a.store.DueAlerts(ctx, channel, 1<<62)
				if readErr != nil {
					err = readErr
					break
				}
				jobs = append(jobs, items...)
			}
			body = map[string]any{"pending": jobs, "configured_channels": a.channels}
		default:
			return adminFailure(404, "not_found")
		}
		if err != nil {
			return adminFailure(503, "unavailable")
		}
		return ok(body)
	}
	if r.Method == http.MethodPost && r.URL.Path == "/admin/api/logout" {
		if err := a.store.EndAdminSession(ctx, cookie); err != nil {
			return adminFailure(503, "unavailable")
		}
		result := ok(map[string]bool{"logged_out": true})
		result.cookie = clearSessionCookie()
		return result
	}
	if r.Method == http.MethodPost && r.URL.Path == "/admin/api/password" {
		if err := a.passwordBudget(ctx); err != nil {
			return adminResult{response: quotaFailure(err)}
		}
		select {
		case a.passwordSlot <- struct{}{}:
			defer func() { <-a.passwordSlot }()
		default:
			return adminFailure(429, "password_check_busy")
		}
		var input struct {
			Current string `json:"current_password"`
			New     string `json:"new_password"`
		}
		if err := decodeRequest(r, &input); err != nil {
			return adminFailure(400, "invalid_request")
		}
		if err := a.store.ChangeOwnerPassword(ctx, input.Current, input.New); err != nil {
			if errors.Is(err, ErrDenied) {
				return adminFailure(403, "incorrect_password")
			}
			return adminFailure(400, "password_change_failed")
		}
		result := ok(map[string]bool{"password_changed": true})
		result.cookie = clearSessionCookie()
		return result
	}
	id, action := "", ""
	if strings.HasPrefix(r.URL.Path, "/admin/api/tokens/") {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/api/tokens/"), "/")
		if len(parts) > 2 || len(parts[0]) != 24 || !messageIDPattern.MatchString(parts[0]) {
			return adminFailure(404, "not_found")
		}
		id = parts[0]
		if len(parts) == 2 {
			action = parts[1]
		}
	}
	if (r.Method == http.MethodPost && r.URL.Path == "/admin/api/tokens") || (r.Method == http.MethodPut && id != "" && action == "") {
		var input struct {
			Name      string      `json:"name"`
			Policy    TokenPolicy `json:"policy"`
			ExpiresAt time.Time   `json:"expires_at"`
		}
		if err := decodeRequest(r, &input); err != nil {
			return adminFailure(400, "invalid_request")
		}
		if len(input.Name) < 1 || len(input.Name) > 80 || strings.ContainsAny(input.Name, "\r\n\x00") || input.Policy.Validate() != nil || !input.ExpiresAt.After(time.Now()) || input.ExpiresAt.After(time.Now().AddDate(5, 0, 0)) {
			return adminFailure(400, "invalid_token_policy")
		}
		if id == "" {
			token, raw, err := a.store.CreateToken(ctx, input.Name, input.Policy, input.ExpiresAt)
			if err != nil {
				return adminFailure(503, "unavailable")
			}
			return adminResult{response: response{status: 201, body: map[string]any{"token": token, "secret": raw}}}
		}
		if err := a.store.UpdateToken(ctx, id, input.Name, input.Policy, input.ExpiresAt); err != nil {
			if errors.Is(err, ErrNotFound) {
				return adminFailure(404, "not_found")
			}
			return adminFailure(503, "unavailable")
		}
		return ok(map[string]bool{"updated": true})
	}
	if id != "" && ((r.Method == http.MethodDelete && action == "") || (r.Method == http.MethodPost && action == "revoke")) {
		var err error
		if action == "revoke" {
			err = a.store.Revoke(ctx, id)
		} else {
			err = a.store.DeleteToken(ctx, id)
		}
		if errors.Is(err, ErrNotFound) {
			return adminFailure(404, "not_found")
		}
		if err != nil {
			return adminFailure(503, "unavailable")
		}
		return ok(map[string]bool{"completed": true})
	}
	return adminFailure(404, "not_found")
}
