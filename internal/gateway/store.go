package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db  *sql.DB
	Dir string
}

const schema = `
CREATE TABLE IF NOT EXISTS tokens (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, digest BLOB NOT NULL,
 policy TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, request_id TEXT NOT NULL,
 token_id TEXT NOT NULL, action TEXT NOT NULL, route TEXT NOT NULL,
 status INTEGER NOT NULL, peer TEXT NOT NULL, details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_time ON audit(at);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL,
 channel TEXT NOT NULL, dedupe TEXT NOT NULL UNIQUE, message TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL,
 delivered_at INTEGER, last_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS alerts_pending ON alerts(channel, delivered_at, next_attempt);
CREATE TABLE IF NOT EXISTS quotas (
 name TEXT NOT NULL, window INTEGER NOT NULL, used INTEGER NOT NULL,
 PRIMARY KEY(name, window)
);
CREATE TABLE IF NOT EXISTS cursors (
 digest TEXT PRIMARY KEY, token_id TEXT NOT NULL, query_hash TEXT NOT NULL,
 page TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sends (
 token_id TEXT NOT NULL, key_hash TEXT NOT NULL, request_hash TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','sent','uncertain')),
 result TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL,
 PRIMARY KEY(token_id, key_hash)
);
CREATE TABLE IF NOT EXISTS owner (
 id INTEGER PRIMARY KEY CHECK(id=1), password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_sessions (
 digest TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires_at INTEGER NOT NULL
);
PRAGMA user_version=1;
`

func OpenStore(dir string) (*Store, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("state directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state directory must be a real directory with mode 0700")
	}
	path := filepath.Join(dir, "mailgate.db")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		_ = f.Close()
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("database must be a regular file with mode 0600")
	}
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "synchronous(FULL)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, Dir: dir}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var version int
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, err
	}
	if version > 1 {
		db.Close()
		return nil, errors.New("database was created by a newer version of mailgate")
	}
	if _, err = db.ExecContext(ctx, "PRAGMA journal_mode=WAL;"); err == nil {
		_, err = db.ExecContext(ctx, schema)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error                   { return s.db.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func randomString(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func hashText(s string) string { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }

func (s *Store) CreateToken(ctx context.Context, name string, p TokenPolicy, expiry time.Time) (Token, string, error) {
	var t Token
	if len(name) < 1 || len(name) > 80 || strings.ContainsAny(name, "\r\n\x00") {
		return t, "", errors.New("token name must be 1–80 characters without control characters")
	}
	if err := p.Validate(); err != nil {
		return t, "", err
	}
	if !expiry.After(time.Now()) || expiry.After(time.Now().AddDate(5, 0, 0)) {
		return t, "", errors.New("token expiry must be in the next five years")
	}
	ident := make([]byte, 12)
	if _, err := rand.Read(ident); err != nil {
		return t, "", err
	}
	secret, err := randomString(32)
	if err != nil {
		return t, "", err
	}
	t = Token{ID: hex.EncodeToString(ident), Name: name, Policy: p, CreatedAt: time.Now().UTC(), ExpiresAt: expiry.UTC()}
	raw := "mg_" + t.ID + "." + secret
	digest := sha256.Sum256([]byte(raw))
	policy, err := json.Marshal(p)
	if err != nil {
		return t, "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return t, "", err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, "INSERT INTO tokens(id,name,digest,policy,created_at,expires_at) VALUES(?,?,?,?,?,?)", t.ID, t.Name, digest[:], string(policy), t.CreatedAt.Unix(), t.ExpiresAt.Unix())
	if err != nil {
		return t, "", err
	}
	_, err = appendEvent(ctx, tx, Event{TokenID: t.ID, Action: "token.created", Details: map[string]any{"name": name, "policy": p, "expires_at": t.ExpiresAt}})
	if err != nil {
		return t, "", err
	}
	if err := tx.Commit(); err != nil {
		return t, "", err
	}
	return t, raw, nil
}

func (s *Store) Authenticate(ctx context.Context, raw string) (Token, error) {
	var t Token
	if len(raw) != 71 || !strings.HasPrefix(raw, "mg_") || raw[27] != '.' {
		return t, ErrDenied
	}
	id := raw[3:27]
	if _, err := hex.DecodeString(id); err != nil {
		return t, ErrDenied
	}
	var digest []byte
	var policy string
	var created, expires int64
	err := s.db.QueryRowContext(ctx, "SELECT id,name,digest,policy,created_at,expires_at,revoked FROM tokens WHERE id=?", id).Scan(&t.ID, &t.Name, &digest, &policy, &created, &expires, &t.Revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrDenied
	}
	if err != nil {
		return t, err
	}
	actual := sha256.Sum256([]byte(raw))
	if subtle.ConstantTimeCompare(actual[:], digest) != 1 || t.Revoked || expires <= time.Now().Unix() {
		return Token{}, ErrDenied
	}
	if json.Unmarshal([]byte(policy), &t.Policy) != nil || t.Policy.Validate() != nil {
		return Token{}, errors.New("invalid stored token policy")
	}
	t.CreatedAt, t.ExpiresAt = time.Unix(created, 0).UTC(), time.Unix(expires, 0).UTC()
	return t, nil
}

func (s *Store) Tokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,name,policy,created_at,expires_at,revoked FROM tokens ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Token{}
	for rows.Next() {
		var t Token
		var p string
		var c, e int64
		if err := rows.Scan(&t.ID, &t.Name, &p, &c, &e, &t.Revoked); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(p), &t.Policy); err != nil {
			return nil, err
		}
		t.CreatedAt, t.ExpiresAt = time.Unix(c, 0).UTC(), time.Unix(e, 0).UTC()
		result = append(result, t)
	}
	return result, rows.Err()
}

func (s *Store) Revoke(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, "UPDATE tokens SET revoked=1 WHERE id=?", id)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	if _, err = appendEvent(ctx, tx, Event{TokenID: id, Action: "token.revoked"}); err != nil {
		return err
	}
	return tx.Commit()
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func takeQuota(ctx context.Context, db sqlExecutor, name string, window int64, cost, limit int) error {
	if cost < 0 || cost > limit {
		return ErrQuota
	}
	r, err := db.ExecContext(ctx, `INSERT INTO quotas(name,window,used) VALUES(?,?,?) ON CONFLICT(name,window) DO UPDATE SET used=used+excluded.used WHERE quotas.used+excluded.used<=?`, name, window, cost, limit)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrQuota
	}
	return nil
}

func (s *Store) TakeQuota(ctx context.Context, name string, period time.Duration, cost, limit int) error {
	return takeQuota(ctx, s.db, name, time.Now().Unix()/int64(period/time.Second), cost, limit)
}

type Event struct {
	ID        int64          `json:"id"`
	At        string         `json:"at"`
	RequestID string         `json:"request_id"`
	TokenID   string         `json:"token_id,omitempty"`
	Action    string         `json:"action"`
	Route     string         `json:"route,omitempty"`
	Status    int            `json:"status,omitempty"`
	Peer      string         `json:"peer,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

func appendEvent(ctx context.Context, db sqlExecutor, e Event) (int64, error) {
	detail, err := json.Marshal(e.Details)
	if err != nil {
		return 0, err
	}
	if len(detail) > 16384 {
		return 0, errors.New("audit record too large")
	}
	r, err := db.ExecContext(ctx, `INSERT INTO audit(at,request_id,token_id,action,route,status,peer,details) VALUES(?,?,?,?,?,?,?,?)`, time.Now().UTC().Format(time.RFC3339Nano), e.RequestID, e.TokenID, e.Action, e.Route, e.Status, e.Peer, string(detail))
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

func (s *Store) Record(ctx context.Context, e Event, channels []string, reason string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	id, err := appendEvent(ctx, tx, e)
	if err != nil {
		return err
	}
	if reason != "" {
		// Pushes contain rule IDs, token IDs and an audit reference, never mail content.
		message := fmt.Sprintf("Mailgate: token %s triggered %s. Audit event %d; request %s.", e.TokenID, reason, id, e.RequestID)
		for _, channel := range channels {
			dedupe := hashText(fmt.Sprintf("%s|%s|%s|%s|%d", channel, e.TokenID, e.Route, reason, time.Now().Unix()/60))
			_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO alerts(event_id,channel,dedupe,message,next_attempt) VALUES(?,?,?,?,?)`, id, channel, dedupe, message, time.Now().Unix())
			if err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) Events(ctx context.Context, limit int) ([]Event, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("limit must be 1–1000")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,at,request_id,token_id,action,route,status,peer,details FROM audit ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Event{}
	for rows.Next() {
		var e Event
		var d string
		if err := rows.Scan(&e.ID, &e.At, &e.RequestID, &e.TokenID, &e.Action, &e.Route, &e.Status, &e.Peer, &d); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(d), &e.Details); err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

type AlertJob struct {
	ID          int64  `json:"id"`
	EventID     int64  `json:"event_id"`
	Channel     string `json:"channel"`
	Message     string `json:"message"`
	Attempts    int    `json:"attempts"`
	NextAttempt int64  `json:"next_attempt"`
	LastError   string `json:"last_error"`
}

func (s *Store) DueAlerts(ctx context.Context, channel string, now int64) ([]AlertJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,event_id,channel,message,attempts,next_attempt,last_error FROM alerts WHERE delivered_at IS NULL AND channel=? AND next_attempt<=? ORDER BY id LIMIT 10`, channel, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []AlertJob{}
	for rows.Next() {
		var j AlertJob
		if err := rows.Scan(&j.ID, &j.EventID, &j.Channel, &j.Message, &j.Attempts, &j.NextAttempt, &j.LastError); err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

func (s *Store) FinishAlert(ctx context.Context, j AlertJob, failure string) error {
	if failure == "" {
		_, err := s.db.ExecContext(ctx, "UPDATE alerts SET delivered_at=?,attempts=attempts+1,last_error='' WHERE id=?", time.Now().Unix(), j.ID)
		return err
	}
	delay := time.Duration(1<<min(j.Attempts, 10)) * 30 * time.Second
	_, err := s.db.ExecContext(ctx, "UPDATE alerts SET attempts=attempts+1,next_attempt=?,last_error=? WHERE id=?", time.Now().Add(delay).Unix(), failure, j.ID)
	return err
}

func (s *Store) SaveCursor(ctx context.Context, tokenID, query, page string) (string, error) {
	raw, err := randomString(32)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO cursors(digest,token_id,query_hash,page,expires_at) VALUES(?,?,?,?,?)", hashText(raw), tokenID, hashText(query), page, time.Now().Add(15*time.Minute).Unix())
	return raw, err
}

func (s *Store) LoadCursor(ctx context.Context, raw, tokenID, query string) (string, error) {
	if len(raw) != 43 {
		return "", ErrNotFound
	}
	var page string
	err := s.db.QueryRowContext(ctx, "SELECT page FROM cursors WHERE digest=? AND token_id=? AND query_hash=? AND expires_at>?", hashText(raw), tokenID, hashText(query), time.Now().Unix()).Scan(&page)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return page, err
}

type SendRecord struct {
	State  string      `json:"state"`
	Result SentMessage `json:"result"`
}

// BeginSend durably commits the send intent and quota before Gmail is contacted.
// An existing intent is never executed again, even after a crash or timeout.
func (s *Store) BeginSend(ctx context.Context, t Token, key, fingerprint string, event Event) (SendRecord, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SendRecord{}, false, err
	}
	defer tx.Rollback()
	var record SendRecord
	var oldHash, result string
	err = tx.QueryRowContext(ctx, "SELECT request_hash,state,result FROM sends WHERE token_id=? AND key_hash=?", t.ID, hashText(key)).Scan(&oldHash, &record.State, &result)
	if err == nil {
		if oldHash != fingerprint {
			return record, false, ErrConflict
		}
		if err = json.Unmarshal([]byte(result), &record.Result); err != nil {
			return record, false, err
		}
		return record, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return record, false, err
	}
	var active int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM tokens WHERE id=? AND revoked=0 AND expires_at>?", t.ID, time.Now().Unix()).Scan(&active); err != nil {
		return record, false, err
	}
	if active != 1 {
		return record, false, ErrDenied
	}
	if err = takeQuota(ctx, tx, "sends:"+t.ID, time.Now().Unix()/86400, 1, t.Policy.SendsPerDay); err != nil {
		return record, false, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO sends(token_id,key_hash,request_hash,state,created_at) VALUES(?,?,?,'pending',?)", t.ID, hashText(key), fingerprint, time.Now().Unix()); err != nil {
		return record, false, err
	}
	event.Action = "send.intent"
	if _, err = appendEvent(ctx, tx, event); err != nil {
		return record, false, err
	}
	if err = tx.Commit(); err != nil {
		return record, false, err
	}
	return SendRecord{State: "pending"}, true, nil
}

func (s *Store) FinishSend(ctx context.Context, tokenID, key string, sent SentMessage, uncertain bool) error {
	state := "sent"
	if uncertain {
		state = "uncertain"
	}
	result, err := json.Marshal(sent)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "UPDATE sends SET state=?,result=? WHERE token_id=? AND key_hash=? AND state='pending'", state, string(result), tokenID, hashText(key))
	return err
}

func (s *Store) PendingSends(ctx context.Context) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT token_id,key_hash,state,created_at FROM sends WHERE state!='sent' ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var t, k, state string
		var at int64
		if err := rows.Scan(&t, &k, &state, &at); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"token_id": t, "key_hash": k, "state": state, "created_at": time.Unix(at, 0).UTC()})
	}
	return items, rows.Err()
}

func (s *Store) Maintain(ctx context.Context, auditDays int) error {
	if auditDays < 7 || auditDays > 3650 {
		return errors.New("audit retention must be 7–3650 days")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []struct {
		sql   string
		value any
	}{
		{"DELETE FROM audit WHERE at < ?", time.Now().AddDate(0, 0, -auditDays).UTC().Format(time.RFC3339Nano)},
		{"DELETE FROM alerts WHERE delivered_at IS NOT NULL AND delivered_at < ?", time.Now().AddDate(0, 0, -auditDays).Unix()},
		{"DELETE FROM cursors WHERE expires_at < ?", time.Now().Unix()},
		{"DELETE FROM admin_sessions WHERE expires_at < ?", time.Now().Unix()},
		{"DELETE FROM quotas WHERE name IN ('admin','admin-login-minute') AND window < ?", time.Now().Unix()/60 - 2},
		{"DELETE FROM quotas WHERE name='admin-login-hour' AND window < ?", time.Now().Unix()/3600 - 2},
		{"DELETE FROM quotas WHERE (name LIKE 'reads:%' OR name LIKE 'sends:%') AND window < ?", time.Now().Unix()/86400 - 2},
		{"DELETE FROM quotas WHERE (name LIKE 'requests:%' OR name='global') AND window < ?", time.Now().Unix()/60 - 2},
	} {
		if _, err = tx.ExecContext(ctx, q.sql, q.value); err != nil {
			return err
		}
	}
	if _, err = appendEvent(ctx, tx, Event{Action: "maintenance.completed", Details: map[string]any{"audit_retention_days": auditDays}}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Backup(ctx context.Context, destination string) error {
	if !filepath.IsAbs(destination) {
		return errors.New("backup path must be absolute")
	}
	f, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "VACUUM INTO ?", destination)
	return err
}
