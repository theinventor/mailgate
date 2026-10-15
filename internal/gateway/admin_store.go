package gateway

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Fixed parameters prevent a corrupt hash from causing unbounded allocations.
// Only one KDF runs at a time in the HTTP handler (64 MiB per verification).
const passwordPrefix = "$argon2id$v=19$m=65536,t=3,p=1$"

func passwordHash(password string) (string, error) {
	if !utf8.ValidString(password) || password == "" || len(password) > 1024 {
		return "", errors.New("password must be nonempty UTF-8 and at most 1024 bytes")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, 3, 65536, 1, 32)
	return passwordPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}

func verifyPassword(hash, password string) bool {
	if len(password) > 1024 || !strings.HasPrefix(hash, passwordPrefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(hash, passwordPrefix), "$")
	if len(parts) != 2 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil || len(salt) != 16 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil || len(want) != 32 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, 3, 65536, 1, 32)
	return subtle.ConstantTimeCompare(actual, want) == 1
}

func (s *Store) OwnerReady(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM owner").Scan(&count)
	return count == 1, err
}

// The first web visitor can initialize the owner. Network access must be
// restricted to the owner during installation, before agent access is granted.
func (s *Store) SetupOwner(ctx context.Context, password string) error {
	ready, err := s.OwnerReady(ctx)
	if err != nil {
		return err
	}
	if ready {
		return ErrDenied
	}
	hash, err := passwordHash(password)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// INSERT OR IGNORE atomically closes setup, including concurrent first visits.
	r, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO owner(id,password_hash) VALUES(1,?)", hash)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrDenied
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM admin_sessions"); err != nil {
		return err
	}
	if _, err = appendEvent(ctx, tx, Event{Action: "owner.password_set"}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ChangeOwnerPassword(ctx context.Context, current, replacement string) error {
	var previous string
	if err := s.db.QueryRowContext(ctx, "SELECT password_hash FROM owner WHERE id=1").Scan(&previous); err != nil {
		return err
	}
	if !verifyPassword(previous, current) {
		return ErrDenied
	}
	hash, err := passwordHash(replacement)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, "UPDATE owner SET password_hash=? WHERE id=1 AND password_hash=?", hash, previous)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrDenied
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM admin_sessions"); err != nil {
		return err
	}
	if _, err = appendEvent(ctx, tx, Event{Action: "owner.password_changed"}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) VerifyOwner(ctx context.Context, password string) (bool, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, "SELECT password_hash FROM owner WHERE id=1").Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return verifyPassword(hash, password), nil
}

type AdminSession struct {
	CSRF      string    `json:"csrf"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Store) NewAdminSession(ctx context.Context) (AdminSession, string, error) {
	var session AdminSession
	raw, err := randomString(32)
	if err != nil {
		return session, "", err
	}
	csrf, err := randomString(32)
	if err != nil {
		return session, "", err
	}
	session = AdminSession{CSRF: csrf, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	_, err = s.db.ExecContext(ctx, "INSERT INTO admin_sessions(digest,csrf,expires_at) VALUES(?,?,?)", hashText(raw), csrf, session.ExpiresAt.Unix())
	return session, raw, err
}

func (s *Store) AdminSession(ctx context.Context, raw string) (AdminSession, error) {
	var session AdminSession
	if len(raw) != 43 {
		return session, ErrDenied
	}
	var expiry int64
	err := s.db.QueryRowContext(ctx, "SELECT csrf,expires_at FROM admin_sessions WHERE digest=?", hashText(raw)).Scan(&session.CSRF, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return session, ErrDenied
	}
	if err != nil {
		return session, err
	}
	if expiry <= time.Now().Unix() {
		return session, ErrDenied
	}
	session.ExpiresAt = time.Unix(expiry, 0).UTC()
	return session, nil
}

func (s *Store) EndAdminSession(ctx context.Context, raw string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM admin_sessions WHERE digest=?", hashText(raw))
	return err
}

func (s *Store) UpdateToken(ctx context.Context, id, name string, p TokenPolicy, expiry time.Time) error {
	if len(name) < 1 || len(name) > 80 || strings.ContainsAny(name, "\r\n\x00") {
		return errors.New("invalid token name")
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if !expiry.After(time.Now()) || expiry.After(time.Now().AddDate(5, 0, 0)) {
		return errors.New("expiry must be in the next five years")
	}
	policy, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, "UPDATE tokens SET name=?,policy=?,expires_at=? WHERE id=?", name, string(policy), expiry.Unix(), id)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	if _, err = appendEvent(ctx, tx, Event{TokenID: id, Action: "token.updated", Details: map[string]any{"name": name, "policy": p, "expires_at": expiry}}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteToken(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, "DELETE FROM tokens WHERE id=?", id)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM cursors WHERE token_id=?", id); err != nil {
		return err
	}
	if _, err = appendEvent(ctx, tx, Event{TokenID: id, Action: "token.deleted"}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Overview(ctx context.Context) (map[string]int, error) {
	result := map[string]int{}
	for name, query := range map[string]string{
		"active_tokens":   "SELECT COUNT(*) FROM tokens WHERE revoked=0 AND expires_at>unixepoch()",
		"requests_today":  "SELECT COUNT(*) FROM audit WHERE action='request.completed' AND at>=strftime('%Y-%m-%d','now')",
		"flags_today":     "SELECT COUNT(*) FROM audit WHERE json_extract(details,'$.rule') IS NOT NULL AND at>=strftime('%Y-%m-%d','now')",
		"pending_alerts":  "SELECT COUNT(*) FROM alerts WHERE delivered_at IS NULL",
		"uncertain_sends": "SELECT COUNT(*) FROM sends WHERE state IN ('pending','uncertain')",
	} {
		var count int
		if err := s.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
			return nil, err
		}
		result[name] = count
	}
	return result, nil
}
