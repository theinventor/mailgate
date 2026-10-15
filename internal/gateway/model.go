package gateway

import (
	"context"
	"errors"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	ScopeSearch = "mail.search"
	ScopeRead   = "mail.read"
	ScopeSend   = "mail.send"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrDenied        = errors.New("access denied")
	ErrQuota         = errors.New("quota exceeded")
	ErrConflict      = errors.New("idempotency key already used for another request")
	ErrBackend       = errors.New("mail backend unavailable")
	messageIDPattern = regexp.MustCompile(`^[a-fA-F0-9]{8,64}$`)
)

type TokenPolicy struct {
	Scopes            []string `json:"scopes"`
	RequestsPerMinute int      `json:"requests_per_minute"`
	ReadsPerDay       int      `json:"reads_per_day"`
	SendsPerDay       int      `json:"sends_per_day"`
	CopyOwner         string   `json:"copy_owner"`
	AllowedLabelIDs   []string `json:"allowed_label_ids,omitempty"`
	AllowedSenders    []string `json:"allowed_senders,omitempty"`
	AllowedRecipients []string `json:"allowed_recipients,omitempty"`
}

func DefaultTokenPolicy() TokenPolicy {
	return TokenPolicy{Scopes: []string{ScopeSearch, ScopeRead}, RequestsPerMinute: 30, ReadsPerDay: 500, SendsPerDay: 10, CopyOwner: "cc"}
}

func (p TokenPolicy) Has(scope string) bool { return slices.Contains(p.Scopes, scope) }

func (p TokenPolicy) Validate() error {
	if len(p.Scopes) == 0 || len(p.Scopes) > 3 {
		return errors.New("choose one or more of mail.search, mail.read, mail.send")
	}
	seen := map[string]bool{}
	for _, s := range p.Scopes {
		if (s != ScopeSearch && s != ScopeRead && s != ScopeSend) || seen[s] {
			return errors.New("unknown or duplicate permission")
		}
		seen[s] = true
	}
	if p.RequestsPerMinute < 1 || p.RequestsPerMinute > 10000 || p.ReadsPerDay < 1 || p.ReadsPerDay > 100000 || p.SendsPerDay < 0 || p.SendsPerDay > 1000 {
		return errors.New("invalid token quota")
	}
	if p.Has(ScopeSend) && p.SendsPerDay == 0 {
		return errors.New("send permission requires a positive daily send limit")
	}
	if p.CopyOwner != "cc" && p.CopyOwner != "bcc" && p.CopyOwner != "none" {
		return errors.New("copy_owner must be cc, bcc, or none")
	}
	if len(p.AllowedLabelIDs) > 100 || len(p.AllowedRecipients) > 100 || len(p.AllowedSenders) > 100 {
		return errors.New("too many policy entries")
	}
	for _, label := range p.AllowedLabelIDs {
		if label == "" || len(label) > 128 || strings.ContainsAny(label, "\r\n\x00") {
			return errors.New("invalid label ID")
		}
	}
	for _, addresses := range [][]string{p.AllowedSenders, p.AllowedRecipients} {
		for _, address := range addresses {
			if _, err := CanonicalAddress(address); err != nil {
				return errors.New("allowlists must contain exact email addresses")
			}
		}
	}
	return nil
}

type Token struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Policy    TokenPolicy `json:"policy"`
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	Revoked   bool        `json:"revoked"`
}

type Message struct {
	ID            string   `json:"id"`
	ThreadID      string   `json:"thread_id,omitempty"`
	From          string   `json:"from"`
	To            string   `json:"to,omitempty"`
	CC            string   `json:"cc,omitempty"`
	Subject       string   `json:"subject"`
	Date          string   `json:"date,omitempty"`
	Body          string   `json:"body,omitempty"`
	Untrusted     bool     `json:"untrusted_content"`
	LabelIDs      []string `json:"-"`
	ScanText      string   `json:"-"`
	Uninspectable bool     `json:"-"`
}

type SearchPage struct {
	IDs      []string
	NextPage string
}

type Outgoing struct {
	To      []string `json:"to"`
	CC      []string `json:"cc,omitempty"`
	BCC     []string `json:"bcc,omitempty"`
	Subject string   `json:"subject"`
	Body    string   `json:"body"`
}

type SentMessage struct {
	ID       string `json:"id"`
	ThreadID string `json:"thread_id,omitempty"`
}

type Backend interface {
	Search(context.Context, string, string, int) (SearchPage, error)
	Read(context.Context, string) (Message, error)
	Send(context.Context, Outgoing) (SentMessage, error)
}

func CanonicalAddress(value string) (string, error) {
	if len(value) > 320 || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("invalid email address")
	}
	a, err := mail.ParseAddress(value)
	if err != nil || a.Name != "" || a.Address != value || !strings.Contains(a.Address, "@") {
		return "", errors.New("use a bare email address")
	}
	return strings.ToLower(a.Address), nil
}

func containsAddress(addresses []string, address string) bool {
	for _, a := range addresses {
		if strings.EqualFold(a, address) {
			return true
		}
	}
	return false
}
