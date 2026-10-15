package gateway

import (
	"net/mail"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

type rule struct {
	name    string
	pattern *regexp.Regexp
}

type Inspector struct {
	rules         []rule
	extra         []string
	blockedLabels []string
}

func NewInspector(c Config) *Inspector {
	i := &Inspector{blockedLabels: c.BlockedLabelIDs}
	patterns := []struct{ name, expression string }{
		{"identity_document", `\b(driver\s*s?\s*licen[sc]e|driving\s+licen[sc]e|passport|social\s*security|ssn|national\s+identity|tax\s+return)\b`},
		{"payment_details", `\b(credit\s*card|debit\s*card|card\s+number|cvv|cvc|bank\s+account|routing\s+number|iban)\b`},
		{"authentication_secret", `\b(password|passcode|one\s*time\s+(password|code)|verification\s+code|security\s+code|login\s+(code|link)|sign\s*in\s+(code|link)|recovery\s+(code|key)|backup\s+codes?|reset\s+(link|code)|api\s*key|access\s*token|refresh\s*token|private\s*key|secret\s*key|seed\s+phrase|mnemonic|2fa|two\s+factor|mfa)\b`},
	}
	for _, p := range patterns {
		i.rules = append(i.rules, rule{p.name, regexp.MustCompile(p.expression)})
	}
	for _, k := range c.SensitiveKeywords {
		i.extra = append(i.extra, normalize(k))
	}
	return i
}

func normalize(s string) string {
	s = norm.NFKC.String(strings.ToLower(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Cf, r), unicode.Is(unicode.Mn, r):
		case unicode.IsLetter(r), unicode.IsNumber(r):
			b.WriteRune(r)
		default:
			b.WriteByte(' ')
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

var ssnPattern = regexp.MustCompile(`\b[0-9]{3}[- ][0-9]{2}[- ][0-9]{4}\b`)
var cardPattern = regexp.MustCompile(`(?:[0-9][ -]?){12,18}[0-9]`)
var secretPattern = regexp.MustCompile(`(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAIza[0-9A-Za-z_-]{25,}|\b(?:gh[pousr]_|github_pat_|sk-[a-zA-Z0-9_-]{8,})[a-zA-Z0-9_-]{12,})`)

func (i *Inspector) Check(text string) string {
	if len(text) > 2<<20 {
		return "inspection_limit"
	}
	n := normalize(text)
	for _, r := range i.rules {
		if r.pattern.MatchString(n) {
			return r.name
		}
	}
	for _, k := range i.extra {
		if strings.Contains(n, k) {
			return "custom_sensitive_keyword"
		}
	}
	if ssnPattern.MatchString(n) {
		return "ssn_pattern"
	}
	if secretPattern.MatchString(text) {
		return "credential_pattern"
	}
	for _, candidate := range cardPattern.FindAllString(n, -1) {
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, candidate)
		if len(digits) >= 13 && len(digits) <= 19 && luhn(digits) {
			return "payment_card_pattern"
		}
	}
	return ""
}

func luhn(s string) bool {
	sum, nonzero := 0, false
	for x := len(s) - 1; x >= 0; x-- {
		n := int(s[x] - '0')
		if n != 0 {
			nonzero = true
		}
		if (len(s)-1-x)%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return nonzero && sum%10 == 0
}

func (i *Inspector) Message(m Message, p TokenPolicy) string {
	if m.Uninspectable {
		return "uninspectable_message"
	}
	for _, label := range m.LabelIDs {
		for _, denied := range i.blockedLabels {
			if label == denied {
				return "blocked_label"
			}
		}
	}
	if len(p.AllowedLabelIDs) > 0 {
		allowed := false
		for _, label := range m.LabelIDs {
			for _, permitted := range p.AllowedLabelIDs {
				if label == permitted {
					allowed = true
				}
			}
		}
		if !allowed {
			return "outside_mailbox_scope"
		}
	}
	if len(p.AllowedSenders) > 0 {
		a, err := mail.ParseAddress(m.From)
		if err != nil || !containsAddress(p.AllowedSenders, a.Address) {
			return "outside_mailbox_scope"
		}
	}
	return i.Check(strings.Join([]string{m.From, m.To, m.CC, m.Subject, m.Date, m.Body, m.ScanText}, "\n"))
}
