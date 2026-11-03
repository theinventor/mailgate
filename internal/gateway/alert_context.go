package gateway

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Request previews are owner diagnostics, not copies of request bodies. Apply
// redaction before truncation so a long secret cannot leak its leading bytes.
var previewRedactions = []*regexp.Regexp{
	regexp.MustCompile(`(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`),
	regexp.MustCompile(`(?i)\b(?:mg_[0-9a-f]{24}\.[a-z0-9_-]+|mmb_[a-z0-9_-]+|gh[pousr]_[a-z0-9_]+|github_pat_[a-z0-9_]+|sk-[a-z0-9_-]{8,}|AIza[a-z0-9_-]{25,})`),
	regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[a-z0-9+/_=.:-]+`),
	regexp.MustCompile(`(?i)\b(?:password|passcode|token|(?:access|refresh|id)[-_ ]?token|api[-_ ]?key|(?:client[-_ ]?)?secret|otp|(?:verification|security|login|recovery)\s+code)["']?\s*(?::|=|\bis\b)\s*(?:"[^"]*"|'[^']*'|[^\s&]+)`),
	regexp.MustCompile(`(?i)https?://[^\s<>"']+`),
	regexp.MustCompile(`\b(?:[0-9][ -]?){4,}\b`),
	regexp.MustCompile(`\b[A-Za-z0-9_-]{32,}\b`),
}

func clipText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	if limit < 3 {
		return ""
	}
	n := limit - 3
	for n > 0 && !utf8.RuneStart(text[n]) {
		n--
	}
	return text[:n] + "..."
}

func requestPreview(text string, limit int) string {
	return diagnosticPreview(text, limit, true)
}

func botPreview(text string, limit int) string {
	return diagnosticPreview(text, limit, false)
}

func diagnosticPreview(text string, limit int, redactOpaque bool) string {
	text = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, norm.NFKC.String(strings.ToValidUTF8(text, "")))
	for index, pattern := range previewRedactions {
		// Owner-chosen bot names often look like long hyphenated identifiers.
		// Still redact recognizable credentials, but retain those display names.
		if !redactOpaque && index == len(previewRedactions)-1 {
			continue
		}
		text = pattern.ReplaceAllString(text, "[redacted]")
	}
	return clipText(strings.Join(strings.Fields(text), " "), limit)
}

func alertMessageContext(details map[string]any, message Message) {
	if messageIDPattern.MatchString(message.ID) {
		details["message_id"] = message.ID
	}
	details["message_from"] = requestPreview(message.From, 80)
	details["message_subject"] = requestPreview(message.Subject, 100)
}

func eventText(event Event, key string) string {
	value, _ := event.Details[key].(string)
	return value
}

func securityReason(reason string) string {
	if strings.HasPrefix(reason, "outbound_") {
		return "Outgoing content: " + securityReason(strings.TrimPrefix(reason, "outbound_"))
	}
	switch reason {
	case "unknown_endpoint":
		return "Unsupported API endpoint"
	case "disallowed_method":
		return "HTTP method not allowed"
	case "permission_denied":
		return "Token lacks the required permission"
	case "request_rate_limit":
		return "Request rate limit exceeded"
	case "recipient_not_allowed":
		return "Recipient is outside the token's allowlist"
	case "identity_document", "ssn_pattern":
		return "Identity document or Social Security information"
	case "payment_details", "payment_card_pattern":
		return "Payment or bank information"
	case "authentication_secret", "credential_pattern":
		return "Password, login code, or credential information"
	case "custom_sensitive_keyword":
		return "Owner-configured sensitive keyword"
	case "inspection_limit":
		return "Content exceeds the inspection limit"
	case "blocked_label":
		return "Email has an owner-blocked label"
	case "outside_mailbox_scope":
		return "Email is outside the token's mailbox access"
	case "uninspectable_message":
		return "Email could not be safely inspected"
	case "send_status_unknown":
		return "Send outcome is uncertain; check Sent mail before retrying"
	case "owner_test":
		return "Owner-requested notification test"
	default:
		return "Security policy triggered"
	}
}

func securityAlert(event Event, reason string) string {
	bot := botPreview(event.TokenName, 80)
	if bot == "" {
		bot = event.TokenID
	}
	if bot == "" {
		bot = "Owner / unauthenticated request"
	}
	method, path := eventText(event, "method"), eventText(event, "path")
	request := strings.TrimSpace(method + " " + path)
	if request == "" {
		request = event.Route
	}
	lines := []string{"Bot: " + bot, "Request: " + requestPreview(request, 160),
		"Reason: " + securityReason(reason) + " (" + requestPreview(reason, 48) + ")"}
	switch eventText(event, "trigger") {
	case "search_query":
		lines = append(lines, "Trigger: Search query; returned an empty result")
	case "search_result":
		lines = append(lines, "Trigger: Protected email encountered in search results")
	case "message":
		lines = append(lines, "Trigger: Requested email was withheld")
	case "outgoing_message":
		lines = append(lines, "Trigger: Outgoing message")
	}
	if event.Status != 0 {
		outcome := fmt.Sprintf("HTTP %d", event.Status)
		if event.Status >= 400 {
			if reason == "send_status_unknown" {
				outcome += "; delivery not confirmed"
			} else if event.Status >= 500 {
				outcome += "; request failed"
			} else {
				outcome += "; request rejected"
			}
		}
		if count, ok := event.Details["returned"]; ok {
			outcome += fmt.Sprintf("; %v returned", count)
		}
		if count, ok := event.Details["withheld"]; ok {
			outcome += fmt.Sprintf("; %v withheld", count)
		}
		lines = append(lines, "Result: "+outcome)
	}
	for _, field := range []struct{ key, label string }{
		{"query_preview", "Query"}, {"message_id", "Email ID"},
		{"message_from", "From"}, {"message_subject", "Subject"},
		{"recipient_preview", "Recipients"}, {"required_permission", "Required permission"},
	} {
		if value := eventText(event, field.key); value != "" {
			lines = append(lines, field.label+": "+requestPreview(value, 180))
		}
	}
	stamp := event.At
	if at, err := time.Parse(time.RFC3339Nano, stamp); err == nil {
		stamp = at.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	footer := "Time: " + stamp
	if event.Peer != "" {
		footer += "\nClient: " + event.Peer
	}
	if event.TokenID != "" {
		footer += "\nToken ID: " + event.TokenID
	}
	footer += fmt.Sprintf("\nAudit #%d; request %s", event.ID, event.RequestID)
	// Keep the audit reference even when the owner supplied a long bot name or
	// the request has several diagnostic fields. Both providers get the same text.
	footer = clipText(footer, 300)
	return clipText(strings.Join(lines, "\n"), 950-len(footer)-1) + "\n" + footer
}

func securityAlertTitle(message string) string {
	first, _, _ := strings.Cut(message, "\n")
	if name, ok := strings.CutPrefix(first, "Bot: "); ok {
		return "Mailgate: " + botPreview(name, 80)
	}
	return "Mailgate security alert"
}
