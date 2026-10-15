# Security model and limits

## Trust boundary

The protected boundary is the dedicated machine and its service account. A full-access Google credential is intentionally behind Mailgate. Tokens describe narrower capabilities but do not alter that Google authorization. Root on this host, the `mailgate` account, a compromised service process, or the owner's admin password can cross that boundary. Root on other machines must not imply SSH, admin-port, filesystem, or backup access to this host. A shared development host does not provide a dedicated host's isolation.

The admin and agent handlers run in the same binary but have separate listeners, connection limits, request slots, and authentication. Only the admin listener exposes setup/login/token management. The production API listener rejects admin paths regardless of Host header. Admin authentication uses a password and a random server-side session; bearer tokens never grant admin access.

The first admin visit is intentionally automatic. Network restrictions identify who may initialize the service. Password creation is an atomic insert into a single owner record, preventing concurrent setup from replacing an established password. No invitation URL or setup credential exists.

## Implemented controls

- Argon2id password hashes: 64 MiB, three iterations, one lane, fresh 128-bit salt, 256-bit result. One concurrent password computation, five attempts per minute and forty per hour, persisted across restarts. Browser-generated passwords use Web Crypto randomness.
- Owner-selected passwords have no complexity or minimum-length policy beyond requiring a nonempty value. A 1,024-byte UTF-8 size limit bounds processing. This applies to setup and password changes.
- 256-bit random bearer secrets; only SHA-256 hashes are stored. Token IDs are public metadata. Every request checks current token state, expiry, and policy. Token deletion retains the audit and send history.
- One-hour sessions, hashed random session IDs, Secure/HttpOnly/SameSite=Strict cookies, exact configured Host/Origin checks, CSRF tokens on authenticated mutations, strict CSP, no external scripts/fonts, and no localStorage token cache. Password changes invalidate sessions.
- Loopback-only application sockets, bounded HTTP bodies/headers/connections and timeouts, persistent global and per-token quotas, two GOG processes by default, strict input schemas, duplicate JSON key rejection, fixed subprocess arguments, no shell, and a minimal subprocess environment.
- GOG read commands have an exact command allowlist and runtime `--readonly --gmail-no-send`. Sending has a distinct exact allowlist. Agents cannot override the account, OAuth client, GOG home, flags, URLs, or credential source.
- Per-token allowed label IDs and senders are enforced on fetched messages, independent of the search query. Sender matching is a mailbox filter, not proof that a sender header is authentic. Global blocked labels override allowlists.
- Sending validates bare recipient addresses and rejects header injection, arbitrary MIME, attachments, caller BCC, and sender overrides. The server adds the owner CC/BCC after validation; that enforced copy is exempt from the recipient allowlist.
- Durable audit preflight precedes Google access. Responses are buffered until the final audit write succeeds. Sending commits its intent and quota before contacting Gmail. Lost or uncertain responses leave an unreplayable pending/uncertain record for manual review.
- The required GOG build disables its automatic retries for Gmail send POSTs. Mock-server tests return 429, 500, and 503 and verify exactly one POST for both send paths. Application idempotency alone would not prevent retries inside GOG; the gateway checks the patched build marker at startup.
- Alerts are enqueued transactionally with audit events. Pushover and brrr have independent workers, timeout/retry/backoff, per-rule/token/minute coalescing, fixed endpoints, and no redirects. Delivery is at least once; a crash after delivery but before acknowledgement can duplicate a push.

## Sensitive content

Search terms are normalized and checked for configured keywords, identity/payment/authentication terminology, SSN-like patterns, valid Luhn card numbers, and some credential formats. A matching search gets the same JSON shape as a truly empty result. Search queries are not forwarded to Google when flagged.

For ordinary queries, Mailgate fetches and inspects each candidate before releasing even its subject or sender. It examines decoded text, HTML text, raw HTML, alternate MIME parts, and the fields it returns. It withholds messages with uninspectable attachments, unexpected binary parts, invalid encoding, or excessive size/depth. Direct message-ID reads undergo the same checks. Outbound content is checked too.

This is deterministic filtering, not a proof that arbitrary email cannot contain sensitive information. Images, encrypted content, novel wording, uncommon identifiers, malicious encodings, and false positives require a conservative policy. Version 1 withholds entire messages that contain uninspectable attachments, including common inline signature images. There is no OCR or PDF extraction. Allowlisted labels and blocked sensitive folders provide stronger bounds than keywords alone. Configure `sensitive_keywords` and `blocked_label_ids` in the root-owned configuration, then restart.

HTTP success/empty results do not guarantee perfect concealment: timing, quotas, and different surrounding mail can reveal that filtering exists. Alert delivery depends on working external providers and connectivity. The service preserves failed deliveries for retry and exposes queue state in the admin interface.

## Audit data

Audit records contain event/request IDs, token identity, route, time/status, rule, counts, message IDs, and hashed queries/subjects/bodies/idempotency keys where relevant. Send intents include recipient addresses so the owner can inspect outbound destinations. Passwords, bearer secrets, OAuth tokens, raw queries, email bodies, and GOG stderr are excluded. Audit storage is private but is not cryptographically immutable against root or a fully compromised service process. Treat backups as sensitive account data.

Tests cover auth separation, automatic setup races, CSRF/Host/Origin restrictions, password rotation, token lifecycle, persistent atomic quotas, sensitive queries/results/direct reads, MIME alternatives, scope restrictions, required copies, input/CLI injection, subprocess time/output bounds, durable send outcomes, audit failure, cursor binding, alert persistence, browser XSS escaping, and mobile UI behavior. A successful test suite and dependency scan do not replace deployment/network verification or ongoing updates.
