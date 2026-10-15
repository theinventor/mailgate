# Verification — 2026-10-14

Mailgate 0.1.0 was tested on an x86-64 Linux development host and cross-compiled for ARM64. Performance and network isolation on a physical Raspberry Pi have not been validated.

## Automated checks

- `make check`: unit/integration tests, race detector, and Go vet passed with Go 1.27.2.
- `npm test`: Chromium completed automatic password setup, generated-password validation, token CRUD, HTML escaping, audit/alerts pages, mobile layout, login/logout, and password rotation against fake Gmail and disposable state.
- Linux ARM64 and AMD64 binaries compiled for both Mailgate and the required GOG variant.
- The GOG patch applied without fuzzy matching. Regression tests exercised compose and raw CLI send paths with HTTP 429, 500, and 503 responses; each produced exactly one send POST. Raw sends remain unavailable through Mailgate.
- The gateway rejects the stock GOG release because its implicit retries could duplicate a send after an ambiguous response.
- systemd unit verification passed. The service runs as `mailgate`, with private state and systemd credentials.

## Live checks

- Private HTTPS admin state and agent health returned 200. First-visit owner setup was still pending at verification time; no admin password was chosen by the agent.
- GOG searched a randomly generated, nonexistent RFC message ID through Mailgate and returned an empty result in about 0.26 seconds. No actual email content was retrieved or email sent by these deployment checks.
- A sensitive search returned 200 with an empty array and delivered alerts through both Pushover and brrr. An authenticated attempt to use an admin route through the agent listener returned 404 and triggered both alert queues. All deployment test tokens were revoked.
- Application listeners were verified to bind only to loopback, with private Tailscale Serve exposing separate agent and admin HTTPS ports. The verified configuration contained no public Funnel permission.
- Owner-device isolation of the admin route and SSH was not established on the shared development host. It must be verified on a dedicated deployment before opening access to agents.

## Dependency scan and remaining review

Gateway `govulncheck` reported zero affecting vulnerabilities. The GOG variant updates the toolchain and network/crypto dependencies that were vulnerable in the original installed release.

GOG's binary scan still reports **GO-2026-5932**, the unmaintained `golang.org/x/crypto/openpgp` advisory. Its build dependency closure does not import that package or any of its subpackages; the build script explicitly checks this. The binary scanner reports wildcard OpenPGP symbols despite that evidence. This discrepancy is recorded for independent review; the GOG binary scan is not reported as clean.

No independent Claude review has been completed. Run `scripts/review-claude.sh` with an authenticated Claude CLI to request one; it uses only repository file-reading tools and writes its report under `docs/reviews/`.

Actual email sending was tested with mock transports, including mandatory owner copies, quotas, idempotency, and ambiguous failures. Delivery of a real Gmail send has not been tested. Deterministic filtering has the limitations documented in [security.md](security.md), including withholding entire messages with uninspectable attachments.

## Password policy update — 2026-10-14

The 16-character minimum was removed from setup and password changes in both the API and browser. Passwords remain nonempty and limited to 1,024 UTF-8 bytes. `make check`, ARM64/AMD64 builds, and the Chromium flow passed again. Tests now exercise setup with a one-character password, changing an existing password to one digit, login with the new password, and rejection of empty/oversized setup inputs. These checks used disposable test state, not the live owner password.
