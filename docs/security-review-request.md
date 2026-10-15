# Claude security review request

Review the Mailgate implementation in this repository. This is a read-only review: use Read, Glob, and Grep only. Do not edit files, run commands, access external applications, or read outside this repository. Do not inspect live credentials under /etc, /var/lib, home directories, or environment files. Do not send notifications or contact Gmail.

Read README.md, docs/security.md, docs/deployment.md, cmd/mailgate, internal/gateway (including browser files and tests), deploy, and scripts. Identify exploitable security issues and substantive correctness problems. Prioritize actual attack paths over generic advice. For every finding provide severity, file and line, attacker prerequisites, concrete reproduction or reasoning, and an actionable fix. Distinguish definite defects from limitations. Include an overall assessment and missing tests. Return a concise Markdown review in your final response.

Intentional requirements accepted by the owner:

- A full-access GOG Google authorization lives under the service account. The microservice, not Google OAuth scope narrowing, implements agent permissions.
- Admin password creation happens automatically in the browser on the first visit if no owner exists. There is no setup link, bootstrap token, or interactive SSH password prompt. The admin network route must be restricted to the owner device for first setup; subsequent visits require the password.
- At the owner's explicit request, admin passwords have no complexity or minimum-length policy beyond being nonempty. The 1,024-byte input limit, Argon2id hashing, and login throttling remain in place.
- Agent and admin listeners are separate loopback ports. Deployment uses private HTTPS. No public Funnel is permitted. Root on the protected host is outside the protection boundary. A shared development host does not provide the intended dedicated-host isolation.
- Sensitive searches deliberately return successful empty results and trigger alerts. Message-content filtering is deterministic, conservative, and documented as imperfect. Messages with uninspectable attachments are withheld entirely.
- Agent requests expose only search/read/plain text send, with optional server-enforced CC/BCC, quotas, durable audit, and no mailbox mutation/settings/Drive endpoints.

Verification already run: Go tests, race detection, go vet, browser setup/login/CRUD/password-change/XSS/mobile tests, ARM64 cross-compilation, and gateway vulnerability scan with Go 1.27.2. A live harmless unique message-ID query returned 200/empty through GOG. A sensitive query returned 200/empty and both notification channels delivered successfully. The tested deployment uses loopback listeners behind private HTTPS, with no public Funnel permission.

GOG v0.38.2 is rebuilt with Go 1.27.2 and x/net v0.61.0, x/crypto v0.58.0, x/text v0.43.0 by scripts/build-gog.sh. A local patch disables GOG's implicit Gmail send retries using its WithoutRetries context; the gateway requires build marker 03d192ff-mailgate.1. Regression tests exercise both CLI send paths through its retry transport and assert one POST on 429/500/503 responses. See docs/verification.md for verification limits and the outstanding binary-scanner advisory. Credentials are not present in this repository. Do not treat test fixture passwords or example domains as live secrets.
