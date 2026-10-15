# Deployment

Target: a dedicated Raspberry Pi running 64-bit Raspberry Pi OS Lite or another current Linux distribution with systemd. The service uses one Go binary, embedded web assets, SQLite, and the direct GOG executable. A compiler, Node, Redis, and a separate database server are unnecessary on the Pi.

## Network layout

| Listener | Bind | Exposure |
| --- | --- | --- |
| Agent API | `127.0.0.1:8787` | Private HTTPS port 9444 |
| Owner admin | `127.0.0.1:8788` | Private HTTPS port 9443, owner device only |

Choose unused loopback ports if the host already runs services. No Mailgate listener binds a LAN wildcard or public interface. TLS is terminated by a private reverse proxy.

For tailnet access, use **Tailscale Serve**, which is private to the tailnet. **Do not enable Funnel**, router port forwarding, or an internet-facing proxy. Check existing Serve/Funnel routes before installation: a preexisting public proxy to the same loopback port would expose a new service. See the [official Serve documentation](https://tailscale.com/docs/reference/tailscale-cli/serve).

Apply [the example tailnet policy](../deploy/tailnet-policy.example.hujson), adapted to your actual devices, before opening the admin listener. Grants are additive: an existing allow-all rule overrides the intended isolation. Owner-device access must use a dedicated device tag or device IP, not merely the owner's login identity if agent machines share that identity. Keep SSH and port 9443 unreachable from agent devices.

**Automatic first-visit setup means the first device allowed to reach the admin listener can set the password.** There is deliberately no setup link or bootstrap secret. Restrict the admin network route to the owner's trusted device before the first visit. Once initialized, setup closes atomically and stays closed across restarts.

If only the physical LAN is desired, use a TLS reverse proxy bound to the host's specific private LAN address with a certificate trusted by the owner's browser. Proxy the two ports separately and firewall the admin port to the owner device. Set `admin_origin` to that exact HTTPS origin. Do not weaken Secure cookies or enable plain HTTP login. Outbound HTTPS remains necessary for Google and the alert providers.

## Install

Build the matching ARM64 binary on the development host with `make release`. Use the Mailgate build of GOG **v0.38.2**, the adapter's tested command/JSON version. Its source comes from [the official GOG repository](https://github.com/openclaw/gogcli/tree/v0.38.2). Do not install a shell wrapper that imports another user's credential environment.

`scripts/build-gog.sh /absolute/path/to/gog-linux-arm64 arm64` builds that pinned source with Go 1.27.2 and updated network/crypto dependencies. It also applies [the send patch](../patches/gog-single-attempt-send.patch), disabling automatic retries of Gmail send requests. The upstream release retries some failed POSTs, which could duplicate an email after an ambiguous response. The build runs a local mock-server regression test against both send paths and embeds marker `03d192ff-mailgate.1`; both the installer and gateway reject other builds. The maintained command/JSON contract stays at v0.38.2.

Replace the example account, owner address, and private hostname below with your own values.

```sh
sudo scripts/install.sh \
  --binary dist/mailgate-linux-arm64 \
  --gog-binary /path/to/direct/gog \
  --account owner@example.com \
  --owner owner@example.com \
  --admin-origin https://YOUR-PI.YOUR-TAILNET.ts.net:9443
```

The installer creates the unprivileged `mailgate` account, private directories, configuration, and systemd units. It does not start the service, modify SSH/firewall/tailnet policy, or request an admin password. Existing configuration is never overwritten. `--upgrade` replaces binaries and units while retaining state and configuration; restart explicitly after validation.

## Google and notification credentials

Provision these files, owned by root and mode **0600**, inside `/etc/mailgate/secrets` (directory mode **0700**):

- `gog-keyring-password`: password for GOG's encrypted file keyring.
- `pushover-app-token`: Pushover application token.
- `pushover-user-key`: the owner's Pushover user key.
- `brrr-key`: the owner's brrr shared/device webhook key.

Keep values out of command arguments, source control, chat transcripts, and logs. The service receives private copies through systemd `LoadCredential`. `require_alerts` defaults to true: missing alert credentials prevent startup. Provider outages after startup are handled by the durable delivery queues; inspect their pending count and service logs.

GOG home is `/var/lib/mailgate/gog`, mode 0700, owned by `mailgate`. With `--home`, GOG v0.38.2 uses `config/config.json`, `data/credentials.json`, and `data/keyring/`. This differs from the legacy `~/.config/gogcli` layout. Store files with mode 0600. Authorize the personal Google account using normal user OAuth, or securely provision its existing encrypted keyring and OAuth client credentials. Mailgate supports broad Google authorization; its token policy controls agent access independently of the underlying OAuth scopes. Never share this directory or keyring password with agents.

Provision a separate GOG home for the service account, even if another GOG installation already exists on the host. Keep the service's credential copies and notification settings in the private directories above.

## Start and open the private UI

With credentials provisioned and the network policy in place:

```sh
sudo systemctl enable --now mailgate.service mailgate-maintain.timer
sudo systemctl status mailgate.service --no-pager
sudo journalctl -u mailgate.service -n 30 --no-pager
sudo tailscale serve --bg --https=9443 http://127.0.0.1:8788
sudo tailscale serve --bg --https=9444 http://127.0.0.1:8787
tailscale serve status --json
tailscale funnel status --json
```

If you changed the loopback ports, update the proxy targets accordingly. Confirm neither new port has `AllowFunnel: true`. Do not run `tailscale serve reset` on a shared host; it would remove unrelated routes.

Open `https://YOUR-PI.YOUR-TAILNET.ts.net:9443/admin/`. The page detects the empty owner configuration and opens password setup. Generate or choose a password, save it, and continue. The service stores an Argon2id hash, never a recoverable password. Agent tokens are created in the web interface. Tokens cannot grant deletion, settings changes, raw CLI access, or admin access.

Before inviting agents, verify from an agent machine that 9444 is reachable while 9443 and SSH are blocked. A request to `/admin/api/setup` through the agent port must fail even when its Host header is forged. Search a harmless unique message ID to check Google connectivity, then a sensitive phrase to check empty-result behavior and both notification providers. Revoke the test token afterward.

## Maintenance, backup, migration

- `mailgate-maintain.timer` runs daily with a 90-day audit retention policy. It prunes expired sessions/cursors and stale counters. It preserves send idempotency records. Monitor disk usage and pending alerts. A database write failure causes requests to fail closed.
- Run state commands as the service account: `sudo -u mailgate /usr/local/bin/mailgate tokens list`, `audit`, `sends`, or `backup --output /var/lib/mailgate/backup-YYYY-MM-DD.db`. A backup destination must be new and private. SQLite's backup command produces a consistent snapshot; do not copy a live database without its WAL.
- For migration, stop the old service, transfer the SQLite database, GOG home, and root-only secret files over an authenticated encrypted connection, restore ownership/modes, and update `admin_origin` for the Pi. Preserve the owner record so password setup does not reopen. Start the Pi, verify it, then retire the temporary deployment and its credential copies.
- Password changes happen in Settings and invalidate every admin session. There is no unauthenticated password-reset endpoint. If the password is lost, physical/root recovery is required; do not delete the owner record while the admin route is available to other devices.
- Final SSH policy is an operator step after deployment: restrict OpenSSH to the owner, remove temporary deployment keys, and disable Tailscale SSH if it would bypass that policy. Test a second owner connection before closing the deployment session. The installer does not change SSH settings.

The systemd unit limits memory to 512 MiB, GOG concurrency to two, inbound connections, subprocess output, request sizes, and timeouts. Measure memory use and latency on the target hardware before relying on its capacity. Gmail latency and the cost of fetching/inspecting every candidate dominate search performance.
