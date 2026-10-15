#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(dirname -- "$script_dir")
binary="$repo_dir/bin/mailgate"
gog_binary=""
account=""
owner=""
admin_origin=""
listen="127.0.0.1:8787"
admin_listen="127.0.0.1:8788"
upgrade=false

usage() {
  cat <<'USAGE'
Usage: sudo scripts/install.sh --binary PATH --gog-binary PATH \
  --account EMAIL --owner EMAIL --admin-origin https://HOST:9443
Optional: --listen 127.0.0.1:8787 --admin-listen 127.0.0.1:8788
Upgrade:  sudo scripts/install.sh --upgrade --binary PATH --gog-binary PATH

Installs this application's files and systemd units. Does not change firewall,
Tailscale, SSH, Google authorization, or start the service. No password prompt:
the first admin web visit sets the password automatically.
USAGE
}
while (($#)); do
  case "$1" in
    --binary|--gog-binary|--account|--owner|--admin-origin|--listen|--admin-listen)
      if (($# < 2)); then usage >&2; exit 2; fi
      case "$1" in
        --binary) binary=$2;; --gog-binary) gog_binary=$2;; --account) account=$2;;
        --owner) owner=$2;; --admin-origin) admin_origin=$2;; --listen) listen=$2;; --admin-listen) admin_listen=$2;;
      esac
      shift 2;;
    --upgrade) upgrade=true; shift;;
    -h|--help) usage; exit 0;;
    *) usage >&2; exit 2;;
  esac
done
if [[ $EUID != 0 ]]; then printf '%s\n' 'Run this installer as root.' >&2; exit 1; fi
if [[ ! -x "$binary" || ! -x "$gog_binary" ]]; then printf '%s\n' 'Both executable paths are required.' >&2; exit 1; fi
"$binary" version >/dev/null
gog_version=$("$gog_binary" --version)
if [[ "$gog_version" != 'v0.38.2 (03d192ff-mailgate.1)'* ]]; then printf '%s\n' 'Build the pinned GOG variant using scripts/build-gog.sh first.' >&2; exit 1; fi
if ! $upgrade; then
  if [[ -z "$account" || -z "$admin_origin" ]]; then usage >&2; exit 2; fi
  if [[ -e /etc/mailgate/config.json ]]; then printf '%s\n' 'Configuration exists; use --upgrade to preserve it.' >&2; exit 1; fi
fi
for target in /etc/mailgate /etc/mailgate/secrets /var/lib/mailgate /usr/local/lib/mailgate; do
  if [[ -L "$target" ]]; then printf '%s\n' 'Refusing symlinked application directory.' >&2; exit 1; fi
done
if ! getent passwd mailgate >/dev/null; then
  useradd --system --user-group --home-dir /var/lib/mailgate --shell "$(command -v nologin)" mailgate
fi
install -d -o root -g mailgate -m 0750 /etc/mailgate
install -d -o root -g root -m 0700 /etc/mailgate/secrets
install -d -o mailgate -g mailgate -m 0700 /var/lib/mailgate
install -d -o root -g root -m 0755 /usr/local/lib/mailgate
# Atomic rename also works while the previous executable is running.
install -o root -g root -m 0755 "$binary" /usr/local/bin/mailgate.new
mv -f /usr/local/bin/mailgate.new /usr/local/bin/mailgate
install -o root -g root -m 0755 "$gog_binary" /usr/local/lib/mailgate/gog.new
mv -f /usr/local/lib/mailgate/gog.new /usr/local/lib/mailgate/gog
if ! $upgrade; then
  /usr/local/bin/mailgate init --account "$account" --owner "${owner:-$account}" \
    --admin-origin "$admin_origin" --listen "$listen" --admin-listen "$admin_listen" \
    --gog-path /usr/local/lib/mailgate/gog >/dev/null
  chown root:mailgate /etc/mailgate/config.json
  chmod 0640 /etc/mailgate/config.json
fi
install -o root -g root -m 0644 "$repo_dir/deploy/mailgate.service" /etc/systemd/system/mailgate.service
install -o root -g root -m 0644 "$repo_dir/deploy/mailgate-maintain.service" /etc/systemd/system/mailgate-maintain.service
install -o root -g root -m 0644 "$repo_dir/deploy/mailgate-maintain.timer" /etc/systemd/system/mailgate-maintain.timer
systemctl daemon-reload
printf '%s\n' 'Installed. Follow docs/deployment.md to provision GOG, alerts, and private HTTPS, then start the service.'
