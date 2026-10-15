#!/usr/bin/env bash
set -euo pipefail

# Keep the command/JSON contract pinned, while updating its network/crypto
# dependencies and toolchain to the versions audited with this gateway.
export GOTOOLCHAIN=go1.27.2
export CGO_ENABLED=0
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
build_dir=$(mktemp -d -t mailgate-gog-build.XXXXXXXX)
trap 'rm -rf -- "$build_dir"' EXIT
output=${1:?Usage: scripts/build-gog.sh ABSOLUTE_OUTPUT_PATH [amd64|arm64]}
architecture=${2:-amd64}
case "$output" in /*) ;; *) printf '%s\n' 'Output path must be absolute.' >&2; exit 2;; esac
case "$architecture" in amd64|arm64) ;; *) exit 2;; esac
source_dir=$(go mod download -json github.com/openclaw/gogcli@v0.38.2 | python3 -c 'import json,sys; print(json.load(sys.stdin)["Dir"])')
cp -a "$source_dir/." "$build_dir/"
chmod -R u+w "$build_dir"
cd "$build_dir"
patch --batch --forward --fuzz=0 -p1 -i "$script_dir/../patches/gog-single-attempt-send.patch"
cp "$script_dir/../patches/gog-single-attempt-test.go.txt" internal/cmd/mailgate_single_attempt_test.go
go mod edit -go=1.27.2
go get golang.org/x/net@v0.61.0 golang.org/x/crypto@v0.58.0 golang.org/x/text@v0.43.0
go list -deps ./cmd/gog | python3 -c 'import sys; packages=sys.stdin.read().splitlines(); assert not any(p == "golang.org/x/crypto/openpgp" or p.startswith("golang.org/x/crypto/openpgp/") for p in packages), "Unmaintained OpenPGP dependency is not allowed"'
go test ./internal/cmd -run '^TestMailgateSendSingleAttempt$' -count=1
GOOS=linux GOARCH="$architecture" go build -trimpath \
  -ldflags '-s -w -X github.com/openclaw/gogcli/internal/cmd.version=v0.38.2 -X github.com/openclaw/gogcli/internal/cmd.commit=03d192ff-mailgate.1' \
  -o "$output" ./cmd/gog
printf '%s\n' "Built GOG v0.38.2 mailgate.1 with patched dependencies and single-attempt sends for linux/$architecture."
