GO ?= go
VERSION ?= 0.1.0
BUILD_FLAGS = -trimpath -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build test race vet check release browser-test vuln
build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o bin/mailgate ./cmd/mailgate
test:
	$(GO) test ./...
race:
	$(GO) test -race ./...
vet:
	$(GO) vet ./...
check: test race vet
release:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(BUILD_FLAGS) -o dist/mailgate-linux-arm64 ./cmd/mailgate
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(BUILD_FLAGS) -o dist/mailgate-linux-amd64 ./cmd/mailgate
	cd dist && sha256sum mailgate-linux-* > SHA256SUMS
browser-test:
	npm test
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
