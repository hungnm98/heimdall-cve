BIN      := bin/heimdall
PKG      := github.com/hungnm98/heimdall-cve
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS  := -s -w -X $(PKG)/internal/cli.Version=$(VERSION) -X $(PKG)/internal/cli.Commit=$(COMMIT)

.PHONY: build test race vet lint fmt golden check test-pg

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/heimdall

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

fmt:
	gofmt -w cmd internal

golden:
	go test ./internal/report/... ./internal/notify/... -update

check: vet race

# Needs HEIMDALL_TEST_PG_DSN pointing at a disposable database.
test-pg:
	@test -n "$$HEIMDALL_TEST_PG_DSN" || (echo "set HEIMDALL_TEST_PG_DSN" && exit 1)
	go test -race -count=1 ./internal/store/postgres/
