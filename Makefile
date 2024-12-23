# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: lint-fix lint-deps lint shisui shisui-image test fmt clean devtools help

GOBIN = ./build/bin
GO ?= latest
GORUN = go run

GIT_COMMIT := $(shell git rev-parse --short=8 HEAD)
GIT_DATE := $(shell git log -1 --format=%ci | cut -d ' ' -f 1)

#? shisui: Build shisui
shisui:
	go build -ldflags "-X github.com/zen-eth/shisui/internal/version.gitCommit=$(GIT_COMMIT) -X github.com/zen-eth/shisui/internal/version.gitDate=$(GIT_DATE)" ./cmd/shisui/main.go
	mkdir -p $(GOBIN)
	mv main $(GOBIN)/shisui
	@echo "Done building."
	@echo "Run \"$(GOBIN)/shisui\" to launch shisui."

#? shisui-image: Build shisui image
shisui-image:
	docker build -t ghcr.io/zen-eth/shisui:latest -f Dockerfile .

#? fmt: Ensure consistent code formatting.
fmt:
	gofmt -s -w $(shell find . -name "*.go")

#? test: Run the tests.
test:
	go test -v ./...

#? clean: Clean go cache, built executables, and the auto generated folder.
clean:
	go clean -cache
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

#? devtools: Install recommended developer tools.
devtools:
	env GOBIN= go install golang.org/x/tools/cmd/stringer@latest
	env GOBIN= go install github.com/fjl/gencodec@latest
	env GOBIN= go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	env GOBIN= go install ./cmd/abigen
	@type "solc" 2> /dev/null || echo 'Please install solc'
	@type "protoc" 2> /dev/null || echo 'Please install protoc'

#? help: Get more info on make commands.
help: Makefile
	@echo ''
	@echo 'Usage:'
	@echo '  make [target]'
	@echo ''
	@echo 'Targets:'
	@sed -n 's/^#?//p' $< | column -t -s ':' |  sort | sed -e 's/^/ /'

#? lint-deps: Install lint dependencies.
lint-deps:
	@which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

#? lint: Run linters.
lint: lint-deps
	golangci-lint run

#? lint-fix: Run linters and fix issues.
lint-fix: lint-deps
	golangci-lint run --fix

