GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/vault-plugin-secrets-volcengine cmd/vault-plugin-secrets-volcengine/main.go

fmt:
	go fmt $$(go list ./...)

test:
	go test -v ./... -count=1

.PHONY: build fmt test
