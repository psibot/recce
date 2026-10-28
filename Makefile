SHELL := /bin/bash
BIN   := bin
GO    ?= go

.PHONY: build clean schema fmt smoke up down

build: $(BIN)/recce-normalize $(BIN)/recce-scope ## build the Go helpers

$(BIN)/recce-normalize: helpers/go/normalize/main.go helpers/go/go.mod
	@mkdir -p $(BIN)
	cd helpers/go && $(GO) build -o ../../$(BIN)/recce-normalize ./normalize

$(BIN)/recce-scope: helpers/go/scope/main.go helpers/go/go.mod
	@mkdir -p $(BIN)
	cd helpers/go && $(GO) build -o ../../$(BIN)/recce-scope ./scope

fmt:
	cd helpers/go && $(GO) fmt ./...

schema: ## apply db schema (needs DATABASE_URL)
	psql "$$DATABASE_URL" -f db/schema.sql

clean:
	rm -rf $(BIN)

up:   ## bring up the full stack
	docker compose up -d --build

down:
	docker compose down

# Offline smoke test of the pipeline with no external tools installed:
# feeds a seed domain through normalize|scope (ingest is skipped here).
smoke: build
	@mkdir -p /tmp/recce-smoke
	@printf '{"include":[{"type":"domain","value":"example.com"}],"exclude":[]}' > /tmp/recce-smoke/scope.json
	@printf '%s\n' \
	  '{"kind":"asset","type":"subdomain","value":"WWW.Example.com."}' \
	  '{"kind":"asset","type":"subdomain","value":"www.example.com"}' \
	  '{"kind":"asset","type":"subdomain","value":"evil.attacker.com"}' \
	  | $(BIN)/recce-normalize \
	  | $(BIN)/recce-scope -rules /tmp/recce-smoke/scope.json
	@echo "(expect: one www.example.com line; dupe collapsed; attacker.com blocked)"
