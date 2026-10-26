PHP ?= php
APP ?= .
MATRIX ?= 7.0 7.4 8.1 8.3 8.5

.PHONY: help test lint audit-local audit-json test-matrix

help:
	@echo "make test         Lint and run the zero-dependency test suite"
	@echo "make lint         php -l on the CLI and test runner"
	@echo "make audit-local  Audit APP (default: .) and print the terminal report"
	@echo "make audit-json   Audit APP and write anonymized audit-summary.json"
	@echo "make test-matrix  Run the suite on PHP $(MATRIX) via OrbStack containers"

test: lint
	$(PHP) tests/run-tests.php

lint:
	$(PHP) -l bin/php2shell-audit
	$(PHP) -l tests/run-tests.php

audit-local:
	$(PHP) bin/php2shell-audit --path=$(APP)

audit-json:
	$(PHP) bin/php2shell-audit --path=$(APP) --json > audit-summary.json
	@echo "Wrote audit-summary.json (anonymized; review before sharing)."

# Uses the docker CLI provided by OrbStack.
test-matrix:
	@for v in $(MATRIX); do \
		echo "== PHP $$v"; \
		docker run --rm -v "$(CURDIR)":/app -w /app php:$$v-cli php tests/run-tests.php | tail -1 || exit 1; \
	done
