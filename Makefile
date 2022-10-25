ifeq ($(VENV),)
	ACTIVATE :=
else
	ACTIVATE := source $(VENV)/bin/activate; 
endif

PYTHON := $(ACTIVATE)python3

all: lint tests

prereq-py:
	$(PYTHON) -m pip install --user --upgrade pip
	$(PYTHON) -m pip install --user -r requirements.txt

prereq-go: prereq-py
	go install golang.org/x/lint/golint@latest

lint:
	$(PYTHON) -m black -q --check geneve tests || ($(PYTHON) -m black geneve tests; false)
	$(PYTHON) -m isort -q --check geneve tests || ($(PYTHON) -m isort geneve tests; false)

license-check:
	bash scripts/license_check.sh

tests: tests/*.py
	$(PYTHON) -m pytest -raP tests/test_*.py

online-tests: tests/*.py
	$(PYTHON) -m pytest -raP tests/test_emitter_*.py

up:
	@$(call print_server_version,ES,ELASTICSEARCH)
	@$(call print_server_version,KB,KIBANA)
	docker compose up --wait --quiet-pull

down:
	docker compose down

gnv: main.go $(shell find cmd -name \*.go)
	go build -race -o $@ .

cli-build: gnv

cli-lint:
	go vet .
	golint .

cli-test:
	go test -race ./...

cli-bench:
	go test -bench=. ./cmd/geneve

pkg-build:
	$(PYTHON) -m build

pkg-install:
	$(PYTHON) -m pip install --force-reinstall dist/geneve-*.whl

pkg-tests: GENEVE := $(ACTIVATE)geneve
pkg-tests:
	$(GENEVE) --version
	$(GENEVE) --help
	$(GENEVE)
	$(GENEVE) stack --help
	$(GENEVE) stack
	$(GENEVE) stack -d -v

package: VENV := .venv-test
package: pkg-build
	rm -rf $(VENV)
	$(PYTHON) -mvenv $(VENV)
	$(MAKE) pkg-install VENV=$(VENV)
	$(MAKE) pkg-tests VENV=$(VENV)
	rm -rf $(VENV)

CREDS_FILE=credentials-cloud-stack.json

cloud-stack-up:
	touch $(CREDS_FILE)
	chmod 600 $(CREDS_FILE)
	ecctl deployment create --file tests/deployment.json --track | tee /dev/stderr | (jq >$(CREDS_FILE) 2>/dev/null; cat >/dev/null)

cloud-stack-down: $(CREDS_FILE)
	ecctl deployment shutdown --force $(shell jq -r .id $(CREDS_FILE))
	rm $(CREDS_FILE)

define print_server_version
	if [ -n "$$TEST_$(2)_IMAGE" ]; then \
		echo "$(1): $$TEST_$(2)_IMAGE"; \
	else \
		echo "$(1): $$TEST_STACK_VERSION"; \
	fi
endef

export TEST_STACK_VERSION

ifeq ($(TEST_STACK_VERSION)$(TEST_ELASTICSEARCH_IMAGE),)
override TEST_STACK_VERSION = latest
endif

ifeq ($(TEST_STACK_VERSION)$(TEST_KIBANA_IMAGE),)
override TEST_STACK_VERSION = latest
endif

ifeq ($(TEST_STACK_VERSION),latest)
override TEST_STACK_VERSION := $(shell \
	curl -s -L https://artifacts-api.elastic.co/v1/versions | \
	jq -r 'last(.versions[] | select(contains("SNAPSHOT") | not))' \
)
endif

ifeq ($(TEST_STACK_VERSION),latest-snapshot)
override TEST_STACK_VERSION := $(shell \
	curl -s -L https://artifacts-api.elastic.co/v1/versions | \
	jq -r 'last(.versions[] | select(contains("SNAPSHOT")))' \
)
endif

.PHONY: lint tests online_tests run up down
