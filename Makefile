ifeq ($(VENV),)
	ACTIVATE :=
else
	ACTIVATE := source $(VENV)/bin/activate;
endif

PYTHON := $(ACTIVATE)python3

all: lint tests

prereq:
	$(PYTHON) -m pip install --user --upgrade pip
	$(PYTHON) -m pip install --user -r requirements.txt

lint:
	$(PYTHON) -m black -q --check geneve tests || ($(PYTHON) -m black geneve tests; false)
	$(PYTHON) -m isort -q --check geneve tests || ($(PYTHON) -m isort geneve tests; false)

tests: tests/*.py
	$(PYTHON) -m pytest -raP tests/test_*.py

online_tests: tests/*.py
	$(PYTHON) -m pytest -raP tests/test_emitter_*.py

up:
	@$(call print_server_version,ES,ELASTICSEARCH)
	@$(call print_server_version,KB,KIBANA)
	docker compose up --wait --quiet-pull

down:
	docker compose down

license_check:
	bash scripts/license_check.sh

run:
	$(PYTHON) -m geneve --version
	$(PYTHON) -m geneve --help
	$(PYTHON) -m geneve

pkg_build:
	$(PYTHON) -m build

pkg_install:
	$(PYTHON) -m pip install --force-reinstall dist/geneve-*.whl

pkg_try:
	geneve --version
	geneve --help
	geneve

package: pkg_build pkg_install pkg_try

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
