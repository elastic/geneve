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

unit_tests_matrix:
	echo '{ "python-version": ["3.8", "3.9", "3.10"], "os": ["ubuntu-latest", "macos-latest"] }'

up:
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

.PHONY: lint tests online_tests run up down
