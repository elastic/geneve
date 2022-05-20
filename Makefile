ifeq ($(VENV),)
	PYTHON:=python3
else
	PYTHON:=source $(VENV)/bin/activate; python3
endif

all: lint tests

prereq:
	$(PYTHON) -m pip install --user --upgrade pip
	$(PYTHON) -m pip install --user -r requirements.txt

lint:
	$(PYTHON) -m flake8 geneve tests --ignore D203 --max-line-length 120 --exclude geneve/kql

tests: tests/*.py
	$(PYTHON) -m pytest -raP tests/test_*.py

online-tests: tests/*.py
	$(PYTHON) -m pytest -raP tests/test_emitter_*.py

up:
	docker compose up --wait --quiet-pull

down:
	docker compose down

license-checks:
	bash scripts/license_check.sh

run:
	$(PYTHON) -m geneve --version
	$(PYTHON) -m geneve --help
	$(PYTHON) -m geneve

pkg-build:
	$(PYTHON) -m build

pkg-install:
	$(PYTHON) -m pip install --force-reinstall dist/geneve-*.whl

pkg-try:
	geneve --version
	geneve --help
	geneve

package: pkg-build pkg-install pkg-try

.PHONY: lint tests online-tests run up down license-checks package
