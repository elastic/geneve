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

stack-up:
	cd tests && docker compose up --wait --quiet-pull

stack-down:
	cd tests && docker compose down

docker: GENEVE_VERSION=$(shell $(PYTHON) -c "import geneve; print(geneve.version)")
docker:
	docker build -q -t geneve:$(GENEVE_VERSION) .

docker-sanity: GENEVE_VERSION=$(shell $(PYTHON) -c "import geneve; print(geneve.version)")
docker-sanity:
	docker run -p 127.0.0.1:5000:80 --name geneve-test --rm -d geneve:$(GENEVE_VERSION)
	for n in `seq 5`; do \
	[ "`curl -s --fail http://localhost:5000/api/v1/version`" = '{"version":"$(GENEVE_VERSION)"}' ] && exit 0 || sleep 1; \
done; docker container stop geneve-test; exit 1
	docker container stop geneve-test

license-checks:
	bash scripts/license_check.sh

run:
	$(PYTHON) -m geneve --version
	$(PYTHON) -m geneve --help
	$(PYTHON) -m geneve

flask:
	FLASK_APP=geneve/webapi.py $(PYTHON) -m flask run

pkg-build:
	$(PYTHON) -m build

pkg-install:
	$(PYTHON) -m pip install --force-reinstall dist/geneve-*.whl

pkg-try:
	geneve --version
	geneve --help
	geneve

package: pkg-build pkg-install pkg-try

.PHONY: lint tests online-tests run flask stack-up stack-down license-checks package docker docker-sanity
