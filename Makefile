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

sanity-checks:
	for n in `seq 30`; do \
	curl -s --fail http://localhost:30000/api/v1/version && exit 0 || sleep 1; \
done; exit 1

stack-pull:
	cd tests && docker compose pull -q

stack-up:
	cd tests && docker compose up --wait --quiet-pull

stack-down:
	cd tests && docker compose down

docker-build:
	-docker image rm geneve
	docker build -q -t geneve .

docker-run:
	docker run -p 127.0.0.1:30000:5000 --rm --name geneve geneve

docker-sanity: GENEVE_VERSION=$(shell $(PYTHON) -c "import geneve; print(geneve.version)")
docker-sanity:
	docker run -p 127.0.0.1:30000:5000 --rm --name geneve-test -d geneve
	[ "`$(MAKE) -s sanity-checks`" = '{"version":"$(GENEVE_VERSION)"}' ] || \
		(docker container stop geneve-test; exit 1)
	docker container stop geneve-test

docker-push: GENEVE_VERSION=$(shell $(PYTHON) -c "import geneve; print(geneve.version)")
docker-push:
	docker tag geneve:latest $(DOCKER_REGISTRY)/geneve:latest
	docker tag geneve:latest $(DOCKER_REGISTRY)/geneve:$(GENEVE_VERSION)
	docker push -q $(DOCKER_REGISTRY)/geneve:latest
	docker push -q $(DOCKER_REGISTRY)/geneve:$(GENEVE_VERSION)
	docker image rm $(DOCKER_REGISTRY)/geneve:latest $(DOCKER_REGISTRY)/geneve:$(GENEVE_VERSION)

kind-up:
	kind create cluster --config=etc/kind-config.yml
	kind load docker-image geneve
	kubectl apply -f etc/pods/geneve.yml
	kubectl apply -f etc/services/geneve.yml

kind-down:
	kind delete cluster

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
