all: lint tests

prereq:
	python3 -m pip install --upgrade pip
	python3 -m pip install -r requirements.txt

lint:
	python3 -m flake8 geneve tests --ignore D203 --max-line-length 120

tests: tests/*.py
	python3 -m pytest

run:
	python3 -m geneve --version
	python3 -m geneve --help
	python3 -m geneve

pkg_build:
	python3 -m build

pkg_install:
	python3 -m pip install --force-reinstall dist/geneve-*.whl

pkg_try:
	geneve --version
	geneve --help
	geneve

package: pkg_build pkg_install pkg_try

.PHONY: lint tests run
