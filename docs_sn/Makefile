MAKEFILE_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
SCRIPTS_DIR := $(abspath $(MAKEFILE_DIR))

.PHONY: default

UID := $(shell id -u)
GID := $(shell id -g)

build:
	@docker build -f Dockerfile . -t sovdsphinx:latest
	@docker run --rm --user "$(UID):$(GID)" \
		-v "${SCRIPTS_DIR}:/docs" \
		-v "${SCRIPTS_DIR}/..:/project" \
		-it sovdsphinx:latest sphinx-build -W -b html /docs /docs/_build

clean:
	@rm -rf "${SCRIPTS_DIR}/_build"

default: build
