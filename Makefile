# SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

STABLE := 1.88.0
NIGHTLY := nightly-2026-07-21
CARGO_DENY_VERSION := 0.20.2
CARGO_LLVM_COV_VERSION := 0.9.1
PROTOC_VERSION := 34.1

.DEFAULT_GOAL := build

.PHONY: build release check test integration-test integration-test-can integration-test-mixed \
	build-all-features build-mbedtls build-minimal build-minimal-cda \
	lint lint-all-features lint-nightly lint-nightly-all-features fmt fmt-check \
	precommit precommit-all-features \
	coverage coverage-can integration-coverage deny \
	generate-config generate-test-config generate-flatbuffers generate-protos docs rustdoc \
	tool-versions setup-devenv doctor run profile depgraph clean clean-doc help

build:
	cargo +$(STABLE) build --locked $(ARGS)

release:
	$(MAKE) build ARGS="--release $(ARGS)"

check:
	cargo +$(STABLE) check --workspace

test:
	cargo +$(STABLE) test --locked --workspace $(ARGS)

integration-test:
	cargo +$(STABLE) test --locked -p integration-tests --features integration-tests

integration-test-can:
	CDA_INTEGRATION_TEST_USE_CAN=true cargo +$(STABLE) test --locked -p integration-tests --features can-integration-tests --test integration_tests

integration-test-mixed:
	CDA_INTEGRATION_TEST_USE_MIXED=true cargo +$(STABLE) test --locked -p integration-tests --features can-integration-tests --test integration_tests

build-all-features:
	$(MAKE) build ARGS="--all-features $(ARGS)"

build-mbedtls:
	$(MAKE) build ARGS="-p opensovd-cda --no-default-features --features mbedtls $(ARGS)"

build-minimal:
	$(MAKE) build ARGS="--no-default-features $(ARGS)"

build-minimal-cda:
	$(MAKE) build ARGS="--no-default-features --package opensovd-cda $(ARGS)"

lint:
	cargo +$(STABLE) clippy --all-targets $(ARGS) -- --deny=warnings

lint-all-features:
	$(MAKE) lint ARGS="--all-features $(ARGS)"

lint-nightly:
	cargo +$(NIGHTLY) clippy --all-targets $(ARGS) -- --deny=warnings

lint-nightly-all-features:
	$(MAKE) lint-nightly ARGS="--all-features $(ARGS)"

fmt:
	cargo +$(NIGHTLY) fmt $(ARGS)

fmt-check:
	$(MAKE) fmt ARGS="--check $(ARGS)"

precommit:
	uv run --locked --group tools prek run --all-files --show-diff-on-failure

precommit-all-features:
	uv run --locked --group tools prek run --all-files --group CI --group @ungrouped --show-diff-on-failure

coverage:
	cargo +$(STABLE) llvm-cov --workspace --lcov --output-path lcov.info -- --show-output

coverage-can:
	cargo +$(STABLE) llvm-cov -p opensovd-cda -p cda-comm-can --features opensovd-cda/can-socketcand,cda-comm-can/can-socketcand --lcov --output-path lcov-can-unit.info -- --show-output

integration-coverage:
	CDA_INTEGRATION_TEST_COVERAGE=true cargo +$(STABLE) llvm-cov --features integration-tests --lcov --output-path lcov.info

deny:
	cargo +$(STABLE) deny check $(ARGS)

generate-config:
	cargo +$(STABLE) run --locked --all-features -- generate-config --output $(or $(OUTPUT),opensovd-cda.toml)

generate-test-config:
	cargo +$(STABLE) test --locked --workspace --all-features --test integration_tests -- --exact --ignored util::config::tests::generate_compose_configs

generate-flatbuffers:
	$(MAKE) build ARGS="-p cda-database --features gen-flatbuffers $(ARGS)"

generate-protos:
	$(MAKE) build ARGS="-p cda-database --features gen-protos $(ARGS)"

docs:
	cd docs && ./rebuild_docs.sh

rustdoc:
	cargo +$(STABLE) doc $(ARGS)

tool-versions:
	@printf '%s\n' \
		'stable=$(STABLE)' \
		'nightly=$(NIGHTLY)' \
		'cargo_deny=$(CARGO_DENY_VERSION)' \
		'cargo_llvm_cov=$(CARGO_LLVM_COV_VERSION)' \
		'protoc=$(PROTOC_VERSION)'

setup-devenv:
	@command -v rustup >/dev/null 2>&1 || { printf '%s\n' 'rustup is required: https://rustup.rs'; exit 1; }
	@command -v uv >/dev/null 2>&1 || { printf '%s\n' 'uv is required: https://docs.astral.sh/uv/'; exit 1; }
	rustup toolchain install $(STABLE) --profile minimal --component clippy --component rustfmt --component llvm-tools
	rustup toolchain install $(NIGHTLY) --profile minimal --component clippy --component rustfmt
	cargo +$(STABLE) install --locked --version $(CARGO_DENY_VERSION) cargo-deny
	cargo +$(STABLE) install --locked --version $(CARGO_LLVM_COV_VERSION) cargo-llvm-cov
	uv sync --locked --group tools
	$(MAKE) doctor

doctor:
	@missing=0; \
	for tool in rustup cargo uv git cmake protoc docker cargo-deny cargo-llvm-cov; do \
		if command -v "$$tool" >/dev/null 2>&1; then \
			printf 'Found required tool: %s\n' "$$tool"; \
		else \
			printf 'Missing required tool: %s\n' "$$tool"; \
			missing=1; \
		fi; \
	done; \
	for tool in jq dot lcov ninja pkg-config; do \
		if command -v "$$tool" >/dev/null 2>&1; then \
			printf 'Found optional tool: %s\n' "$$tool"; \
		else \
			printf 'Missing optional tool: %s\n' "$$tool"; \
		fi; \
	done; \
	if command -v rustup >/dev/null 2>&1; then \
		rustup run $(STABLE) rustc --version >/dev/null 2>&1 || { printf 'Missing Rust toolchain: %s\n' '$(STABLE)'; missing=1; }; \
		rustup run $(NIGHTLY) rustc --version >/dev/null 2>&1 || { printf 'Missing Rust toolchain: %s\n' '$(NIGHTLY)'; missing=1; }; \
	fi; \
	if command -v cargo-deny >/dev/null 2>&1; then \
		version=$$(cargo-deny --version 2>/dev/null); \
		if [ "$$version" != 'cargo-deny $(CARGO_DENY_VERSION)' ]; then \
			printf 'Expected cargo-deny %s, found %s\n' '$(CARGO_DENY_VERSION)' "$$version"; \
			missing=1; \
		fi; \
	fi; \
	if command -v cargo-llvm-cov >/dev/null 2>&1; then \
		version=$$(cargo +$(STABLE) llvm-cov --version 2>/dev/null); \
		if [ "$$version" != 'cargo-llvm-cov $(CARGO_LLVM_COV_VERSION)' ]; then \
			printf 'Expected cargo-llvm-cov %s, found %s\n' '$(CARGO_LLVM_COV_VERSION)' "$$version"; \
			missing=1; \
		fi; \
	fi; \
	if command -v protoc >/dev/null 2>&1; then \
		protoc_version=$$(protoc --version 2>/dev/null); \
		protoc_version=$${protoc_version#libprotoc }; \
		if [ "$$protoc_version" != '$(PROTOC_VERSION)' ]; then \
			printf 'Recommended protoc %s, found %s\n' '$(PROTOC_VERSION)' "$$protoc_version"; \
		fi; \
	fi; \
	printf '%s\n' 'System libraries are platform-specific; verify OpenSSL and DLT development libraries separately.'; \
	if [ "$$missing" -ne 0 ]; then exit 1; fi
	@uv run --locked --group tools prek --version
	@uv run --locked --group tools ruff --version

run:
	cargo +$(STABLE) run --locked --release -- $(ARGS)

profile:
	RUSTFLAGS="-C force-frame-pointers=yes" cargo +$(STABLE) build --profile release-with-debug --bin opensovd-cda --features heap-profiling

depgraph:
	cargo +$(STABLE) depgraph --target-deps --dedup-transitive-deps --workspace-only | dot -Tpng > depgraph.png

clean:
	cargo +$(STABLE) clean

clean-doc:
	cargo +$(STABLE) clean --doc

help:
	@printf '%s\n' \
		'build ARGS="..."             Build the workspace with optional cargo arguments' \
		'release ARGS="..."           Build the release profile' \
		'check                        Check the workspace' \
		'test ARGS="..."              Run workspace unit tests' \
		'integration-test             Run DoIP integration tests' \
		'integration-test-can         Run CAN integration tests' \
		'integration-test-mixed       Run mixed DoIP/CAN integration tests' \
		'build-all-features           Build with all features' \
		'build-mbedtls                Build CDA with only mbedTLS' \
		'build-minimal                Build the workspace without default features' \
		'build-minimal-cda            Build CDA without default features' \
		'lint ARGS="..."              Run stable Clippy' \
		'lint-all-features            Run stable Clippy with all features' \
		'lint-nightly ARGS="..."      Run pinned-nightly Clippy' \
		'lint-nightly-all-features    Run pinned-nightly Clippy with all features' \
		'fmt ARGS="..."               Format code' \
		'fmt-check                    Check code formatting' \
		'precommit                    Run standard pre-commit checks' \
		'precommit-all-features       Run all pre-commit checks' \
		'coverage                     Generate unit-test LCOV coverage' \
		'coverage-can                 Generate CAN unit-test LCOV coverage' \
		'integration-coverage         Generate integration-test LCOV coverage' \
		'deny ARGS="..."              Run all or selected cargo-deny checks' \
		'generate-config              Regenerate opensovd-cda.toml' \
		'generate-test-config         Generate testcontainer/cda-test-config*.toml for docker compose' \
		'generate-flatbuffers         Regenerate FlatBuffers sources' \
		'generate-protos              Regenerate protobuf sources' \
		'docs                         Rebuild Sphinx documentation' \
		'rustdoc ARGS="..."           Build Rust API documentation' \
		'tool-versions                Print machine-readable tool versions' \
		'setup-devenv                 Install pinned development tools' \
		'doctor                       Check development prerequisites' \
		'run ARGS="..."               Run the release binary' \
		'profile                      Build the heap-profiling binary' \
		'depgraph                     Generate depgraph.png' \
		'clean / clean-doc            Clean all artifacts or Rustdoc artifacts'
