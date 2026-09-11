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

STABLE  := 1.88
NIGHTLY := nightly-2026-07-21

.PHONY: build lint lint-all-features fmt precommit precommit-all-features

lint:
	cargo +$(STABLE) clippy --all-targets -- --deny=warnings
	cargo +$(NIGHTLY) clippy --all-targets -- --deny=warnings

lint-all-features:
	cargo +$(STABLE) clippy --all-targets --all-features -- --deny=warnings
	cargo +$(NIGHTLY) clippy --all-targets --all-features -- --deny=warnings

fmt:
	cargo +$(NIGHTLY) fmt

precommit:
	uv run --locked --group tools prek run --all-files --show-diff-on-failure

precommit-all-features:
	uv run --locked --group tools prek run --all-files --group CI --group @ungrouped --show-diff-on-failure
