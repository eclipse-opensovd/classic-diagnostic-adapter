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

"""Rust target wrappers for CDA workspace crates."""

load("@cda_crates//:defs.bzl", "aliases", _crate_deps = "crate_deps")
load("@mbedtls-rs//:defs.bzl", _mbedtls_rs_library = "mbedtls_rs_library")
load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library")

def workspace_mbedtls_rs_library(name, visibility = None):
    """Instantiates mbedtls-rs against CDA's Cargo dependency universe."""
    _mbedtls_rs_library(
        name = name,
        aliases = aliases(),
        tokio = "@cda_crates//:tokio",
        tracing = "@cda_crates//:tracing",
        visibility = visibility,
    )

def workspace_rust_library(
        crate_deps = [],
        proc_macro_crate_deps = [],
        deps = [],
        **kwargs):
    """Defines a Rust 2024 library with explicitly selected Cargo dependencies."""
    rust_library(
        aliases = aliases(),
        edition = "2024",
        deps = deps + _crate_deps(crate_deps),
        proc_macro_deps = _crate_deps(proc_macro_crate_deps),
        **kwargs
    )

def workspace_rust_binary(
        crate_deps = [],
        proc_macro_crate_deps = [],
        deps = [],
        **kwargs):
    """Defines a Rust 2024 binary with explicitly selected Cargo dependencies."""
    rust_binary(
        aliases = aliases(),
        edition = "2024",
        deps = deps + _crate_deps(crate_deps),
        proc_macro_deps = _crate_deps(proc_macro_crate_deps),
        **kwargs
    )
