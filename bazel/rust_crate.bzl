# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0

"""Workspace-local wrappers for common rules_rust target patterns."""

load("@crate_index//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//cargo:defs.bzl", "cargo_build_script")
load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library")

def workspace_rust_library(
        name,
        srcs,
        crate_name,
        local_deps = None,
        local_proc_macro_deps = None,
        crate_features = None,
        **kwargs):
    """Define a first-party rust_library using crate_universe-generated deps."""
    rust_library(
        name = name,
        srcs = srcs,
        crate_name = crate_name,
        edition = "2024",
        aliases = aliases(normal = True, proc_macro = True),
        crate_features = crate_features or [],
        deps = (local_deps or []) + all_crate_deps(normal = True),
        proc_macro_deps = (local_proc_macro_deps or []) + all_crate_deps(proc_macro = True),
        **kwargs
    )

def workspace_rust_binary(
        name,
        srcs,
        local_deps = None,
        crate_features = None,
        **kwargs):
    """Define a first-party rust_binary using crate_universe-generated deps."""
    rust_binary(
        name = name,
        srcs = srcs,
        edition = "2024",
        aliases = aliases(normal = True, proc_macro = True),
        crate_features = crate_features or [],
        deps = (local_deps or []) + all_crate_deps(normal = True),
        **kwargs
    )

def workspace_cargo_build_script(
        name,
        srcs,
        local_deps = None,
        local_proc_macro_deps = None,
        **kwargs):
    """Define a cargo_build_script using crate_universe-generated build deps."""
    cargo_build_script(
        name = name,
        srcs = srcs,
        edition = "2024",
        aliases = aliases(build = True, build_proc_macro = True),
        deps = (local_deps or []) + all_crate_deps(build = True),
        proc_macro_deps = (local_proc_macro_deps or []) + all_crate_deps(build_proc_macro = True),
        **kwargs
    )