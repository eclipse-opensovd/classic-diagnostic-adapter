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

"""Verify that every pinned Rust version matches the MSRV declared in Cargo.toml.

`rust-version` in the root Cargo.toml is the single source of the Rust version: the
Makefile, cargo's resolver, Dependabot and the integration tests read it directly.
The files checked here cannot read it and carry a copy instead.
"""

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FULL_VERSION = re.compile(r"\d+\.\d+\.\d+")
BAZEL_MODULES = ("MODULE.bazel", "bazel/vendor-consumer-test/MODULE.bazel")
DOCKERFILE = "testcontainer/cda/Dockerfile"


def cargo_rust_version() -> str:
    """Read the authoritative rust-version from Cargo.toml."""
    with (ROOT / "Cargo.toml").open("rb") as cargo_toml:
        manifest = tomllib.load(cargo_toml)

    return manifest["workspace"]["package"]["rust-version"]


def bazel_rust_versions(module_path: Path) -> list[str]:
    """Read the Rust toolchain versions from a Bazel module."""
    module = module_path.read_text(encoding="utf-8")
    toolchain = re.search(r"rust\.toolchain\((.*?)\n\)", module, re.DOTALL)
    if toolchain:
        versions = re.search(r"versions\s*=\s*\[([^\]]*)\]", toolchain.group(1))
        if versions:
            return re.findall(r'"([^"]+)"', versions.group(1))

    raise ValueError(f"{module_path.relative_to(ROOT)} has no versions for rust.toolchain")


def dockerfile_rust_version(dockerfile_path: Path) -> str:
    """Read the default of the RUST_VERSION build argument from a Dockerfile."""
    dockerfile = dockerfile_path.read_text(encoding="utf-8")
    default = re.search(r"^ARG RUST_VERSION=(\S+)$", dockerfile, re.MULTILINE)
    if default:
        return default.group(1)

    raise ValueError(f"{dockerfile_path.relative_to(ROOT)} has no default for ARG RUST_VERSION")


def main() -> None:
    """Fail when a pinned Rust version differs from Cargo's rust-version."""
    cargo_version = cargo_rust_version()
    if not FULL_VERSION.fullmatch(cargo_version):
        raise ValueError(
            f"Cargo.toml rust-version must be a full version like 1.88.0: {cargo_version}"
        )

    for module in BAZEL_MODULES:
        bazel_versions = bazel_rust_versions(ROOT / module)
        if bazel_versions != [cargo_version]:
            raise ValueError(
                f"{module} rust.toolchain versions do not match Cargo.toml rust-version: "
                f"{bazel_versions} != ['{cargo_version}']"
            )

    docker_version = dockerfile_rust_version(ROOT / DOCKERFILE)
    if docker_version != cargo_version:
        raise ValueError(
            f"{DOCKERFILE} RUST_VERSION does not match Cargo.toml rust-version: "
            f"{docker_version} != {cargo_version}"
        )


if __name__ == "__main__":
    try:
        main()
    except (KeyError, TypeError, ValueError) as error:
        print(f"::error::{error}", file=sys.stderr)
        raise SystemExit(1) from error
