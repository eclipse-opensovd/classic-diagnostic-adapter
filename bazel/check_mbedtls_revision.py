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

"""Verify Bazel uses the mbedtls-rs revision declared by Cargo."""

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FULL_GIT_REVISION = re.compile(r"[0-9a-f]{40}")


def cargo_revision() -> str:
    """Read the authoritative mbedtls-rs revision from Cargo.toml."""
    with (ROOT / "Cargo.toml").open("rb") as cargo_toml:
        manifest = tomllib.load(cargo_toml)

    dependency = manifest["workspace"]["dependencies"]["mbedtls-rs"]
    return dependency["rev"]


def bazel_revision() -> str:
    """Read the mbedtls-rs git override revision from MODULE.bazel."""
    module = (ROOT / "MODULE.bazel").read_text(encoding="utf-8")
    for override in re.findall(r"git_override\((.*?)\n\)", module, re.DOTALL):
        if re.search(r'module_name\s*=\s*"mbedtls-rs"', override):
            commit = re.search(r'commit\s*=\s*"([^"]+)"', override)
            if commit:
                return commit.group(1)
            break

    raise ValueError("MODULE.bazel has no commit for the mbedtls-rs git_override")


def main() -> None:
    """Fail when Bazel does not use Cargo's mbedtls-rs revision."""
    cargo_rev = cargo_revision()
    bazel_rev = bazel_revision()

    if not FULL_GIT_REVISION.fullmatch(cargo_rev):
        raise ValueError(f"Cargo.toml mbedtls-rs rev is not a full Git revision: {cargo_rev}")
    if not FULL_GIT_REVISION.fullmatch(bazel_rev):
        raise ValueError(f"MODULE.bazel mbedtls-rs commit is not a full Git revision: {bazel_rev}")
    if bazel_rev != cargo_rev:
        raise ValueError(
            "MODULE.bazel mbedtls-rs commit does not match Cargo.toml rev: "
            f"{bazel_rev} != {cargo_rev}"
        )


if __name__ == "__main__":
    try:
        main()
    except (KeyError, TypeError, ValueError) as error:
        print(f"::error::{error}", file=sys.stderr)
        raise SystemExit(1) from error
