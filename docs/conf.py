# Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

extensions = [
    "sphinx_needs",
    "sphinx_codelinks",
    "sphinxcontrib.plantuml",
    "sphinx.ext.todo",
]

src_trace_config_from_toml = "cda_trace.toml"

# Exclude build artifacts and editor/project files so Sphinx doesn't treat generated
# files under `_build` as additional source documents (this caused duplicate needs).
# Also exclude individual RST files that are intended to be included into
# `02_requirements/index.rst` using `.. include::` so they are not treated as
# standalone documents by Sphinx (which would register needs twice).
exclude_patterns = [
    "_build",
    "**/_build/**",
    "Thumbs.db",
    ".DS_Store",
    "**/0**.rst",
]

project = "CDA"
copyright = "%Y, Eclipse OpenSOVD authors"
# todo, automatically retrieve from project version
version = "1.0"
html_theme = "bizstyle"

plantuml = "java -jar /usr/local/bin/plantuml.jar"

# dots are not allowed, because they cause linking issues with sphinx-needs due to normalization,
# underscores require the use of backticks when used in rust comments, and are therefore also not allowed
needs_id_regex = r"^(req|arch|dsgn|impl|dimpl|test|itest)~[a-zA-Z0-9\-]+$"
needs_id_required = True

needs_types = [
    {
        "directive": "req",
        "title": "Software Requirement",
        "prefix": "req~",
        "color": "#BFD8D2",
        "style": "node",
    },
    {
        "directive": "arch",
        "title": "Software Architecture",
        "prefix": "arch~",
        "color": "#D3B6C6",
        "style": "node",
    },
    {
        "directive": "dsgn",
        "title": "Detailed Design",
        "prefix": "dsgn~",
        "color": "#F4BFD2",
        "style": "node",
    },
    {
        "directive": "impl",
        "title": "Implementation",
        "prefix": "impl~",
        "color": "#F5E6CA",
        "style": "node",
    },
    {
        "directive": "dimpl",
        "title": "Detailed Design & Implementation",
        "prefix": "dimpl~",
        "color": "#F5E6CA",
        "style": "node",
    },
    {
        "directive": "test",
        "title": "Unit Test",
        "prefix": "test~",
        "color": "#C3E0F2",
        "style": "node",
    },
    {
        "directive": "itest",
        "title": "Integration Test",
        "prefix": "itest~",
        "color": "#C3E0F2",
        "style": "node",
    },
]

needs_extra_options = [
    {
        "name": "rationale",
        "description": "Rationale for the requirement",
        "title": "Rationale",
        "schema": {
            "type": "string",
        },
    }
]
