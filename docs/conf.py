# SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

import os
import shutil

extensions = [
    "sphinx_needs",
    "sphinx_codelinks",
    "sphinxcontrib.plantuml",
    "sphinx.ext.todo",
]

# sphinx-needs re-copies its static CSS on every build; Sphinx refuses to
# overwrite existing files in _build and warns, which fails incremental -W builds.
suppress_warnings = ["misc.copy_overwrite"]

src_trace_config_from_toml = "cda_trace.toml"

# Exclude build artifacts and editor/project files so Sphinx doesn't treat generated
# files under `_build` as additional source documents (this caused duplicate needs).
exclude_patterns = [
    "_build",
    "**/_build/**",
    ".venv",
    "Thumbs.db",
    ".DS_Store",
]

project = "CDA"
copyright = "%Y, Eclipse OpenSOVD authors"
# todo, automatically retrieve from project version
version = "1.0"
html_theme = "furo"
html_static_path = ["_static"]
html_css_files = ["force_light_theme.css", "wide_layout.css"]
html_js_files = ["force_light_theme.js"]

plantuml = (
    os.environ.get("PLANTUML")
    or shutil.which("plantuml")
    or "java -jar /usr/local/bin/plantuml.jar"
)

# a needs json should be generated
needs_build_json = True

# dots are not allowed, because they cause linking issues with sphinx-needs due to normalization,
# underscores require the use of backticks when used in rust comments,
# and are therefore also not allowed
needs_id_regex = r"^(req|arch|dsgn|impl|dimpl|testset|test|itest)~[a-zA-Z0-9\-]+$"
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
        "directive": "testset",
        "title": "Test Set",
        "prefix": "testset~",
        "color": "#A9CCE3",
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

needs_fields = {
    "rationale": {
        "description": "Rationale for the requirement",
        "title": "Rationale",
        "schema": {
            "type": "string",
        },
    },
    "reqtype": {
        "description": "Requirement type classification (functional, non-functional, "
        + "interface, constraint)",
        "title": "Requirement Type",
        "schema": {
            "type": "string",
            "enum": ["functional", "non-functional", "interface", "constraint"],
        },
    },
    "status": {
        "description": "Status of the item",
        "title": "Status",
        "schema": {
            "type": "string",
            "enum": ["draft", "valid", "approved", "rejected", "obsolete"],
        },
    },
}

# Traceability link direction checks
# `:links:` must always point from a higher-level item down to the lower-level
# item(s) realizing or verifying it:
#   req -> arch -> dsgn -> impl/dimpl
#   arch/dsgn -> testset -> test/itest
# Test sets are linked from arch/dsgn items, never from impl/dimpl items.
# Links between items of the same level are allowed, but must not form cycles.
# Violations are emitted as warnings, which fail `sphinx-build -W`.
NEED_LEVELS = {
    "req": 0,
    "arch": 1,
    "dsgn": 2,
    "impl": 3,
    "dimpl": 3,
    "testset": 4,
    "test": 5,
    "itest": 5,
}
IMPL_TYPES = ("impl", "dimpl")


def _need_type(need_id):
    return need_id.split("~", 1)[0]


def _need_level(need_id):
    return NEED_LEVELS.get(_need_type(need_id))


def check_link_direction(app, exception):
    if exception is not None:
        return
    from sphinx.util import logging
    from sphinx_needs.data import SphinxNeedsData

    logger = logging.getLogger("cda.traceability")
    needs = {
        need_id: need
        for need_id, need in SphinxNeedsData(app.env).get_needs_view().items()
        if not need["is_external"]
    }
    same_level = {}
    for need_id, need in needs.items():
        src = _need_level(need_id)
        for target in need["links"]:
            dst = _need_level(target)
            if src is None or dst is None:
                continue
            if _need_type(need_id) in IMPL_TYPES and _need_type(target) == "testset":
                logger.warning(
                    "%s links to test set %s; link the test set from the arch/dsgn item instead",
                    need_id,
                    target,
                    location=(need["docname"], need["lineno"]),
                )
            elif dst < src:
                logger.warning(
                    "%s links upwards to %s; reverse the link (higher level "
                    "items link to the lower level items realizing them)",
                    need_id,
                    target,
                    location=(need["docname"], need["lineno"]),
                )
            elif dst == src and target in needs:
                same_level.setdefault(need_id, []).append(target)

    # cycle detection on same-level links (iterative DFS)
    state = {}
    for start in same_level:
        if state.get(start):
            continue
        stack = [(start, iter(same_level.get(start, [])))]
        path = [start]
        state[start] = 1
        while stack:
            node, children = stack[-1]
            child = next(children, None)
            if child is None:
                stack.pop()
                path.pop()
                state[node] = 2
            elif state.get(child) == 1:
                cycle = [*path[path.index(child) :], child]
                need = needs[node]
                logger.warning(
                    "link cycle: %s",
                    " -> ".join(cycle),
                    location=(need["docname"], need["lineno"]),
                )
            elif not state.get(child):
                state[child] = 1
                path.append(child)
                stack.append((child, iter(same_level.get(child, []))))


def setup(app):
    # run before sphinx-needs' own build-finished handlers (priority 500)
    app.connect("build-finished", check_link_direction, priority=400)
