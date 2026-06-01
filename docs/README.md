<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# Documentation

## Building with uv (local)

Requires [uv](https://docs.astral.sh/uv/) and `plantuml` on your PATH (or set the `PLANTUML` env var).

```sh
cd docs
uv run sphinx-build -W -b html . _build/html
```

To override the PlantUML command:

```sh
PLANTUML="java -jar /path/to/plantuml.jar" uv run sphinx-build -W -b html . _build/html
```

## Building with Docker

```sh
cd docs
./rebuild_docs.sh
```

This builds a self-contained Docker image with all dependencies (including PlantUML) and runs sphinx-build inside it.

## Output

HTML output is written to `docs/_build/html/`.
