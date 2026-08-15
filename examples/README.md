<!--
SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0

SPDX-License-Identifier: Apache-2.0
-->

# OEM integration examples

One runnable binary per CDA extension point. Each customises exactly one thing
and leaves everything else stock, so the diff against a plain `opensovd-cda` is
the extension point and nothing else.

| Example | Extension point |
| --- | --- |
| [`oem-routes`](oem-routes) | Custom SOVD routes: both service addressing modes, DTCs, and ECU / functional-group locks |
| [`oem-health`](oem-health) | Reporting a vendor service through CDA's `/health` |
| [`oem-security`](oem-security) | `SecurityPlugin` / `SecurityPluginLoader` |
| [`oem-communication`](oem-communication) | `CommunicationPlugin` - when the vehicle network may be brought up |
| [`oem-storage`](oem-storage) | `Storage` backend for runtime-update files |
| [`oem-update-policy`](oem-update-policy) | `RuntimeUpdateSecurityPlugin` and `RuntimeFileInspector` |

Each takes the same CLI flags and configuration file as `opensovd-cda`:

```sh
cargo run -p example-oem-routes -- --config opensovd-cda.toml
```

## Vendor configuration

CDA's configuration file reserves an `[oem]` section that CDA itself never reads.
It is handed to extensions verbatim through `ExtensionContext::oem_config`, so an
integration can keep its own settings in the same file instead of loading a
second one:

```toml
[oem]
endpoint = "https://vendor.example/api"
retries = 3

[oem.nested]
enabled = true
```

It is a named section rather than a catch-all so that an unknown key elsewhere in
the file stays a typo instead of being silently absorbed. The section is absent
from the shipped `opensovd-cda.toml` reference on purpose - it exists for
integrations, not for a stock CDA.

## Why they are in the workspace

They stand in for an external OEM integration. Nothing in this repository used to
consume the public extension points, so a breaking visibility or signature change
was only discovered when someone else's build failed. These are workspace
members, so that change fails here first.

They are deliberately *not* default members: a plain `cargo build` or `cargo test`
skips them, and CI builds them in a dedicated step that can report which
extension point broke. Building them all:

```sh
cargo build --all-features \
  -p example-oem-routes \
  -p example-oem-health \
  -p example-oem-security \
  -p example-oem-communication \
  -p example-oem-storage \
  -p example-oem-update-policy
```

## Adding one

Add the crate under `examples/`, then add it to **both** `members` and — unless it
should build by default — leave it out of `default-members` in the root
`Cargo.toml`, and add it to the CI step in `.github/workflows/build.yml`. The
container build copies `examples/` wholesale, so it needs no change.
