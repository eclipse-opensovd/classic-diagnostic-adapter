<!--
SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0

SPDX-License-Identifier: Apache-2.0
-->

# Heap Profiling

This guide describes how to attribute CDA heap allocations to their Rust call
stacks during startup or a representative workload.

## Install Heaptrack

On Debian or Ubuntu, install Heaptrack and its graphical viewer:

```shell
sudo apt install heaptrack heaptrack-gui
```

## Build the profiling binary

Build the `release-with-debug` profile with the `heap-profiling` feature:

```shell
RUSTFLAGS='-C force-frame-pointers=yes' \
  cargo build --locked --profile release-with-debug --bin opensovd-cda \
  --features heap-profiling
```

The resulting binary is `target/release-with-debug/opensovd-cda`.

The `heap-profiling` feature uses Rust's system allocator instead of mimalloc,
allowing Heaptrack to intercept and attribute allocations. The
`release-with-debug` profile retains debug information and reduces optimization
to improve call-stack readability.

## Capture allocations

Run CDA under Heaptrack with the same arguments as the scenario to analyze:

```shell
heaptrack target/release-with-debug/opensovd-cda -c <your-config.toml>
```

For startup analysis, wait until CDA has loaded its databases and discovered
ECUs, then stop it cleanly. Heaptrack writes a capture named similar to
`heaptrack.opensovd-cda.<PID>.gz` to the current directory.

## Inspect the capture

Open the generated capture in the Heaptrack GUI:

```shell
heaptrack_gui heaptrack.opensovd-cda.<PID>.gz
```

Use the Peak Contribution view to identify code retaining the most memory at
startup. Use Total Allocations to identify allocation churn. Expand a call stack
until it reaches a CDA crate such as `cda_database`, `cda_sovd`, or
`cda_comm_*`; standard-library frames such as `FromIterator` are normally only
generic allocation helpers.
