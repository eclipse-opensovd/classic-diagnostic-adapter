<!--
SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0

SPDX-License-Identifier: Apache-2.0
-->

# 🚗 Classic Diagnostic Adapter 🏥

This repository will contain the Classic Diagnostic Adapter of the Eclipse OpenSOVD project and its documentation.

In the SOVD (Service-Oriented Vehicle Diagnostics) context, a Classic Diagnostic Adapter serves as a
compatibility bridge between traditional (legacy) diagnostic interfaces and the modern SOVD-based
diagnostic architecture used in next-generation vehicles.

It facilitates the communication to the actual ECUs, by translating the SOVD calls with the
diagnostic description of the ECU to its UDS via DoIP counterpart.

It handles the communication to the ECUs, by using the communication parameters from the diagnostic description.

## goals

- 🚀 high performance (asynchronous I/O)
- 🤏 low memory and disk-space consumption
- 🛡️ safe & secure
- ⚡ fast startup
- 🧩 modularity / reusability

## introduction

### usage

1. Obtain one or more `.mdd` files (see prerequisites below).
2. Start the CDA, pointing it at your databases directory and DoIP interface:

   ```shell
   cargo run --release -- --databases-path ./databases --tester-address <YOUR_IP>
   ```

3. Wait a few seconds for DoIP discovery, then confirm the CDA found your ECUs:

   ```shell
   curl http://localhost:20002/vehicle/v15/components | jq
   ```

4. Browse the full API interactively at **<http://localhost:20002/swagger-ui>**.

### prerequisites

To run the CDA you will need at least one `MDD` file. Check out [eclipse-opensovd/odx-converter](https://github.com/eclipse-opensovd/odx-converter) on how to get started with creating `MDD`(s) from ODX.

Once you have the `MDD`(s) you can update the config in `opensovd-cda.toml` to point `databases_path` to the directory containing the files. Alternatively you can pass the config via arg `--databases-path MY_PATH`.

### running

Ensure that the config (`opensovd-cda.toml`) fits your setup:

- tester_address is set to the IP of your DoIP interface.
- databases_path points to a valid path containing one or more `.mdd` files.

Run the cda via `cargo run --release` or after building from the target directory `./opensovd-cda`

To see the available command line options run `./opensovd-cda -h`

#### protocol selection

Use `--protocol-name` to select the DoIP protocol variant used for com-param lookups in the diagnostic database (matched case-insensitively):

| Flag | Protocol | When to use |
|------|----------|-------------|
| `--protocol-name UDS_Ethernet_DoIP_DOBT` *(default)* | DoIP-DOBT | CDA runs inside the vehicle (e.g. on a gateway ECU) |
| `--protocol-name UDS_Ethernet_DoIP` | DoIP | CDA runs outside the vehicle (laptop, test bench) |

```shell
# Offboard
cargo run --release -- --databases-path ./databases --tester-address <YOUR_IP> --protocol-name UDS_Ethernet_DoIP
```

## building

### prerequisites for building & sdk

We recommend using [rustup](https://rustup.rs/) for this.
The minimum required version of the toolchain is [Rust 1.88.0](https://blog.rust-lang.org/2025/06/26/Rust-1.88.0/).

### build the executable

```shell
cargo build --release
```

### Windows

Prerequisite:

- Build Toolchain for Windows
- OpenSSL (if targeting the OpenSSL build)
   `winget install openssl`

#### Setup Env

```pwsh
$env:CMAKE_GENERATOR="Ninja"
$env:OPENSSL_DIR="C:\Program Files\OpenSSL-Win64"
$env:OPENSSL_LIB_DIR="C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD"
$env:OPENSSL_INCLUDE_DIR="C:\Program Files\OpenSSL-Win64\include"
```

### building with Bazel

As an alternative to Cargo, the project can be built with [Bazel](https://bazel.build/) (via [Bazelisk](https://github.com/bazelbuild/bazelisk)).

```shell
# Build with OpenSSL (default TLS backend)
bazel build //:opensovd-cda

# Build with mbedtls TLS backend
bazel build --config=mbedtls //:opensovd-cda
```

The resulting binary is located at `bazel-bin/cda-main/opensovd-cda`.

### Rust toolchain policy (Bazel)

This repository is intentionally toolchain-neutral when consumed as a Bazel dependency.
It does not force downstream projects to use a specific Rust distribution.

- Local development in this repository uses upstream `rules_rust` toolchains.
- Downstream integrators can register their own Rust toolchains (for example Ferrocene)
  in their top-level `MODULE.bazel`.

This keeps OpenSOVD independent from SCORE-specific toolchain modules while still allowing
SCORE-based integrations to use Ferrocene where required.

## developing

### pre commit

Check staged files:

```shell
uv run --group tools prek run
```

Check all files:

```shell
uv run --group tools prek run --all-files
```

Install this command as documented here: <https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks>

### codestyle

see [codestyle](CODESTYLE.md)

### linting

To run clippy with the same settings as the CI/CD pipeline (nightly toolchain, all targets and features, warnings as errors):

```shell
cargo +nightly-2025-07-14 clippy --all-targets --all-features -- -D warnings
```

Or using the `cargo lint` alias (stable toolchain, otherwise identical flags):

```shell
cargo lint
```

### testing

#### unit tests

Unittests are placed in the relevant module as usual in rust:

```rust
...
#[cfg(test)]
mod test {
    ...
}
```

Run unit tests with:

```shell
cargo test --locked --lib
```

#### integration tests

Integration tests are located in the `integration-tests/` directory and test the complete CDA system end-to-end, including:

- SOVD API endpoints
- ECU communication via DoIP
- Session management and locking

The integration test framework automatically manages the test environment by:

1. Starting an ECU simulator
2. Starting the CDA with appropriate configuration
3. Running tests against the running system
4. Cleaning up resources after tests complete

##### running integration tests

**Using Docker (Recommended):**

Docker mode spins up the ECU simulator and CDA in isolated containers:

```shell
cargo test --locked --features integration-tests
```

**Without Docker (For Development/Debugging):**

Running locally allows easier debugging but requires manual setup:

```shell
# Set environment variable to disable Docker
export CDA_INTEGRATION_TEST_USE_DOCKER=false

# Optional set an IP address to bind the tester interface to
# export CDA_INTEGRATION_TEST_TESTER_ADDRESS=

# Run the tests
cargo test --locked --features integration-tests
```

When running without Docker, the ECU simulator and CDA will run as local processes with default ports (20002 for CDA, 13400 for DoIP gateway, 8181 for ECU sim control).
Furthermore the local setup does *not* automatically build the MDD files from ODX data, so ensure that the required MDD files are already present.

##### environment variables

The integration test framework supports the following environment variables:

- **`CDA_INTEGRATION_TEST_USE_DOCKER`** (default: `true`)
  Controls whether to use Docker Compose or run services locally.
  - `true`: Uses Docker Compose to run CDA and ECU simulator in containers
  - `false`: Runs services as local processes (useful for debugging)

  Example:

  ```shell
  export CDA_INTEGRATION_TEST_USE_DOCKER=false
  ```

- **`CDA_INTEGRATION_TEST_TESTER_ADDRESS`** (default: `0.0.0.0`)
  Override the tester address used by the CDA when running without Docker.
  Some systems may require using a specific interface address (e.g., `127.0.0.1` or a specific network interface IP) for proper ECU simulator connectivity.

  Example:

  ```shell
  export CDA_INTEGRATION_TEST_TESTER_ADDRESS=127.0.0.1
  ```

- **`CDA_INTEGRATION_TEST_COVERAGE`** (default: `false`)
  When set to `true`, uses coverage-instrumented Docker images for integration tests.
  This enables code coverage collection from tests running inside Docker containers.

  Example:

  ```shell
  export CDA_INTEGRATION_TEST_COVERAGE=true
  cargo llvm-cov --locked --features integration-tests --lcov --output-path lcov.info
  ```

##### test structure

Tests use a shared runtime to avoid repeatedly starting/stopping the CDA and ECU simulator:

- Tests can request exclusive or shared access to the test runtime
- Exclusive tests hold a mutex lock to prevent concurrent execution
- The test framework automatically finds available ports when using Docker
- Test resources (Docker containers, processes) are automatically cleaned up on exit

Example test:

```rust
#[tokio::test]
async fn test_ecu_session_switching() {
    // Request exclusive access to prevent concurrent modifications
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();

    // runtime.config contains CDA configuration
    // runtime.ecu_sim contains ECU simulator connection info

    // ... perform test operations ...
}
```

### generate module dependency graph for workspace

With the help of [cargo-depgraph](https://github.com/jplatte/cargo-depgraph) a simple diagram showing
the relations between the workspace crates can be generated. To create a png from the output of
cargo-depgraph, [Graphviz](https://graphviz.org/) is required.

```shell
cargo depgraph --target-deps --dedup-transitive-deps --workspace-only | dot -Tpng > depgraph.png
```

### build with tokio-tracing for tokio-console

To analyze the runtime during execution you can build and run the cda with
[tokio-console](https://github.com/tokio-rs/console) support.

#### install tokio-console

```shell
cargo install --locked tokio-console
```

You need to enable tokio-experimental in the rustflags.

```shell
RUSTFLAGS="--cfg tokio_unstable" cargo run --release --features tokio-tracing
```

If you don't want to specify the env all the time, you can add this to your `.cargo/config.toml`

```toml
[build]
rustflags = ["--cfg", "tokio_unstable"]
```

In a second terminal window start `tokio-console` and it should automatically connect.

### architecture

see [overview](https://eclipse-opensovd.github.io/classic-diagnostic-adapter/03_architecture/index.html)
