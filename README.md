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

### prerequisites

To run the CDA you will need at least one `MDD` file. Check out [eclipse-opensovd/odx-converter](https://github.com/eclipse-opensovd/odx-converter) on how to get started with creating `MDD`(s) from ODX.  

> [!IMPORTANT]
> At the moment it is necessary to use the [floroks/flatbuffers-ng](https://github.com/eclipse-opensovd/odx-converter/tree/floroks/flatbuffers-ng) branch to create `MDD` files containing the ECU description in the flatbuf format.


Once you have the `MDD`(s) you can update the config in `opensovd-cda.toml` to point `databases_path` to the directory containing the files. Alternatively you can pass the config via arg `--databases-path MY_PATH`.

### running

Ensure that the config (`opensovd-cda.toml`) fits your setup:
 - tester_address is set to the IP of your DoIP interface.
 - databases_path points to a valid path containing one or more `.mdd` files.

Run the cda via `cargo run --release` or after building from the target directory `./opensovd-cda`

To see the available command line options run `./opensovd-cda -h`

## building

### prerequisites

You need to install a rust compiler & sdk - we recommend using [rustup](https://rustup.rs/) for this.  
The minimum required version of the toolchain is [Rust 1.88.0](https://blog.rust-lang.org/2025/06/26/Rust-1.88.0/).

### build the executable

```shell
cargo build --release
```

## developing

### codestyle

see [codestyle](CODESTYLE.md)

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
Furthermore the local setup does _not_ automatically build the MDD files from ODX data, so ensure that the required MDD files are already present.

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

see [overview](docs/architecture/index.adoc)