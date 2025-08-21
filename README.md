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

### build the executable

```shell
cargo build --release
```

## developing

### Codestyle

see [codestyle](CODESTYLE.md)

### Testing

Unittests are placed in the relevant module as usual in rust:
```rust
...
#[cfg(test)]
mod test {
    ...
}
```

Integration tests are not yet included, as they rely on ECU data and will be included once the 
simluation & odx files without vendor relation are available.

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