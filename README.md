# 🚗 Classic Diagnostic Adapter 🏥

This repository will contain the Classic Diagnostic Adapter of the Eclipse OpenSOVD project and its documentation.

In the SOVD (Service-Oriented Vehicle Diagnostics) context, a Classic Diagnostic Adapter serves as a
compatibility bridge between traditional (legacy) diagnostic interfaces and the modern SOVD-based
diagnostic architecture used in next-generation vehicles.

It facilitates the communication to the actual ECUs, by translating the SOVD calls with the
diagnostic description of the ECU to its UDS via DoIP counterpart. SOVD-REST-Requests are translated into their
respective UDS via DoIP counterparts. It handles the communication to the ECUs, by using the communication
parameters from the diagnostic description.

## goals

- 🚀 high performance (asynchronous I/O)
- 🤏 low memory and disk-space consumption
- 🛡️ safe & secure
- ⚡ fast startup
- 🧩 modularity / reusability

## introduction

### usage


## building

### prerequisites

You need to install a rust compiler & sdk - we recommend using [rustup](https://rustup.rs/) for this.

### build the executable

```shell
cargo build --release
```

## developing



### architecture

see [overview](docs/overview/index.adoc)