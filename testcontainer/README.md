# Manual test setup

## Generate odx file(s)

In the directory `testcontainer/odx`, run:

```sh
./generate_docker.sh
```

This should generate the PDX-files:

- FLXDC1000.pdx

## Build & run converter on pdx files

Build the converter with `./gradlew shadowJar` in the odx-converter directory.

Go back to the directory with the `pdx`-files, and execute:
```sh
java -jar <path-to-odx-converter>/converter/build/libs/converter-all.jar FLXC1000.pdx
```

You should now have a `FLXC1000.mdd` and `FLXC1000.mdd.log` in the same directory.

## Build & run the simulation

Goto `testcontainer/ecu-sim/docker`.

Build:
```sh
./build_docker.sh
```

Run:
```sh
./run_docker.sh
```
Needs privileged access, so it can add more ip addresses to the network interface for multiple gateways.

## Build & run the CDA

In the CDA main directory:
```sh
cargo build --release
```

In the `target/release` folder:
```sh
./opensovd-cda -o true -d ../../testcontainer/odx -t 172.17.0.1
```

You might need to change the IP to your docker interface used by the sim.

Currently you need to start the SIM first, haven't analyzed further.