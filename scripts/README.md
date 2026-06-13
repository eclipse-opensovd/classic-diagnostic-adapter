<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
-->

# CAN Bus Testing Scripts

This directory contains scripts for testing the CAN bus transport
implementation in the Classic Diagnostic Adapter (CDA) together with the
MDD-driven ECU simulator (`cda-simulator` crate).

CAN support in CDA is behind the `can` cargo feature; everything below
assumes binaries built with `--features can` where CDA itself is involved.

## Scripts Overview

### `setup_vxcan.sh` - Virtual CAN Setup

Creates a pair of linked virtual CAN interfaces for testing without physical
CAN hardware.

**Usage:**

```bash
sudo ./scripts/setup_vxcan.sh
```

**What it does:**

- Loads the `vcan`/`vxcan` kernel modules
- Creates linked virtual CAN interfaces: `vxcan0` <-> `vxcan1`
- Brings up both interfaces

**Result:**

- `vxcan0` - Used by the CDA (configured in `opensovd-cda-can.toml`)
- `vxcan1` - Used by the ECU simulator

Frames sent to `vxcan0` appear on `vxcan1` and vice versa.

### `../start_can_simulator.sh` - Simulator Lifecycle

Starts/stops the Rust `cda-simulator` for any MDD
(`start`, `stop`, `restart`, `status`). Writes `simulator.log` and
`simulator.pid` at the repo root. The MDD path is taken from `-m`/`--mdd`
(forwarded to cda-simulator) or the `SIM_MDD` environment variable. The
simulator also serves a REST control API on port 8080
(Swagger UI at `http://localhost:8080/swagger-ui`).

```bash
./start_can_simulator.sh -m testcontainer/odx/FLXC1000.mdd start
./start_can_simulator.sh stop
```

### `../start_with_can.sh` - CDA Lifecycle

Starts/stops CDA built with `--features can` using `opensovd-cda-can.toml`.
Writes `cda.log` and `cda.pid` at the repo root.

### `get_token.sh` - SOVD Auth Helper

Fetches a bearer token from CDA
(`POST /vehicle/v15/authorize`, default `localhost:20002`).

### `get_data.sh` - Generic Data Query

Authenticate against CDA and read a single data item of any component over
the SOVD REST API. Takes `<component> <service>` as positional args, e.g.:

```bash
./scripts/get_data.sh flxc1000 vindataidentifier
```

### `test_all_data_services.py` - Data Service Smoke Test

Lists every data service of a component and reads each one, reporting
failures (needs `python3` + `requests`).

```bash
./scripts/test_all_data_services.py flxc1000
```

The default component is `flxc1000`. Override with `--known-failure
<service_id>` (repeatable) to skip services known to fail on a given MDD.

### `test_can_e2e.sh` - Automated End-to-End Test

Self-contained e2e test of the whole CAN stack. For each MDD it starts the
simulator and a CDA instance (port 20102 by default, so it does not clash
with a dev instance on 20002) on the same CAN interface and asserts:

1. The ECU is discovered.
2. Variant detection completes (state `Online`).
3. The `VINDataIdentifier` data item returns the static test marker
   `CDA-SIM-MARKER000` (17 ASCII chars) end-to-end, through
   `HTTP -> CDA -> ISO-TP/CAN -> simulator`.

```bash
# all example MDDs from testcontainer/odx/ on vcan0 (created if --setup)
./scripts/test_can_e2e.sh --setup

# a single MDD with a specific simulator variant
./scripts/test_can_e2e.sh -v FLXC1000_App_0101 testcontainer/odx/FLXC1000.mdd

# userspace ISO-TP over raw CAN: vcan module needed, can_isotp NOT
./scripts/test_can_e2e.sh -t rawcan

# CAN frames over TCP: no (v)can or ISO-TP kernel support needed at all
./scripts/test_can_e2e.sh -t tcp
```

Notes:

- `-t/--transport` selects the ISO-TP backend (default `kernel`). The same
  assertions run in all modes; only the interface strings handed to the
  simulator and CDA (`rawcan:vcan0`, `tcplisten:`/`tcp:127.0.0.1:19800`)
  and the cargo feature set (`can`, `can-isotp-userspace`, `can-tcp`)
  change. In `tcp` mode the simulator binds a TCP frame hub and CDA
  connects to it, so the test also runs where SocketCAN is unavailable
  (e.g. containers without CAP_NET_ADMIN, non-Linux hosts).

- The example MDDs contain a CAN protocol layer but no CAN addressing
  com-params, so the script assigns explicit IDs (`0x7E0`/`0x7E8`) and CDA
  uses a matching `[[can.ecu_mappings]]` entry. MDDs that provide CAN IDs
  (e.g. via `CP_UniqueRespIdTable`) are used as-is.
- Protocol selection is adaptive: `protocol = "UDS_CAN"` first, falling
  back to `ignore_protocol = true` for MDDs without protocol definitions
  (e.g. TMCC3000, mirroring `testcontainer/cda-test-config.toml`).
- Designed to be CI-friendly: on a GitHub Actions ubuntu runner, the
  kernel modules are available via
  `sudo apt-get install linux-modules-extra-$(uname -r)` followed by
  `sudo modprobe vcan can_isotp`, after which `--setup` can create `vcan0`.

## Simulator Default Overrides

The simulator can load a `<mdd-stem>.defaults.toml` file at startup
(alongside the MDD) to seed non-zero, non-null values for known
parameters. The 6 example MDDs ship with such files; they set:

- `VINDataIdentifier_Read.VIN` to `CDA-SIM-MARKER000` (synthetic
  17-character marker; clearly not a real-world VIN).
- `ActiveDiagnosticSessionDataIdentifier_Read.EcuSessionType` to `1`
  (Default session).
- `Identification_Read.Identification` to `0xAABBCC`.

This lets the e2e test assert exact values rather than only HTTP 200. To
override the path, pass `--defaults <file>` (or `--no-defaults` to skip
loading entirely). See `cda-simulator --help`.

## Quick Start

```bash
# 1. one-time interface setup (or use vcan0 with --setup in the e2e test)
sudo ./scripts/setup_vxcan.sh

# 2. start the simulator (an example MDD on vxcan1)
./start_can_simulator.sh -m testcontainer/odx/FLXC1000.mdd start

# 3. start CDA (CAN feature, vxcan0)
./start_with_can.sh start

# 4. query data
./scripts/get_token.sh
./scripts/get_data.sh flxc1000 vindataidentifier
```

## Troubleshooting

### "vcan/vxcan module not found"

Your kernel lacks CAN support. Most distribution kernels ship it as modules;
otherwise compile with `CONFIG_CAN=m`, `CONFIG_CAN_VXCAN=m`, and
`CONFIG_CAN_ISOTP=m`.

### "Simulator not responding"

1. Check it is running: `./start_can_simulator.sh status`
2. Verify the interface: simulator and CDA must be on a linked CAN
   interface pair (e.g. vxcan0/vxcan1) or the same one
3. Watch the bus: `candump vcan0`

### "No ECUs discovered"

1. Check `cda.log` for CAN initialization errors
2. Verify CAN IDs in `opensovd-cda-can.toml` match the simulator (example
   MDDs: request `0x7E0`, response `0x7E8`)
3. Re-run `./scripts/test_can_e2e.sh --setup` to bypass configuration
   mistakes end-to-end

## Architecture Notes

```text
+-------------+         +-------------+
|     CDA     |<------->|  simulator  |
|   (vxcan0)  |  linked |  (vxcan1)   |
+-------------+         +-------------+
```

- CDA opens ISO-TP sockets per ECU (request/response CAN ID pair) and sends
  a functional-broadcast TesterPresent keep-alive on `0x7DF`.
- The simulator parses the MDD, answers `ReadDataByIdentifier` & friends,
  applies any `<basename>.defaults.toml` overrides, and lets tests push
  parameter values at runtime via the REST API
  (`PUT /services/<name>/parameters/<param>`).

## Related Files

- `/opensovd-cda-can.toml` - CAN-only CDA configuration
- `/start_can_simulator.sh` - generic simulator lifecycle wrapper
- `/start_with_can.sh` - CDA lifecycle wrapper (`--features can`)
- `/cda-simulator/` - the simulator crate
- `/testcontainer/odx/*.mdd` - example MDDs (with sibling `.defaults.toml`
  files; usable with the simulator and the e2e test)
