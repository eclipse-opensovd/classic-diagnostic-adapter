<!--
SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0

SPDX-License-Identifier: Apache-2.0
-->

# Flash download benchmark

Flashes a random file (default 100 MiB) through the CDA into the ECU simulator over DoIP,
once per `maxNumberOfBlockLength`, and records a DoIP capture, the CDA logs and a CSV
summary per run. The ECU simulator verifies length, block sequence counter, block length
and the SHA-1 of the received data.

## Prerequisites

- Docker with Compose, `curl`, `jq`, `sha1sum` or `shasum`
- `python3` for millisecond timestamps (without it the durations have second resolution)
- `tshark` and `python3` for the gap analysis (optional)

The script runs with the stock macOS tools (BSD `date`/`stat`, bash 3.2).

## Run

```sh
cd testcontainer
docker compose up -d --build ecu-sim cda
demo/flash-benchmark/run-benchmark.sh                 # 4096 8192 16384 32768 65535
demo/flash-benchmark/run-benchmark.sh 4096 65535      # selected block lengths
FILE_SIZE=1048576 SNAPLEN=128 demo/flash-benchmark/run-benchmark.sh
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `FILE_SIZE` | `104857600` | Size of the random flash file in bytes |
| `SNAPLEN` | `0` | tcpdump snap length, `0` captures full packets |
| `CDA_RUST_LOG` | `info` | `RUST_LOG` of the CDA; the container is recreated with it and restored to the compose default (`debug`) when the script exits |
| `ECU` | `FLXC1000` | ECU to flash |
| `OUT_DIR` | `./out` | Output directory |

The data per TransferData request is `maxNumberOfBlockLength - 2` (SID and block sequence
counter are part of the block length, ISO 14229-1).

## Output

`out/results_<timestamp>.csv` contains per block length the transfer duration (CDA view
and ECU view), throughput and the tester turnaround measured by `analyze_gaps.py`: the time
from the ECU's TransferData positive response until the CDA starts sending the next
TransferData request (mean, median, p95, max, min).

`analyze_gaps.py <pcap>` can also be run on its own.
