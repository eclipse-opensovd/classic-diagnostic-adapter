<!--
SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0

SPDX-License-Identifier: Apache-2.0
-->

# Demo: Wireshark capture analysis with the `cda-capture-analysis` skill

The demo records DoIP traffic between the CDA and the ECU simulator while the simulator
misbehaves on purpose. An AI agent then analyzes each capture with the
`cda-capture-analysis` skill and decides whether the ECU, the CDA or the configuration is
at fault.

## Prerequisites

- Docker with Compose, `curl`, `jq`
- `tshark` and `python3` (for the analysis only)
- An opencode session in the repository root with the `mdd-mcp` server set up
  (skill `cda-mdd-mcp-setup`)

## Record the captures

```sh
cd testcontainer
docker compose up -d --build ecu-sim cda
demo/capture-analysis/run-demo.sh list     # show scenarios
demo/capture-analysis/run-demo.sh all      # or: run-demo.sh pending-gap late-response
```

The script captures inside the network namespace of the `ecu-sim` container (image
`nicolaka/netshoot`), so no host privileges are needed. Ports are taken from
`testcontainer/.env`.

For each scenario it writes the following to `out/` (`*.pcap*` is git-ignored):

- `<scenario>.pcap`: the DoIP traffic
- `<scenario>.log`: the CDA container logs (debug level) for the capture period, with
  timestamps for correlation with capture frames. The SOVD requests, HTTP status and
  duration are printed to the terminal.

Before each capture the script resets the sim and reads `Identification` (`22 F100`, also used for variant detection) outside the
capture, so variant detection and DoIP connection setup don't clutter the trace.

## Scenarios

The CDA test config uses `CP_P6Max = 1 s`, `CP_P6Star = 1 s`, `CP_RepeatReqCountApp = 2` and
`CP_RC21RequestTime = 200 ms`. While it delays, the sim's ECU is busy and answers every
other request with NRC 0x21.

| Scenario | Sim behavior | What the analysis should find |
| --- | --- | --- |
| `healthy` | lock, extended session, read the VIN, idle 8 s, unlock | 0x10 03 with the P2/P2* it announces, tester present period vs. `CP_TesterPresentTime`. All OK. |
| `late-response` | reply after 1500 ms, no 0x78 | ECU breaks P2server (no 0x78). CDA times out at P6Max (1 s) and repeats; the ECU answers the repeat with 0x21. The late reply to the first request races with that 0x21; the CDA retries after 0x21 and SOVD shows HTTP 200 although the capture and CDA log show a timeout. |
| `pending-ok` | 4 × 0x78 every 800 ms, then the reply | Every 0x78 gap is under `CP_P6Star`. Total 3.2 s is OK. |
| `pending-gap` | 2 × 0x78 every 1500 ms | The ECU stays within P2*server (5 s, ISO), but the CDA gives up after `CP_P6Star` (1 s) and repeats while the response is still pending. Verdict: `config mismatch`, P6Star too small for this ECU. |
| `busy-retry` | 3 × NRC 0x21, then the reply | The repeat interval of about 200 ms matches `CP_RC21RequestTime`. OK. |
| `no-response` | never replies | 1 + 2 repeats (`CP_RepeatReqCountApp`), each after P6Max of 1 s. HTTP 504 after 3 s. OK on the CDA side. |

Suggested flow (about 15 minutes): `healthy` as the baseline, then `pending-ok` and
`pending-gap` back to back ("both slow, only one breaks — who's to blame?"), then
`late-response` as the closing case.

## Agent prompts

```text
Analyze testcontainer/demo/capture-analysis/out/pending-gap.pcap.
ECU FLXC1000 (MDD testcontainer/odx/FLXC1000.mdd), CDA config testcontainer/cda-test-config.toml.
CDA log: testcontainer/demo/capture-analysis/out/pending-gap.log
Is the ECU or the CDA at fault?
```

```text
Compare pending-ok.pcap and pending-gap.pcap. Both requests took about 3 s, so why does only one
follow the protocol? Give a com param change that would make pending-gap pass.
```

```text
The SOVD request in late-response returned HTTP 200 with the correct VIN. Check
late-response.pcap and late-response.log: is that result trustworthy?
```

## Sim interceptor API (used by the script)

`PUT /interceptor/{ecu}/inbound/{name}` on the sim control port, `DELETE` removes it:

```json
{
  "request": "22F190",
  "response": null,
  "removeAfterNRequest": 1,
  "delayMs": 1500,
  "pendingResponses": 2,
  "pendingIntervalMs": 1500
}
```

- `request`: a hex regex, where `[]` matches anything.
- `response`: the hex reply. `""` means no reply. `null` forwards the request to the regular
  ECU handler.
- `delayMs`: wait before the first reply.
- `pendingResponses` and `pendingIntervalMs`: send `7F <SID> 78` N times, waiting the
  interval after each one (default 1000 ms).

All timing fields are optional, so existing interceptor calls behave as before.
