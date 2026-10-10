---
name: cda-capture-analysis
description: Analyze Wireshark captures (.pcap/.pcapng) of CDA to ECU communication over DoIP or CAN/ISO-TP. Extracts UDS request/response pairs with timings (P2, P2*, NRC 0x78/0x21/0x94 chains, tester present cycle, DoIP ACK/routing activation), checks them against ISO 14229/13400/15765-2 and against the ECU's CDA com params read from the MDD via mdd-mcp. Use whenever a capture file needs to be inspected or timing/conformance of ECU or CDA behavior must be verified.
---

<!--
SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0

SPDX-License-Identifier: Apache-2.0
-->

# CDA Capture Analysis

Goal: from a capture file, produce (1) a UDS transaction table with timings, (2) a protocol
conformance verdict and (3) a comparison of observed timings with the effective CDA com
params of the ECU. Every finding must reference frame numbers.

## 0. Prerequisites

- `tshark` (Wireshark CLI) and `python3`. If missing: `sudo apt install tshark` (or the
  distro equivalent); do not install without asking the user.
- `mdd-mcp_*` tools for com params. If missing, load the `cda-mdd-mcp-setup` skill.
- For normative details (exact timer semantics, NRC rules) load the
  `cda-diagnostic-protocol-spec` skill or delegate to the `cda-spec-expert` agent.
- Ask the user for anything not inferable: capture file, ECU name / logical address
  (DoIP) or CAN IDs, MDD file, CDA config file (`opensovd-cda.toml`) used during capture,
  and the SOVD request(s) that triggered the traffic.

## 1. Inspect the capture

```sh
capinfos <file>                                  # duration, packet count, link type
tshark -r <file> -q -z io,phs                    # protocol hierarchy: doip? iso15765? uds?
tshark -r <file> -q -z conv,tcp                  # DoIP TCP connections (port 13400)
```

- DoIP on a non-standard port: add `-d tcp.port==<p>,doip -d udp.port==<p>,doip`.
- CAN: link type SocketCAN / candump. ISO-TP must be decoded as UDS:
  `-o iso15765.try_heuristic_first:TRUE` or `-d can.id==0x7E0,iso15765` per ID; extended
  / mixed addressing and CAN FD need the matching `iso15765` preferences.
- Check `tcp.analysis.flags` (retransmissions, zero window) — these distort timings.
- Note clock source: timings are only as good as the capture point. A capture on the CDA
  host measures tester-side times (includes network latency); on the ECU side it measures
  ECU-side times. State this in the report.

## 2. Extract UDS traffic

Use the bundled script (wraps `tshark`, pairs requests and responses, computes timings):

```sh
python3 .opencode/skills/cda-capture-analysis/scripts/uds_timeline.py <file> \
    [--ecu 0x1234] [--tshark-arg "-d tcp.port==13401,doip"] [--csv out.csv] [--json out.json]
```

Output per UDS message: frame, relative time, direction, source/target address (DoIP
logical address or CAN ID), SID, raw payload (hex). Per transaction: request frame,
DoIP diagnostic ACK/NACK delay, time to first response, each `0x7F xx 78` (response
pending) gap, final response delay, final result (positive / NRC name). It also lists
tester present (`0x3E`) intervals, session changes (`0x10`), security access (`0x27`) and
DoIP routing activation (`0x0005`/`0x0006`) with delays.

Timing caveat for ISO-TP: tshark reports a reassembled multi-frame UDS message at its last
CF, so the script's response time is "until complete" (P6-like). For P2client/P2server
checks on CAN, take the FF timestamp:
`tshark -r <file> -Y "iso15765.message_type == 1" -T fields -e frame.number -e frame.time_relative -e can.id`.

If the script is unsuitable (unusual dissector setup), extract manually:

```sh
tshark -r <file> -Y "uds || doip" -T fields -E separator=';' \
  -e frame.number -e frame.time_relative -e doip.payload_type \
  -e doip.source_address -e doip.target_address -e can.id -e uds.sid -e uds.err.sid \
  -e uds.err.code -e data.data
```

## 3. Get the ECU com params (mdd-mcp)

Use the `mdd-mcp_*` tools (or delegate to the `cda-mdd-inspector` agent with the absolute
MDD path) to read the com params of the ECU variant and protocol (`UDS_Ethernet_DoIP`,
`UDS_CAN`, ...) actually in use. Collect at least:

| Com param | CDA meaning | Check against capture |
| --- | --- | --- |
| `CP_P6Max` | Client timeout for a response, used by CDA for DoIP and CAN (default 1 s) | end of request -> complete response (DoIP) / response start (ISO-TP) |
| `CP_P6Star` | Client timeout after each NRC 0x78 (default 1 s) | 0x78 -> next response |
| `CP_P2Max` / `CP_P2Star` (`CP_P2Min`) | Expected server P2/P2* (ISO-TP client timing basis) | compare with 0x10 response and ECU behavior |
| CAN config `response_timeout_ms` | `cda-comm-can` read timeout (default 5000 ms) | CAN response gaps |
| `CP_RC78Handling`, `CP_RC78CompletionTimeout` | 0x78 policy / max total wait (25 s) | whole 0x78 chain |
| `CP_RC21Handling`, `CP_RC21RequestTime`, `CP_RC21CompletionTimeout` | busy-repeat policy | gap NRC 0x21 -> repeated request |
| `CP_RC94Handling`, `CP_RC94RequestTime`, `CP_RC94CompletionTimeout` | temp. not available repeat | gap NRC 0x94 -> repeated request |
| `CP_RepeatReqCountApp` | app-level repeats | number of identical repeated requests |
| `CP_TesterPresentHandling`, `CP_TesterPresentSendType`, `CP_TesterPresentTime`, `CP_TesterPresentAddrMode`, `CP_TesterPresentReqResp`, `CP_TesterPresentMessage` | tester present | 0x3E period, addressing, suppressPosRsp bit, payload |
| `CP_DoIPLogicalEcuAddress`, `CP_DoIPLogicalTesterAddress`, `CP_DoIPLogicalGatewayAddress`, `CP_DoIPLogicalFunctionalAddress` | addressing | DoIP SA/TA |
| `CP_DoIPDiagnosticAckTimeout` | wait for DoIP 0x8002/0x8003 | request -> diag ACK |
| `CP_DoIPRoutingActivationTimeout` | wait for 0x0006 | 0x0005 -> 0x0006 |
| `CP_DoIPNumberOfRetries`, `CP_DoIPRetryPeriod`, `CP_RepeatReqCountTrans` | NACK retries | retries after 0x8003 |
| `CP_DoIPConnectionTimeout`, `CP_DoIPConnectionRetryDelay`, `CP_DoIPConnectionRetryAttempts` | TCP connect | SYN retries / spacing |
| `CP_CanPhysReqId`, `CP_CanRespUSDTId`, `CP_CanFuncReqId`, `CP_UniqueRespIdTable` | CAN IDs | CAN IDs in capture |
| ISO-TP `CP_As/Ar/Bs/Br/Cs/Cr`, `CP_BlockSize`, `CP_STmin` | ECU / ISO-TP timing | server response times, FC parameters |

Effective value = MDD value unless overridden in the CDA config (`[com_params]` in
`opensovd-cda.toml` / `CDA_` env vars, precedence `Config` vs `Database`; see
`cda-main/src/config/com_params.rs` and `cda-interfaces/src/datatypes/com_params.rs` for
names and defaults). Always state which source each value came from. Watch units: MDD
values are often in microseconds.

## 4. Conformance checks

Standard behavior (verify details with the spec skill when a finding depends on it):

- UDS (ISO 14229-1/-2)
  - Every non-suppressed request gets exactly one final response; response SID = SID+0x40
    or `7F <SID> <NRC>`. Positive response echoes subfunction / DID as applicable.
  - Suppress-positive-response bit (subfunction bit 7) set -> no positive response
    (NRCs still allowed, except for functional requests with NRC 0x11/0x12/0x31/0x7E/0x7F).
  - Server side (all transports): ECU must start its response within P2server
    (typ. 50 ms) else send 0x78; after each 0x78 the next response within P2*server
    (typ. 5000 ms). Values are announced in the 0x10 positive response (P2 in ms, P2* in
    10 ms units) — decode them and compare with the MDD values.
  - Client side (ISO 14229-2), depends on the transport:
    - ISO-TP: P2client / P2*client, measured until the *start* of the response (SF or FF
      reception). P2client = P2server + network delays.
    - DoIP: P6client / P6*client, measured until the *complete* response is received
      (no first-frame indication on DoIP). P6client > P2client.
    - The CDA uses `CP_P6Max` / `CP_P6Star` for both transports (`cda-comm-uds`). On CAN,
      additionally `response_timeout_ms` from the `cda-comm-can` config bounds a single
      read. Measure a gap against the timer that matches the transport, and state which
      one you used: start of response on ISO-TP, end of the last CF on DoIP.
  - No new request from tester while a response is pending (except functional TP).
  - S3server (5 s): tester present must keep non-default sessions alive; session falls
    back to default after S3 without traffic.
  - NRC plausibility (e.g. 0x7F/0x7E vs current session, 0x33/0x35/0x36/0x37 for 0x27,
    0x37 delay respected before next seed request).
- DoIP (ISO 13400-2)
  - Routing activation (0x0005) before diagnostic messages; response 0x0006 code 0x10 OK.
  - Each diagnostic message (0x8001) gets 0x8002 ACK or 0x8003 NACK before the UDS
    response; SA/TA swapped correctly; ACK echoes previous message optionally.
  - Alive check (0x0007/0x0008), generic header NACK (0x0000), protocol version / inverse.
- ISO-TP (ISO 15765-2)
  - SF/FF/CF/FC sequence, SN wrap 0..F, FC.BS/STmin respected by sender, N_Bs/N_Cr
    timeouts, padding consistent, correct response CAN ID.

## 5. Compare with CDA com params

For each transaction decide which side deviated:

- ECU slow but within spec, CDA timed out early -> com param too small (or not applied).
- CDA waited longer/shorter than the configured value -> CDA bug; locate in
  `cda-comm-uds` (P6/0x78/0x21/0x94/tester present) or `cda-comm-doip` /
  `cda-comm-can` (ACK, routing activation, connect, ISO-TP).
- Repeat count, repeat interval, tester present period/addressing differ from params.
- ECU response outside P2server/P2*server without 0x78 -> ECU non-conformant.
- Client timer must suit the transport: on DoIP `CP_P6Max` must cover P2server plus
  transfer time of the full response (large responses, gateway routing). On ISO-TP it is
  compared like P2client and must exceed P2server plus bus delays.

Allow tolerance for scheduling jitter (state the tolerance used, e.g. ±10 ms or 5 %).
When a timeout is suspected but no frame shows it, the CDA side may have given up
silently — correlate with CDA logs (DLT / `RUST_LOG=debug`) by timestamp, request them if
missing.

## 6. Report

1. Capture summary: file, duration, capture point, transport, ECU(s) and addresses.
2. Effective com params table: name, MDD value, config override, effective value.
3. Transaction table (frame refs, SID, result, timings) — abbreviate long repetitive runs.
4. Findings, each with: frame numbers, observed value, expected value + source (spec
   clause or com param), verdict (`OK` / `ECU non-conformant` / `CDA deviation` /
   `config mismatch` / `inconclusive`), suspected code location if CDA.
5. Open questions / data needed.

If the analysis is part of a bug investigation, hand the findings to the
`cda-issue-analysis` workflow.
