---
name: cda-diagnostic-protocol-spec
description: Knowledge and workflow for answering diagnostic protocol specification questions (UDS ISO 14229, DoIP ISO 13400, CAN/ISO-TP ISO 15765-2) in the context of the Classic Diagnostic Adapter (CDA) documentation and code. Use for NRCs, timing (P2/P2*, S3, N_/A_ timers), sessions, security access, DoIP routing activation and payload types, ISO-TP framing, flow control and addressing, or spec-conformance checks.
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

# Diagnostic Protocol Specifications

## Sources, in priority order

1. Specification text provided by the user (markdown version of a standard or excerpts
   of relevant clauses). This is authoritative. If a file path is given, read and grep it.
   Standards may also be provided via the environment variable `OPENSOVD_SPEC_DIR`
   (see below).
2. The CDA documentation in `docs/`:
   - `docs/02_requirements/` (especially `04_communication.rst`, `03_diagnostic_tester.rst`)
   - `docs/03_architecture/` (especially `03_communication/`)
   - `docs/04_adr/`
   - `docs/01_about/02_terminology.rst`, `docs/01_about/03_conventions.rst`
3. General knowledge of the standards (below). Always label it as such; it is not a
   substitute for the specification text.

## Specification directory (`OPENSOVD_SPEC_DIR`)

The user can point `OPENSOVD_SPEC_DIR` to a directory (possibly nested) containing the
standards, e.g. markdown, text or PDF files.

1. Check it with `printenv OPENSOVD_SPEC_DIR`. If unset or empty, skip this step.
2. List its contents recursively (`ls -R "$OPENSOVD_SPEC_DIR"`, or the glob tool) and
   identify the relevant standard by file or directory name (e.g. `14229`, `13400`,
   `15765`, `UDS`, `DoIP`, `ISO-TP`).
3. Search inside the files with the grep tool (markdown/text) or the
   `pdf-reader_search_text`, `pdf-reader_get_table_of_contents` and
   `pdf-reader_get_page_text` tools (PDF). Read only the relevant sections.
   The `pdf-reader_*` tools come from an optional MCP server. If they are missing and a
   PDF must be read, load the `cda-pdf-reader-setup` skill and return its setup steps to the
   user (a restart is required); meanwhile ask for a markdown version or text excerpts.
4. Cite file path and clause/section (and page for PDFs) for every statement taken from it.

## Missing specification text

The ISO standards are not part of the repository. If neither provided text nor
`OPENSOVD_SPEC_DIR` covers the question, and when an answer depends on exact
normative wording, clause numbers, timing values, table contents or byte layouts not
covered by provided text or the docs, do not guess. Ask the user to provide either a
markdown version of the relevant specification or the relevant text parts. Name the
standard, part and topic/clause needed, e.g. "ISO 14229-2, S3 server timer handling".
Mention that they can alternatively set `OPENSOVD_SPEC_DIR` to a directory containing
the standards.
When running as a subagent, return this request to the caller instead.

## Domain knowledge

### UDS (ISO 14229-1 / -2)

- Request SID, positive response SID + 0x40, negative response `0x7F <SID> <NRC>`.
- Sub-functions and suppressPosRspMsgIndicationBit (bit 7 of the sub-function).
- Common NRCs: 0x10 generalReject, 0x11 serviceNotSupported, 0x12 subFunctionNotSupported,
  0x13 incorrectMessageLengthOrInvalidFormat, 0x21 busyRepeatRequest, 0x22
  conditionsNotCorrect, 0x24 requestSequenceError, 0x31 requestOutOfRange, 0x33
  securityAccessDenied, 0x35 invalidKey, 0x36 exceedNumberOfAttempts, 0x37
  requiredTimeDelayNotExpired, 0x78 requestCorrectlyReceived-ResponsePending,
  0x7E subFunctionNotSupportedInActiveSession, 0x7F serviceNotSupportedInActiveSession.
- Timing: P2 / P2* (extended after 0x78), S3 server session timeout, kept alive by
  TesterPresent (0x3E, typically with suppressed positive response).
- Sessions (0x10), ECU reset (0x11), security access seed/key (0x27), authentication
  (0x29), communication control (0x28), DIDs (0x22 / 0x2E), routines (0x31),
  DTCs (0x14 / 0x19 / 0x85), upload/download (0x34 / 0x35 / 0x36 / 0x37).

### DoIP (ISO 13400-2)

- Generic header: protocol version, inverse version, payload type (2 bytes), payload
  length (4 bytes).
- Payload types: vehicle identification request/response (announcement), routing
  activation request/response, alive check request/response, entity status,
  diagnostic power mode, diagnostic message (0x8001) with positive (0x8002) and
  negative (0x8003) ACK, generic header NACK.
- Routing activation response codes; diagnostic message NACK codes.
- Logical addressing: tester source address, entity/ECU target address, functional
  addresses; gateway routing to sub-ECUs.
- Transport: UDP/TCP 13400, TLS on 3496.
- Timers: T_TCP_Initial_Inactivity, T_TCP_General_Inactivity, A_DoIP_Ctrl,
  A_DoIP_Diagnostic_Message.

### CAN / ISO-TP (ISO 15765-2, ISO 11898)

- Frame types via PCI: Single Frame, First Frame, Consecutive Frame, Flow Control.
- Flow control: FS (ContinueToSend, Wait, Overflow), BS, STmin (ms and 100 µs ranges),
  N_WFTmax; SN 4-bit wrap-around.
- Timers: N_As, N_Ar, N_Bs, N_Br, N_Cs, N_Cr.
- Addressing: normal, normal fixed, extended, mixed; 11-bit and 29-bit identifiers;
  physical vs. functional (functional only with single frames).
- CAN FD: DLC mapping up to 64 bytes, SF/FF escape sequences, padding.

## CDA code map

- UDS: `cda-comm-uds`
- DoIP: `cda-comm-doip`
- CAN/ISO-TP: `cda-comm-can`
- Routing: `cda-transport-router`
- SOVD to UDS mapping: `cda-core`

Cite `file_path:line_number` and point out deviations from the specification or from
the documented requirements.

## Report

- Direct answer to the question.
- Source per statement: spec clause from provided text, doc path (with requirement or
  ADR ID if present), or "general knowledge (unverified against spec text)".
- Byte-level examples where they clarify framing or encoding.
- Deviations between CDA docs/code and the specification, if any.
- Open points, and an explicit request for missing specification text if needed.
- Never invent clause numbers, table values or requirement IDs.
