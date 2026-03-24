# Architecture Deviations

This document tracks architecture items (`arch~`) that are either not implemented or whose
implementation deviates from the documented architecture.

## Not Implemented

### `arch~sovd-api-authentication-modes`

- **Source**: `docs/03_architecture/02_sovd-api/02_sovd-api.rst`
- **Description**: Authentication modes endpoint (`/modes/authentication`) for managing
  authentication state via the SOVD API (SID 29h).
- **Status**: Not implemented. No `/modes/authentication` endpoint or handler exists in
  `cda-sovd/src/sovd/components/ecu/modes.rs` or elsewhere. The existing modes module
  only covers session, security, communication control, and DTC setting.

### `arch~plugin-diagnostic-database-update`

- **Source**: `docs/03_architecture/06_plugins.rst`
- **Description**: Plugin mechanism for updating diagnostic databases at runtime.
- **Status**: Not implemented. The architecture item is marked as `draft` in the RST source.
  No plugin code or update mechanism for diagnostic databases exists in the codebase.

## Implementation Deviations

### `arch~sovd-api-operations-handling` — Asynchronous Operations Not Implemented

- **File**: `cda-sovd/src/sovd/components/ecu/operations.rs`, `cda-sovd/src/sovd/mod.rs`
- **Deviation**: The architecture specifies that when a routine has subfunctions beyond
  `Start` (i.e., `Stop` and `RequestResults`), it must be treated as asynchronous:
  - `POST /operations/{routine}/executions` must return an `id` plus response data.
  - `GET /operations/{routine}/executions/{id}` must call `RequestResults`.
  - `DELETE /operations/{routine}/executions/{id}` must call `Stop`.
  - Query parameters `x-sovd2uds-suppressService` and `x-sovd2uds-force` must be supported.

  The implementation deviates in several ways:
  1. No route exists for `/operations/{service}/executions/{id}` (neither GET nor DELETE)
     — see `cda-sovd/src/sovd/mod.rs:439-448`.
  2. The GET handler (`ecu_operation_read_handler`) has a `todo:` comment and always returns
     an empty list — see `cda-sovd/src/sovd/components/ecu/operations.rs:535`.
  3. `x-sovd2uds-suppressService` and `x-sovd2uds-force` are not implemented anywhere.
  4. All operations execute synchronously; POST directly returns the ECU response with no
     `id` for subsequent retrieval.

### `arch~sovd-api-operations-handling` — Operations List Endpoint Missing

- **File**: `cda-sovd/src/sovd/mod.rs`
- **Deviation**: The architecture specifies that `/operations` must list available operations
  with attributes including `id`, `name`, `proximity_proof_required`, and
  `asynchronous_execution`. No `/operations` list route is registered — only
  `/operations/comparam/executions` and `/operations/{service}/executions` exist. The
  `proximity_proof_required` and `asynchronous_execution` attributes are not present anywhere
  in the implementation.

### `arch~sovd-api-operations-handling` — ECU Reset Parameter Handling Incomplete

- **File**: `cda-sovd/src/sovd/components/ecu/operations.rs:721`
- **Deviation**: The reset operation (`/operations/reset/executions`) works for basic cases,
  but has a `todo:` comment: "in the future we have to handle possible parameters for the
  reset service". Parameter handling for ECU reset (SID 11h) is deferred.

### `arch~sovd-api-comparams` — Timeout and Capability Not Handled

- **File**: `cda-sovd/src/sovd/components/ecu/operations.rs`
- **Deviation**: The architecture specifies that POST can take a body with `timeout`,
  `parameters`, and `proximity_response`, and that PUT on `executions/{id}` should handle
  timeout and capability. The implementation has explicit `todo:` comments at:
  - Line 133: "not in scope for now: request can take body with { timeout, parameters,
    proximity_response }"
  - Line 353: "out of scope for now: handle timeout and capability"
  - Lines 355-359: ComParam validation is commented out with "todo: validate that the
    passed in CP is actually a valid CP for the ECU"

### `arch~sovd-api-bulk-data` — DELETE Endpoints Not Implemented

- **File**: `cda-sovd/src/sovd/mod.rs:233-241`, `cda-sovd/src/sovd/apps.rs`
- **Deviation**: The architecture requires:
  - `DELETE /bulk-data/{category}` — delete all data for a category
  - `DELETE /bulk-data/{category}/{entry-id}` — delete a specific entry

  Only GET routes are registered for bulk-data endpoints. No DELETE or POST (upload) routes
  exist. The `apps.rs` module contains only `get` handlers.

### `arch~uds-tester-present` — COM Parameters Not Fully Evaluated

- **File**: `cda-comm-uds/src/lib.rs`
- **Deviation**: This is a documented known limitation in the architecture itself
  (`docs/03_architecture/03_communication/02_uds_communication.rst:528-534`). Only
  `CP_TesterPresentTime` is evaluated at runtime. The following COM parameters are loaded
  from the database but not yet used:
  - `CP_TesterPresentReqResp`
  - `CP_TesterPresentSendType`
  - `CP_TesterPresentMessage`
  - `CP_TesterPresentExpPosResp`
  - `CP_TesterPresentExpNegResp`

  The implementation hardcodes the message as `[0x3E, 0x80]`, uses fixed periodic sending,
  and always generates tester present when a lock is held.

### `arch~doip-vehicle-identification`

- **File**: `cda-comm-doip/src/vir_vam.rs`
- **Deviation**: The VAM (Vehicle Announcement Message) response timeout is hardcoded to
  1 second. The ISO 13400 specification defines configurable timeouts (A_DoIP_Ctrl) which
  are not sourced from COM parameters or configuration.

### `arch~doip-alive-check`

- **File**: `cda-comm-doip/src/connections.rs`
- **Deviation**: The alive check response timeout is hardcoded to `Duration::from_secs(1)`
  (line ~751). Per the DoIP specification, this timeout should be configurable via
  communication parameters (`T_TCP_General_Inactivity` / `T_TCP_Alive_Check`).

### `arch~doip-diagnostic-message`

- **File**: `cda-comm-doip/src/lib.rs`
- **Deviation**: Generic NACK handling is incomplete. There is a TODO comment (#22) indicating
  that proper handling of DoIP generic negative acknowledgement codes is not yet fully
  implemented.

### `arch~doip-tls`

- **File**: `cda-comm-doip/src/ecu_connection.rs`
- **Deviation**: TLS certificate verification is disabled (`SslVerifyMode::NONE`). The
  implementation establishes TLS connections but does not verify the server certificate,
  which deviates from production-grade TLS requirements.

### `arch~doip-error-handling`

- **File**: `cda-comm-doip/src/lib.rs`, `cda-comm-doip/src/connections.rs`
- **Deviation**: Two issues:
  1. Generic NACK handling is incomplete (same as `doip-diagnostic-message`, TODO #22).
  2. Multiple distinct DoIP error conditions (e.g., transport protocol errors, invalid
     header) are collapsed into a single `ConnectionClosed` error variant, losing
     diagnostic granularity.
