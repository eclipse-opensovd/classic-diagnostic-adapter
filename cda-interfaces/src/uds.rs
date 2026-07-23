/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! UDS (Unified Diagnostic Services) protocol constants and helpers.
//!
//! Groups the ISO 14229-1 identifiers and transport-level NRC classification
//! that both the CAN and `DoIP` gateways need.

use crate::ServicePayload;

/// Pending-lifecycle NRC variants that signal the transport must keep its
/// connection/socket open for a follow-up response.
///
/// The transport layer classifies raw bytes into these variants via
/// [`crate::pending_nrc_from_raw`] and performs its own side effects
/// (deadline extension, socket keep-alive) before forwarding to the UDS layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingNrc {
    /// NRC 0x78 -- ECU needs more time, final response will follow.
    ResponsePending { source_address: u16 },
    /// NRC 0x21 -- ECU busy, client should retransmit.
    BusyRepeatRequest { source_address: u16 },
    /// NRC 0x94 -- Resource temporarily unavailable, retransmit.
    TemporarilyNotAvailable { source_address: u16 },
}

/// Response already classified by the transport, with transport-level
/// side effects (deadline extension, socket keep-alive) already applied.
///
/// The transport guarantees:
/// - For [`TransportResponse::Pending`]: the underlying connection/socket
///   remains open and any transport-specific timers have been extended.
/// - For [`TransportResponse::UdsResponse`]: the exchange is complete from the
///   transport's perspective. The payload is the raw UDS response bytes
///   (positive or negative response).
#[derive(Debug, Clone)]
pub enum TransportResponse {
    /// A pending-lifecycle NRC. The transport has already extended its own
    /// deadline / kept its socket open. The UDS layer decides retry policy.
    Pending(PendingNrc),
    /// A terminal response. The payload contains the raw UDS response bytes --
    /// either a positive response or a negative response with an NRC other
    /// than the three pending-lifecycle codes.
    UdsResponse(ServicePayload),
}

/// UDS Service Identifiers (SIDs) from ISO 14229-1.
pub mod service_ids {
    pub const SESSION_CONTROL: u8 = 0x10;
    pub const ECU_RESET: u8 = 0x11;
    pub const CLEAR_DIAGNOSTIC_INFORMATION: u8 = 0x14;
    pub const READ_DTC_INFORMATION: u8 = 0x19;
    /// KWP2000 `ReadDataByLocalIdentifier` (legacy, used by some older ECUs
    /// that are not fully UDS-compliant)
    pub const READ_DATA_BY_LOCAL_IDENTIFIER: u8 = 0x21;
    pub const READ_DATA_BY_IDENTIFIER: u8 = 0x22;
    pub const SECURITY_ACCESS: u8 = 0x27;
    pub const COMMUNICATION_CONTROL: u8 = 0x28;
    pub const AUTHENTICATION: u8 = 0x29;
    pub const WRITE_DATA_BY_IDENTIFIER: u8 = 0x2E;
    pub const INPUT_OUTPUT_CONTROL_BY_IDENTIFIER: u8 = 0x2F;
    pub const ROUTINE_CONTROL: u8 = 0x31;
    pub const REQUEST_DOWNLOAD: u8 = 0x34;
    pub const TRANSFER_DATA: u8 = 0x36;
    pub const REQUEST_TRANSFER_EXIT: u8 = 0x37;
    pub const TESTER_PRESENT: u8 = 0x3E;
    pub const CONTROL_DTC_SETTING: u8 = 0x85;
    /// The first byte of every UDS negative response frame.
    pub const NEGATIVE_RESPONSE: u8 = 0x7F;
}

/// UDS Sub-function identifiers.
pub mod subfunction_ids {
    pub mod routine {
        pub const START: u8 = 0x01;
        pub const STOP: u8 = 0x02;
        pub const REQUEST_RESULTS: u8 = 0x03;
    }
}

/// Negative Response Codes (NRC) from ISO 14229-1 Table A.1 that require
/// special gateway-level handling. All other NRCs are forwarded as final
/// [`UdsResponse::Message`] frames.
pub mod nrc {
    /// NRC 0x21 - `busyRepeatRequest`.
    ///
    /// The server is temporarily too busy; the client shall repeat the
    /// identical request after a short delay.
    /// (ISO 14229-1:2020 Table A.1)
    pub const BUSY_REPEAT_REQUEST: u8 = 0x21;

    /// NRC 0x78 - `requestCorrectlyReceived-ResponsePending`.
    ///
    /// The request was valid but the server needs more time; a final response
    /// will arrive on the same session. The client shall extend its timeout.
    /// (ISO 14229-1:2020 Table A.1)
    pub const RESPONSE_PENDING: u8 = 0x78;

    /// NRC 0x94 - vehicle-manufacturer-specific temporarily not available.
    ///
    /// Used by some ECUs to signal temporary unavailability; treated at the
    /// transport layer the same as `busyRepeatRequest`.
    pub const TEMPORARILY_NOT_AVAILABLE: u8 = 0x94;
}

/// The response-bit mask applied to a request SID to produce the positive
/// response SID (ISO 14229-1: positive response = request SID | 0x40).
pub const UDS_ID_RESPONSE_BITMASK: u8 = 0x40;

/// Suppress-positive-response bit (bit 7) of the UDS sub-function byte.
/// When set, the ECU shall not send a positive response message
/// (ISO 14229-1).
pub const SUPPRESS_POSITIVE_RESPONSE_BIT: u8 = 0x80;

/// Default bitmask applied to sub-function IDs during service lookups.
/// Masks out the suppress-positive-response bit so that `0x01` and `0x81`
/// both match sub-function ID `0x01`.
pub const DEFAULT_SUBFUNCTION_MASK: u8 = 0x7F;

pub(crate) const CONFIGURATIONS_PREFIXES: [u8; 1] = [service_ids::WRITE_DATA_BY_IDENTIFIER];

pub(crate) const DATA_PREFIXES: [u8; 2] = [
    service_ids::READ_DATA_BY_LOCAL_IDENTIFIER,
    service_ids::READ_DATA_BY_IDENTIFIER,
];

pub(crate) const FAULTS_PREFIXES: [u8; 2] = [
    service_ids::CLEAR_DIAGNOSTIC_INFORMATION,
    service_ids::READ_DTC_INFORMATION,
];

pub(crate) const MODES_PREFIXES: [u8; 6] = [
    service_ids::SESSION_CONTROL,
    service_ids::ECU_RESET,
    service_ids::SECURITY_ACCESS,
    service_ids::COMMUNICATION_CONTROL,
    service_ids::AUTHENTICATION,
    service_ids::CONTROL_DTC_SETTING,
];

pub(crate) const OPERATIONS_PREFIXES: [u8; 5] = [
    service_ids::INPUT_OUTPUT_CONTROL_BY_IDENTIFIER,
    service_ids::ROUTINE_CONTROL,
    service_ids::REQUEST_DOWNLOAD,
    service_ids::TRANSFER_DATA,
    service_ids::REQUEST_TRANSFER_EXIT,
];

pub const SERVICE_IDS_PARAMETER_META_DATA: [u8; 3] = [
    service_ids::READ_DATA_BY_IDENTIFIER,
    service_ids::WRITE_DATA_BY_IDENTIFIER,
    service_ids::ROUTINE_CONTROL,
];

/// Returns `true` when `data` begins with the UDS negative-response byte
/// (`0x7F`), indicating a negative response frame.
///
/// Both gateways use this to gate NRC classification before reading the
/// NRC byte at position 2.
#[must_use]
pub fn is_negative_response(data: &[u8]) -> bool {
    data.first() == Some(&service_ids::NEGATIVE_RESPONSE)
}

/// Returns `true` when `data` is a `TesterPresent` negative response (`7F 3E xx`).
///
/// `TesterPresent` NRCs arrive on the shared TCP connection from the functional
/// broadcast keep-alive. They carry a real ECU source address but are unrelated
/// to any pending physical request and must be intercepted before general
/// NRC classification so they can be routed as a dedicated event.
#[must_use]
pub fn is_tester_present_nrc(data: &[u8]) -> bool {
    is_negative_response(data) && data.get(1) == Some(&service_ids::TESTER_PRESENT)
}

/// Returns `true` when the raw response data is one of the three pending-lifecycle
/// NRCs (0x78 / 0x21 / 0x94).
///
/// Transports that must keep a connection/socket open for a follow-up response
/// (e.g. CAN ISO-TP) use this predicate to extend their deadline.
/// Classification into typed variants is done via [`pending_nrc_from_raw`].
#[must_use]
pub fn is_pending_nrc(data: &[u8]) -> bool {
    is_negative_response(data)
        && data.len() >= 3
        && matches!(
            data.get(2).copied(),
            Some(nrc::RESPONSE_PENDING | nrc::BUSY_REPEAT_REQUEST | nrc::TEMPORARILY_NOT_AVAILABLE)
        )
}

/// Classifies raw UDS response bytes into a [`PendingNrc`] variant.
///
/// Returns `Some` when the data is a pending-lifecycle NRC (0x78 / 0x21 / 0x94),
/// `None` otherwise. Both CAN and `DoIP` transports use this single shared function
/// so their classification behaviour is identical by construction.
#[must_use]
pub fn pending_nrc_from_raw(data: &[u8], source_address: u16) -> Option<PendingNrc> {
    if !is_pending_nrc(data) {
        return None;
    }
    #[allow(
        clippy::indexing_slicing,
        reason = "is_pending_nrc guarantees len >= 3"
    )]
    Some(match data[2] {
        nrc::RESPONSE_PENDING => PendingNrc::ResponsePending { source_address },
        nrc::BUSY_REPEAT_REQUEST => PendingNrc::BusyRepeatRequest { source_address },
        nrc::TEMPORARILY_NOT_AVAILABLE => PendingNrc::TemporarilyNotAvailable { source_address },
        _ => return None, // defensive -- is_pending_nrc already excludes this
    })
}

/// Wraps raw UDS response bytes into a [`ServicePayload`] for use as a final
/// transport response.
///
/// This is the counterpart to [`pending_nrc_from_raw`]. Call this only after
/// confirming the data is NOT a pending NRC (i.e. `pending_nrc_from_raw` returned
/// `None`). Both CAN and `DoIP` transports use this single shared function so their
/// classification behaviour is identical by construction.
///
/// All NRC interpretation above the transport boundary (e.g. session-level
/// `TesterPresent` NRCs) is the responsibility of the UDS layer, not the transport.
#[must_use]
pub fn uds_response_from_raw(
    data: Vec<u8>,
    source_address: u16,
    target_address: u16,
) -> ServicePayload {
    ServicePayload {
        data,
        source_address,
        target_address,
        new_session: None,
        new_security: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_ADDRESS: u16 = 0x1001;
    const TARGET_ADDRESS: u16 = 0x0E00;

    #[test]
    fn uds_final_from_raw_preserves_data_and_addresses() {
        let data = vec![service_ids::NEGATIVE_RESPONSE, 0x10, 0x22];
        let payload = uds_response_from_raw(data.clone(), SOURCE_ADDRESS, TARGET_ADDRESS);
        assert_eq!(payload.data, data);
        assert_eq!(payload.source_address, SOURCE_ADDRESS);
        assert_eq!(payload.target_address, TARGET_ADDRESS);
    }

    #[test]
    fn uds_final_from_raw_passes_tester_present_nrc_through_as_payload() {
        // TesterPresent NRCs (7F 3E xx) are no longer intercepted at the transport
        // boundary -- they are absorbed by the DoIP receiver before broadcast, and
        // discarded by the CAN SID filter. uds_final_from_raw treats them like any
        // other negative response: raw bytes in a ServicePayload.
        let data = vec![
            service_ids::NEGATIVE_RESPONSE,
            service_ids::TESTER_PRESENT,
            0x12,
        ];
        let payload = uds_response_from_raw(data.clone(), SOURCE_ADDRESS, TARGET_ADDRESS);
        assert_eq!(payload.data, data);
    }

    #[test]
    fn pending_nrc_0x78_classified_correctly() {
        let data = vec![
            service_ids::NEGATIVE_RESPONSE,
            service_ids::TESTER_PRESENT,
            nrc::RESPONSE_PENDING,
        ];
        let pending = pending_nrc_from_raw(&data, SOURCE_ADDRESS);
        assert_eq!(
            pending,
            Some(PendingNrc::ResponsePending {
                source_address: SOURCE_ADDRESS
            })
        );
    }

    #[test]
    fn pending_nrc_0x21_classified_correctly() {
        let data = vec![
            service_ids::NEGATIVE_RESPONSE,
            0x10, // SessionControl
            nrc::BUSY_REPEAT_REQUEST,
        ];
        let pending = pending_nrc_from_raw(&data, SOURCE_ADDRESS);
        assert_eq!(
            pending,
            Some(PendingNrc::BusyRepeatRequest {
                source_address: SOURCE_ADDRESS
            })
        );
    }

    #[test]
    fn pending_nrc_0x94_classified_correctly() {
        let data = vec![
            service_ids::NEGATIVE_RESPONSE,
            0x22, // ReadDataByIdentifier
            nrc::TEMPORARILY_NOT_AVAILABLE,
        ];
        let pending = pending_nrc_from_raw(&data, SOURCE_ADDRESS);
        assert_eq!(
            pending,
            Some(PendingNrc::TemporarilyNotAvailable {
                source_address: SOURCE_ADDRESS
            })
        );
    }

    #[test]
    fn non_pending_nrc_returns_none() {
        let data = vec![
            service_ids::NEGATIVE_RESPONSE,
            0x10,
            0x22, // conditionsNotCorrect
        ];
        assert!(pending_nrc_from_raw(&data, SOURCE_ADDRESS).is_none());
    }
}
