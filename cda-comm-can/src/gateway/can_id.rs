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

//! A validated CAN arbitration identifier.
//!
//! Range validation, the standard/extended classification and the display
//! convention live here so they cannot drift between config validation,
//! socket setup and logging. Config and com-param surfaces still carry raw
//! `u32` values; converting them into [`CanId`] at the gateway boundary is
//! the single place invalid identifiers are rejected.

use std::fmt;

use tokio_socketcan_isotp::{ExtendedId, Id, StandardId};

use super::error::CanError;

/// A CAN arbitration identifier, validated on construction: 11-bit standard
/// (`<= 0x7FF`) or 29-bit extended (`<= 0x1FFF_FFFF`, e.g. ISO 15765-4
/// normal fixed addressing such as `0x18DA10F1`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum CanId {
    /// 11-bit identifier, sent in the standard frame format.
    Standard(u16),
    /// 29-bit identifier, sent in the extended frame format.
    Extended(u32),
}

impl CanId {
    /// The raw identifier value.
    pub(crate) fn raw(self) -> u32 {
        match self {
            Self::Standard(id) => u32::from(id),
            Self::Extended(id) => id,
        }
    }

    /// Whether this is an 11-bit standard identifier.
    pub(crate) fn is_standard(self) -> bool {
        matches!(self, Self::Standard(_))
    }

    /// Converts into the typed socket identifier of the ISO-TP library.
    pub(crate) fn to_socket_id(self) -> Result<Id, CanError> {
        match self {
            Self::Standard(id) => StandardId::new(id).map(Id::Standard),
            Self::Extended(id) => ExtendedId::new(id).map(Id::Extended),
        }
        // Unreachable after TryFrom validation; mapped instead of unwrapped
        // to keep the conversion total.
        .ok_or_else(|| CanError::InvalidId(format!("invalid CAN ID {self}")))
    }
}

impl TryFrom<u32> for CanId {
    type Error = CanError;

    fn try_from(id: u32) -> Result<Self, Self::Error> {
        if id <= 0x7FF {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "the range check makes the cast lossless"
            )]
            Ok(Self::Standard(id as u16))
        } else if id <= 0x1FFF_FFFF {
            Ok(Self::Extended(id))
        } else {
            Err(CanError::InvalidId(format!(
                "CAN ID 0x{id:X} out of range: must be an 11-bit standard (<= 0x7FF) or 29-bit \
                 extended (<= 0x1FFFFFFF) identifier"
            )))
        }
    }
}

impl fmt::Display for CanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:03X}", self.raw())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_dispatches_standard_and_extended() {
        // 11-bit range -> standard frame format
        assert!(matches!(CanId::try_from(0x000), Ok(CanId::Standard(_))));
        assert!(matches!(CanId::try_from(0x7E0), Ok(CanId::Standard(_))));
        assert!(matches!(CanId::try_from(0x7FF), Ok(CanId::Standard(_))));
        // 29-bit range -> extended frame format (ISO 15765-4 normal fixed
        // addressing lives here, e.g. 0x18DA10F1 physical / 0x18DB33F1
        // functional)
        assert!(matches!(CanId::try_from(0x800), Ok(CanId::Extended(_))));
        assert!(matches!(
            CanId::try_from(0x18DA_10F1),
            Ok(CanId::Extended(_))
        ));
        assert!(matches!(
            CanId::try_from(0x1FFF_FFFF),
            Ok(CanId::Extended(_))
        ));
        // beyond 29 bits -> error
        assert!(CanId::try_from(0x2000_0000).is_err());
        assert!(CanId::try_from(u32::MAX).is_err());
    }

    #[test]
    fn raw_round_trips_and_socket_ids_match_kind() {
        let standard = CanId::try_from(0x7E0).expect("valid standard ID");
        assert_eq!(standard.raw(), 0x7E0);
        assert!(standard.is_standard());
        assert!(matches!(standard.to_socket_id(), Ok(Id::Standard(_))));

        let extended = CanId::try_from(0x18DA_10F1).expect("valid extended ID");
        assert_eq!(extended.raw(), 0x18DA_10F1);
        assert!(!extended.is_standard());
        assert!(matches!(extended.to_socket_id(), Ok(Id::Extended(_))));
    }

    #[test]
    fn display_uses_the_log_convention() {
        assert_eq!(
            CanId::try_from(0x7E0).expect("valid ID").to_string(),
            "0x7E0"
        );
        assert_eq!(CanId::try_from(0x1).expect("valid ID").to_string(), "0x001");
        assert_eq!(
            CanId::try_from(0x18DA_10F1).expect("valid ID").to_string(),
            "0x18DA10F1"
        );
    }
}
