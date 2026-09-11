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

//! Validated CAN arbitration identifiers, shared by MDD extraction,
//! duplicate grouping, request serialization and the CAN transport.
//! Not feature-gated: CAN addressing is carried in every build, and
//! feature-gated types in this crate break under feature unification.

use std::fmt;

/// A CAN arbitration identifier, validated on construction: 11-bit standard
/// (`<= 0x7FF`) or 29-bit extended (`<= 0x1FFF_FFFF`, e.g. ISO 15765-4
/// normal fixed addressing such as `0x18DA10F1`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CanId {
    /// 11-bit identifier, sent in the standard frame format.
    Standard(u16),
    /// 29-bit identifier, sent in the extended frame format.
    Extended(u32),
}

/// Error for a value outside both the 11-bit and the 29-bit CAN ID range.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InvalidCanId(pub u32);

impl fmt::Display for InvalidCanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CAN ID {:#X} out of range: must be an 11-bit standard (<= 0x7FF) or 29-bit extended \
             (<= 0x1FFFFFFF) identifier",
            self.0
        )
    }
}

impl std::error::Error for InvalidCanId {}

impl CanId {
    /// The raw identifier value.
    #[must_use]
    pub fn raw(self) -> u32 {
        match self {
            Self::Standard(id) => u32::from(id),
            Self::Extended(id) => id,
        }
    }

    /// Whether this is an 11-bit standard identifier.
    #[must_use]
    pub fn is_standard(self) -> bool {
        matches!(self, Self::Standard(_))
    }
}

impl TryFrom<u32> for CanId {
    type Error = InvalidCanId;

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
            Err(InvalidCanId(id))
        }
    }
}

impl fmt::Display for CanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#05X}", self.raw())
    }
}

/// Physical CAN arbitration IDs of an ECU (request/response pair).
///
/// These always appear together: a CAN ECU is addressable only when both
/// IDs are known. The pair is resolved from the MDD com-params or from an
/// explicit `[[can.ecu_mappings]]` config entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanIds {
    /// Physical request CAN ID (tester -> ECU).
    pub request: CanId,
    /// Physical response CAN ID (ECU -> tester).
    pub response: CanId,
}

impl CanIds {
    /// Validates a raw request/response pair into a [`CanIds`].
    ///
    /// # Errors
    /// Returns the first out-of-range value as [`InvalidCanId`].
    pub fn try_from_raw(request: u32, response: u32) -> Result<Self, InvalidCanId> {
        Ok(Self {
            request: CanId::try_from(request)?,
            response: CanId::try_from(response)?,
        })
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
    fn raw_round_trips_and_classification_matches() {
        let standard = CanId::try_from(0x7E0).expect("valid standard ID");
        assert_eq!(standard.raw(), 0x7E0);
        assert!(standard.is_standard());

        let extended = CanId::try_from(0x18DA_10F1).expect("valid extended ID");
        assert_eq!(extended.raw(), 0x18DA_10F1);
        assert!(!extended.is_standard());
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

    #[test]
    fn can_ids_pair_validates_both_sides() {
        let ids = CanIds::try_from_raw(0x79B, 0x7BB).expect("valid pair");
        assert_eq!(ids.request.raw(), 0x79B);
        assert_eq!(ids.response.raw(), 0x7BB);
        assert_eq!(
            CanIds::try_from_raw(0x2000_0000, 0x7BB),
            Err(InvalidCanId(0x2000_0000))
        );
        assert_eq!(
            CanIds::try_from_raw(0x79B, u32::MAX),
            Err(InvalidCanId(u32::MAX))
        );
    }
}
