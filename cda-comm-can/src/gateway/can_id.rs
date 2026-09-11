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

//! Socket-side conversion for [`CanId`]: only the mapping onto the
//! ISO-TP library's typed identifiers is transport-specific, so it lives
//! behind the feature gate while the type itself is in `cda_interfaces`.

use cda_interfaces::CanId;
use tokio_socketcan_isotp::{ExtendedId, Id, StandardId};

use super::error::CanError;

/// Conversion of a validated [`CanId`] into the ISO-TP socket identifier.
pub(crate) trait CanIdExt {
    /// Converts into the typed socket identifier of the ISO-TP library.
    ///
    /// # Errors
    /// Unreachable after `TryFrom` validation; mapped instead of unwrapped
    /// to keep the conversion total.
    fn to_socket_id(self) -> Result<Id, CanError>;
}

impl CanIdExt for CanId {
    fn to_socket_id(self) -> Result<Id, CanError> {
        match self {
            Self::Standard(id) => StandardId::new(id).map(Id::Standard),
            Self::Extended(id) => ExtendedId::new(id).map(Id::Extended),
        }
        .ok_or_else(|| CanError::InvalidId(format!("invalid CAN ID {self}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_ids_match_the_id_kind() {
        let standard = CanId::try_from(0x7E0).expect("valid standard ID");
        assert!(matches!(standard.to_socket_id(), Ok(Id::Standard(_))));

        let extended = CanId::try_from(0x18DA_10F1).expect("valid extended ID");
        assert!(matches!(extended.to_socket_id(), Ok(Id::Extended(_))));
    }
}
