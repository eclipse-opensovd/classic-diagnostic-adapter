/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use cda_interfaces::DiagServiceError;

use crate::flatbuf::diagnostic_description::dataformat;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseType {
    Positive,
    Negative,
    GlobalNegative,
}

impl TryFrom<dataformat::ResponseType> for ResponseType {
    type Error = DiagServiceError;

    fn try_from(value: dataformat::ResponseType) -> Result<Self, Self::Error> {
        match value {
            dataformat::ResponseType::POS_RESPONSE => Ok(ResponseType::Positive),
            dataformat::ResponseType::NEG_RESPONSE => Ok(ResponseType::Negative),
            dataformat::ResponseType::GLOBAL_NEG_RESPONSE => Ok(ResponseType::GlobalNegative),
            _ => Err(DiagServiceError::InvalidDatabase(format!(
                "ResponseType {value:?} not found"
            ))),
        }
    }
}
