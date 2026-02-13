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
use crate::flatbuf::diagnostic_description::dataformat;

impl From<dataformat::DTC<'_>> for cda_interfaces::datatypes::DtcRecord {
    fn from(val: dataformat::DTC<'_>) -> Self {
        cda_interfaces::datatypes::DtcRecord {
            code: val.trouble_code(),
            display_code: val.display_trouble_code().map(ToOwned::to_owned),
            fault_name: val.short_name().map_or_else(
                || format!("DTC_{}", val.trouble_code()),
                std::borrow::ToOwned::to_owned,
            ),
            severity: val.level().unwrap_or_default().to_owned(),
        }
    }
}
