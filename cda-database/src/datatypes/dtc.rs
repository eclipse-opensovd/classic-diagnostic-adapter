/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use cda_interfaces::{DiagServiceError, StringId};
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;

use crate::{
    datatypes::{DtcMap, option_str_to_string, ref_optional_none},
    proto::dataformat::EcuData,
};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct Dtc {
    pub code: u32,
    pub display_code: Option<StringId>,
    pub fault_name: Option<StringId>,
    pub severity: u32,
}

pub(super) fn get_dtcs(ecu_data: &EcuData, ecu_db_path: &str) -> DtcMap {
    ecu_data
        .dtcs
        .iter()
        .filter(|d| !d.is_temporary())
        .map(|d| {
            Ok((
                d.id.as_ref()
                    .ok_or_else(|| ref_optional_none("DTC.id"))?
                    .value,
                Dtc {
                    code: d.trouble_code,
                    display_code: option_str_to_string(d.display_trouble_code.as_ref()),
                    fault_name: d
                        .text
                        .as_ref()
                        .and_then(|t| option_str_to_string(t.value.as_ref())),
                    severity: d.level(),
                },
            ))
        })
        .filter_map(|res: Result<(u32, Dtc), DiagServiceError>| match res {
            Ok((id, param)) => Some((id, param)),
            Err(e) => {
                tracing::error!(error = %e, ecu_db_path = %ecu_db_path, "Error processing dtc");
                None
            }
        })
        .collect::<DtcMap>()
}
