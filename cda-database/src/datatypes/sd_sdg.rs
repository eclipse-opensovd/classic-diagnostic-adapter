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

use cda_interfaces::{STRINGS, StringId};
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;

use crate::{
    datatypes::{Id, SdMap, SdgMap, option_str_to_string},
    proto::dataformat::{EcuData, sd, sd_or_sdg, sdg},
};

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct Sd {
    pub value: Option<StringId>,
    pub si: Option<StringId>,
    pub ti: Option<StringId>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct Sdg {
    pub caption: Option<StringId>,
    pub si: Option<StringId>,
    pub sdgs: Vec<SdOrSdgRef>,
}
#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum SdOrSdgRef {
    Sd(Id),
    Sdg(Id),
}

#[tracing::instrument(
    skip(ecu_data, ids),
    fields(
        ecu_db_path = %_ecu_db_path,
        sdg_count = ecu_data.sdgs.len(),
        id_count = ids.len()
    )
)]
pub(super) fn get_sdgs(ecu_data: &EcuData, _ecu_db_path: &str, ids: &[Id]) -> SdgMap {
    ecu_data
        .sdgs
        .iter()
        .filter_map(|sdg| {
            sdg.id.as_ref().and_then(|id| {
                if !ids.is_empty() && !ids.contains(&id.value) {
                    return None;
                }
                Some((
                    id.value,
                    Sdg {
                        caption: sdg
                            .caption
                            .as_ref()
                            .map(|cap| STRINGS.get_or_insert(&cap.short_name)),
                        si: option_str_to_string(sdg.si.as_ref()),
                        sdgs: sdg
                            .sds
                            .iter()
                            .filter_map(|sd_or_sdg| match &sd_or_sdg.s_dxor_sdg {
                                Some(sd_or_sdg::SDxorSdg::Sd(sd::Ref { r#ref: Some(id) })) => {
                                    Some(SdOrSdgRef::Sd(id.value))
                                }
                                Some(sd_or_sdg::SDxorSdg::Sdg(sdg::Ref { r#ref: Some(id) })) => {
                                    Some(SdOrSdgRef::Sdg(id.value))
                                }
                                _ => {
                                    tracing::warn!("SDOrSDG has no value");
                                    None
                                }
                            })
                            .collect(),
                    },
                ))
            })
        })
        .collect()
}

#[tracing::instrument(skip(ecu_data), fields(sd_count = ecu_data.sds.len()))]
pub(super) fn get_sds(ecu_data: &EcuData) -> SdMap {
    ecu_data
        .sds
        .iter()
        .filter_map(|sd| {
            sd.id.as_ref().map(|id| {
                (
                    id.value,
                    Sd {
                        value: option_str_to_string(sd.value.as_ref()),
                        si: option_str_to_string(sd.si.as_ref()),
                        ti: option_str_to_string(sd.ti.as_ref()),
                    },
                )
            })
        })
        .collect()
}
