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

use cda_interfaces::{DiagCommAction, DiagCommType};
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;
use hashbrown::HashMap;

use crate::{
    datatypes::{DbDiagComm, DiagnosticServiceMap},
    proto::dataformat::EcuData,
};

pub type FunctionalClassesLookupMap = HashMap<String, FunctClassesServiceMap>;

pub type FunctionalClassesMap = HashMap<u32, String>;

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct FunctClassesServiceMap {
    pub services: HashMap<u32, DbDiagComm>,
}

pub fn get_functional_classes_lookup(
    ecu_data: &EcuData,
    services: &DiagnosticServiceMap,
) -> FunctionalClassesLookupMap {
    ecu_data
        .funct_classes
        .iter()
        .map(|class| {
            let services: HashMap<u32, DbDiagComm> = ecu_data
                .diag_services
                .iter()
                .filter_map(|service| {
                    service
                        .diag_comm
                        .iter()
                        .find(|dc| dc.funct_class.is_some_and(|fc| fc.r#ref == class.id))
                        .and_then(|_| {
                            let s = services.get(&service.id.as_ref()?.value)?;
                            Some((
                                u32::from(s.service_id),
                                DbDiagComm {
                                    action: DiagCommAction::Start,
                                    type_: DiagCommType::Operations,
                                    lookup_name: s.short_name,
                                },
                            ))
                        })
                })
                .filter_map(Option::from)
                .collect();

            (
                class.short_name.to_lowercase(),
                FunctClassesServiceMap { services },
            )
        })
        .collect()
}
