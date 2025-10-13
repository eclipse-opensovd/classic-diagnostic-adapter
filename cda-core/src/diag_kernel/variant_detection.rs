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

use cda_database::datatypes;
use cda_interfaces::{DiagServiceError, diagservices::DiagServiceResponse};
use hashbrown::{HashMap, HashSet};

pub(super) type DiagServiceId = String;

pub(super) struct VariantDetection {
    pub(crate) diag_service_requests: HashSet<DiagServiceId>,
}

pub(super) fn prepare_variant_detection(
    diagnostic_database: &datatypes::DiagnosticDatabase,
) -> Result<VariantDetection, DiagServiceError> {
    let diag_service_requests: HashSet<_> = diagnostic_database
        .ecu_data()?
        .variants()
        .map(|variants| {
            variants
                .iter()
                .filter(|v| !v.is_base_variant())
                .flat_map(|v| {
                    v.variant_pattern().into_iter().flat_map(|patterns| {
                        patterns.iter().flat_map(|pattern| {
                            pattern.matching_parameter().into_iter().flat_map(|params| {
                                params.iter().filter_map(|mp| {
                                    mp.diag_service()
                                        .and_then(|ds| ds.diag_comm())
                                        .and_then(|dc| dc.short_name())
                                        .map(|name| name.to_owned())
                                })
                            })
                        })
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(VariantDetection {
        diag_service_requests,
    })
}

impl VariantDetection {
    // Note: It's extremely important to skip the diagnostic_database
    // otherwise the tracing macro will try to get the debug representation of it
    // which _will_ take several seconds (up to 60s for large DBs)
    #[tracing::instrument(
        skip(self, service_responses, diagnostic_database),
        fields(response_count = service_responses.len())
    )]
    pub(super) fn evaluate_variant<'a, T: DiagServiceResponse + Sized>(
        &self,
        service_responses: HashMap<String, T>,
        diagnostic_database: &'a datatypes::DiagnosticDatabase,
    ) -> Result<datatypes::Variant<'a>, DiagServiceError> {
        let service_responses = service_responses
            .into_iter()
            .map(|(service, res)| {
                let json = res.into_json()?;
                let params = json
                    .data
                    .as_object()
                    .ok_or_else(|| {
                        DiagServiceError::ParameterConversionError(
                            "Expected JSON object".to_owned(),
                        )
                    })?
                    .into_iter()
                    .map(|(name, value)| (name.clone(), value.to_string().replace('"', "")))
                    .collect::<HashMap<String, String>>();
                Ok((service, params))
            })
            .collect::<Result<HashMap<String, HashMap<String, String>>, DiagServiceError>>()?;

        let variants = diagnostic_database.ecu_data()?.variants().ok_or_else(|| {
            DiagServiceError::InvalidDatabase(format!(
                "ECU {:?} has no variants!",
                diagnostic_database
                    .ecu_data()
                    .ok()
                    .and_then(|ecu| ecu.ecu_name())
            ))
        })?;

        variants
            .iter()
            .find(|variant| {
                variant
                    .variant_pattern()
                    .map(|patterns| {
                        patterns.iter().any(|pattern| {
                            pattern
                                .matching_parameter()
                                .map(|params| {
                                    params.iter().all(|matching_param| {
                                        let expected_value =
                                            matching_param.expected_value().unwrap_or_default();
                                        let expected_param = matching_param
                                            .out_param()
                                            .and_then(|out_param| out_param.short_name())
                                            .unwrap_or_default();
                                        let service = matching_param
                                            .diag_service()
                                            .and_then(|ds| ds.diag_comm())
                                            .and_then(|dc| dc.short_name())
                                            .unwrap_or_default();

                                        service_responses
                                            .get(service)
                                            .and_then(|params| {
                                                params
                                                    .iter()
                                                    .find(|(name, _)| **name == expected_param)
                                                    .map(|(_name, value)| {
                                                        value.replace('"', "") == expected_value
                                                    })
                                            })
                                            .unwrap_or(false)
                                    })
                                })
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
            })
            .or(variants.iter().find(|variant| variant.is_base_variant()))
            .map(datatypes::Variant)
            .ok_or_else(move || {
                tracing::debug!(
                    received_responses = ?service_responses,
                    "No variant found for expected services"
                );
                DiagServiceError::VariantDetectionError("No variant found".to_owned())
            })
    }
}
