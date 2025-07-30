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
use cda_interfaces::{DiagServiceError, STRINGS, diagservices::DiagServiceResponse};
use hashbrown::{HashMap, HashSet};

#[derive(Debug)]
pub(super) struct ExpectedParamValue {
    pub expected_value: String,
    pub parameter: String,
}
pub(super) type DiagServiceId = String;

pub(super) type ExpectedParamMap = HashMap<DiagServiceId, Vec<ExpectedParamValue>>;
pub(super) type VariantPatterns = Vec<ExpectedParamMap>;

pub(super) struct VariantDetection {
    pub(crate) diag_service_requests: HashSet<DiagServiceId>,
    pub(crate) variant_param_map: HashMap<u32, VariantPatterns>,
}

pub(super) fn prepare_variant_detection(
    diagnostic_database: &datatypes::DiagnosticDatabase,
) -> Result<VariantDetection, DiagServiceError> {
    let mut diag_service_requests = HashSet::new();
    let mut variant_param_map: HashMap<u32, VariantPatterns> = HashMap::new();
    for (id, v) in &diagnostic_database.variants {
        if v.is_base {
            continue;
        }

        let mut patterns = Vec::new();
        for p in &v.pattern {
            let mut expected_param_map: ExpectedParamMap = HashMap::new();
            for mp in &p.matching_parameters {
                let diag_service_id = diagnostic_database
                    .services
                    .get(&mp.service_id)
                    .and_then(|s| STRINGS.get(s.short_name))
                    .ok_or_else(|| {
                        DiagServiceError::InvalidDatabase("DiagService not found".to_owned())
                    })?;
                let expected_value = STRINGS.get(mp.expected_value).ok_or_else(|| {
                    DiagServiceError::InvalidDatabase("Expected value not found".to_owned())
                })?;
                let parameter = diagnostic_database
                    .params
                    .get(&mp.param_id)
                    .and_then(|p| STRINGS.get(p.short_name))
                    .ok_or_else(|| {
                        DiagServiceError::InvalidDatabase("Parameter not found".to_owned())
                    })?;

                let expected_param_value = ExpectedParamValue {
                    expected_value,
                    parameter,
                };
                diag_service_requests.insert(diag_service_id.clone());
                expected_param_map
                    .entry(diag_service_id)
                    .or_insert(Vec::new())
                    .push(expected_param_value);
            }
            patterns.push(expected_param_map);
        }
        variant_param_map.insert(*id, patterns);
    }

    Ok(VariantDetection {
        diag_service_requests,
        variant_param_map,
    })
}

impl VariantDetection {
    pub(super) fn evaluate_variant<T: DiagServiceResponse + Sized>(
        &self,
        service_responses: HashMap<String, T>,
    ) -> Result<u32, DiagServiceError> {
        let service_responses = service_responses
            .into_iter()
            .map(|(service, res)| {
                let json = res.into_json()?;
                let params = json
                    .as_object()
                    .ok_or_else(|| {
                        DiagServiceError::ParameterConversionError(
                            "Expected JSON object".to_owned(),
                        )
                    })?
                    .into_iter()
                    .map(|(name, value)| {
                        (
                            name.clone(),
                            value.to_string().replace('"', ""), // remove quotes
                        )
                    })
                    .collect::<HashMap<String, String>>();
                Ok((service, params))
            })
            .collect::<Result<HashMap<String, HashMap<String, String>>, DiagServiceError>>()?;

        self.variant_param_map
            .iter()
            .find(|(_, patterns)| {
                patterns.iter().any(|expected_services| {
                    expected_services.iter().all(|(service, expected_params)| {
                        expected_params.iter().all(|expected_param| {
                            service_responses
                                .get(service)
                                .and_then(|params| {
                                    params
                                        .iter()
                                        .find(|(name, _)| **name == expected_param.parameter)
                                        .map(|(_name, value)| {
                                            value.replace('"', "") == expected_param.expected_value
                                        })
                                })
                                .unwrap_or(false)
                        })
                    })
                })
            })
            .map(|(id, _)| *id)
            .ok_or_else(|| {
                log::debug!(
                    target: "variant_detection",
                    "No variant found for expected services: {:#?}
                    Received: {service_responses:#?}",
                    self.variant_param_map
                );
                DiagServiceError::VariantDetectionError("No variant found".to_owned())
            })
    }
}
