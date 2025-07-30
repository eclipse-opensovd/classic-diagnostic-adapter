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

use cda_interfaces::{DiagServiceError, STRINGS, StringId};
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;
use hashbrown::HashMap;

use crate::{
    datatypes::{
        ComParamRef, DiagnosticServiceMap, Id, SingleEcuJobMap, StateChartMap, VariantMap,
        map_comparam_ref, ref_optional_none,
    },
    proto::dataformat::{self, EcuData},
};

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct Variant {
    pub short_name: String,
    pub pattern: Vec<VariantPattern>,
    pub services: Vec<Id>,
    pub service_lookup: HashMap<String, Id>,
    pub com_params: Vec<ComParamRef>,
    pub is_base: bool,
    pub sdgs: Vec<Id>,
    pub single_ecu_jobs: Vec<Id>,
    pub single_ecu_job_lookup: HashMap<String, Id>,
    pub state_charts: Vec<Id>,
    pub state_charts_lookup: HashMap<String, Id>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct VariantPattern {
    pub matching_parameters: Vec<MatchingParameter>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct MatchingParameter {
    pub expected_value: StringId,
    pub service_id: Id,
    pub param_id: Id,
}

pub(super) fn create_variant_map(
    ecu_data: &EcuData,
    services: &DiagnosticServiceMap,
    single_ecu_jobs: &SingleEcuJobMap,
    state_charts: &StateChartMap,
) -> Result<(VariantMap, u32), DiagServiceError> {
    let mut base_variant_id: u32 = 0;
    let variants = ecu_data
        .variants
        .iter()
        .map(|v| {
            if v.is_base_variant {
                base_variant_id =
                    v.id.as_ref()
                        .ok_or_else(|| ref_optional_none("BaseVariant.id"))?
                        .value;
            }
            let pattern = v
                .variant_pattern
                .iter()
                .map(get_variant_pattern)
                .collect::<Result<Vec<_>, DiagServiceError>>()?;

            let diag_layer = v.diag_layer.as_ref().ok_or_else(|| {
                DiagServiceError::InvalidDatabase("Variant has no DiagLayer".to_owned())
            })?;

            let variant_services = diag_layer
                .diag_services
                .iter()
                .map(|s| {
                    s.r#ref
                        .as_ref()
                        .map(|pb| pb.value)
                        .ok_or_else(|| ref_optional_none("Variant.DiagServices[].ref_pb"))
                })
                .collect::<Result<Vec<_>, DiagServiceError>>()?;

            // this lookup will later be used by the webservice to translate between the
            // string name and the ID of the service
            // the id then will be used to fetch the actual service
            // same for single ecu jobs
            let service_lookup: HashMap<String, Id> = variant_services
                .iter()
                .filter_map(|service_id| {
                    services.get(service_id).and_then(|service| {
                        STRINGS
                            .get(service.short_name)
                            .map(|name| (name.to_lowercase(), *service_id))
                    })
                })
                .collect();

            let variant_single_ecu_jobs = diag_layer
                .single_ecu_jobs
                .iter()
                .map(|s| {
                    s.r#ref
                        .as_ref()
                        .map(|pb| pb.value)
                        .ok_or_else(|| ref_optional_none("Variant.SingleEcuJobs[].ref_pb"))
                })
                .collect::<Result<Vec<_>, DiagServiceError>>()?;

            let single_ecu_job_lookup: HashMap<String, Id> = variant_single_ecu_jobs
                .iter()
                .filter_map(|job_id| {
                    single_ecu_jobs.get(job_id).and_then(|job| {
                        STRINGS
                            .get(job.short_name)
                            .map(|short_name| (short_name.to_lowercase(), *job_id))
                    })
                })
                .collect();

            let com_params = diag_layer
                .com_param_refs
                .iter()
                .filter_map(|r| map_comparam_ref(r, &ecu_data.ecu_name))
                .collect::<Result<Vec<_>, DiagServiceError>>()?;

            let sdgs = diag_layer
                .sdgs
                .as_ref()
                .and_then(|sdgs| sdgs.r#ref.as_ref().map(|ref_| ref_.value))
                .map(|sdgs_ref| {
                    ecu_data
                        .sdgss
                        .iter()
                        .filter(|sdgs| Some(sdgs_ref) == sdgs.id.as_ref().map(|id| id.value))
                        .flat_map(|sdgs| {
                            sdgs.sdgs
                                .iter()
                                .filter_map(|sdg_ref| sdg_ref.r#ref.as_ref().map(|ref_| ref_.value))
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<Id>>()
                })
                .unwrap_or_default();

            let variant_state_charts = diag_layer
                .state_charts
                .iter()
                .map(|s| {
                    s.r#ref
                        .as_ref()
                        .map(|pb| pb.value)
                        .ok_or_else(|| ref_optional_none("Variant.StateCharts[].ref_pb"))
                })
                .collect::<Result<Vec<_>, DiagServiceError>>()?;

            let state_chart_lookup: HashMap<String, Id> = variant_state_charts
                .iter()
                .filter_map(|chart_id| {
                    state_charts.get(chart_id).and_then(|chart| {
                        STRINGS
                            .get(chart.short_name)
                            .map(|short_name| (short_name.to_lowercase(), *chart_id))
                    })
                })
                .collect();

            Ok((
                v.id.as_ref()
                    .ok_or_else(|| ref_optional_none("Variant.id"))?
                    .value,
                Variant {
                    short_name: v.diag_layer.as_ref().unwrap().short_name.to_string(),
                    pattern,
                    services: variant_services,
                    service_lookup,
                    single_ecu_jobs: variant_single_ecu_jobs,
                    single_ecu_job_lookup,
                    com_params,
                    is_base: v.is_base_variant,
                    sdgs,
                    state_charts: variant_state_charts,
                    state_charts_lookup: state_chart_lookup,
                },
            ))
        })
        .collect::<Result<VariantMap, DiagServiceError>>()?;
    Ok((variants, base_variant_id))
}

fn get_variant_pattern(p: &dataformat::VariantPattern) -> Result<VariantPattern, DiagServiceError> {
    let matching_parameters = p
        .matching_parameter
        .iter()
        .map(|mp| {
            Ok(MatchingParameter {
                expected_value: STRINGS.get_or_insert(&mp.expected_value),
                service_id: mp
                    .diag_service
                    .as_ref()
                    .ok_or_else(|| {
                        DiagServiceError::InvalidDatabase(
                            "variant pattern service ID not set".to_owned(),
                        )
                    })?
                    .r#ref
                    .as_ref()
                    .ok_or_else(|| {
                        ref_optional_none("VariantPattern.matchingParameter[].diagService.ref_pb")
                    })?
                    .value,
                param_id: mp
                    .out_param
                    .as_ref()
                    .ok_or_else(|| {
                        DiagServiceError::InvalidDatabase(
                            "variant pattern param ID not set".to_owned(),
                        )
                    })?
                    .r#ref
                    .as_ref()
                    .ok_or_else(|| {
                        ref_optional_none("VariantPattern.matchingParameter[].outParam.ref_pb")
                    })?
                    .value,
            })
        })
        .collect::<Result<Vec<_>, DiagServiceError>>()?;
    Ok(VariantPattern {
        matching_parameters,
    })
}
