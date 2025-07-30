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
        ComParamRef, DiagnosticServiceMap, Id, ParameterMap, ParameterValue, RequestMap,
        ResponseMap, map_comparam_ref, option_str_to_string, ref_optional_none,
    },
    proto::dataformat::{EcuData, response},
};

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct DiagnosticService {
    pub service_id: u8,
    pub request_id: Id,
    pub pos_responses: Vec<Id>,
    pub neg_responses: Vec<Id>,
    pub com_param_refs: Vec<ComParamRef>,
    pub short_name: StringId,
    pub semantic: StringId,
    pub long_name: Option<StringId>,
    pub sdgs: Vec<Id>,
    /// allowed ecu states to execute this service.
    pub precondition_states: Vec<Id>,
    pub transitions: HashMap<Id, Id>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct Request {
    pub params: Vec<Id>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct Response {
    pub response_type: ResponseType,
    pub params: Vec<Id>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum ResponseType {
    Positive,
    Negative,
    GlobalNegative,
}

pub(super) fn get_requests(ecu_data: &EcuData) -> Result<RequestMap, DiagServiceError> {
    ecu_data
        .requests
        .iter()
        .map(|r| {
            let params = r
                .params
                .iter()
                .map(|p| {
                    p.r#ref
                        .as_ref()
                        .ok_or_else(|| ref_optional_none("Request.params[].ref_pb"))
                        .map(|p| p.value)
                })
                .collect::<Result<Vec<_>, DiagServiceError>>()?;
            Ok((
                r.id.as_ref()
                    .ok_or_else(|| ref_optional_none("Request.id"))?
                    .value,
                Request { params },
            ))
        })
        .collect::<Result<RequestMap, DiagServiceError>>()
}

pub(super) fn get_responses(ecu_data: &EcuData) -> Result<ResponseMap, DiagServiceError> {
    ecu_data
        .responses
        .iter()
        .map(|r| {
            let response_type = r.response_type.try_into()?;
            let params = r
                .params
                .iter()
                .map(|p| {
                    Ok(p.r#ref
                        .as_ref()
                        .ok_or_else(|| ref_optional_none("Response.params[].ref_pb"))?
                        .value)
                })
                .collect::<Result<Vec<_>, DiagServiceError>>()?;
            Ok((
                r.id.as_ref()
                    .ok_or_else(|| ref_optional_none("Response.id"))?
                    .value,
                Response {
                    response_type,
                    params,
                },
            ))
        })
        .collect::<Result<ResponseMap, DiagServiceError>>()
}

#[allow(clippy::too_many_lines)]
pub(super) fn get_services(
    ecu_data: &EcuData,
    requests: &RequestMap,
    parameters: &ParameterMap,
) -> Result<DiagnosticServiceMap, DiagServiceError> {
    let services = ecu_data
        .diag_services
        .iter()
        .map(|ds| {
            let diagservice_id = ds
                .id
                .as_ref()
                .ok_or_else(|| ref_optional_none("DiagService.id"))?
                .value;

            let pos_responses = ds
                .pos_responses
                .iter()
                .map(|r| {
                    Ok::<Id, DiagServiceError>(
                        r.r#ref
                            .as_ref()
                            .ok_or_else(|| ref_optional_none("posResponses[].ref_pb"))?
                            .value,
                    )
                })
                .collect::<Result<Vec<_>, DiagServiceError>>()?;
            let neg_responses = ds
                .neg_responses
                .iter()
                .map(|r| {
                    Ok::<Id, DiagServiceError>(
                        r.r#ref
                            .as_ref()
                            .ok_or_else(|| ref_optional_none("negResponses[].ref_pb"))?
                            .value,
                    )
                })
                .collect::<Result<Vec<_>, DiagServiceError>>()?;
            let com_params = ds
                .com_param_refs
                .iter()
                .filter_map(|r| map_comparam_ref(r, &ecu_data.ecu_name))
                .collect::<Result<Vec<_>, DiagServiceError>>()?;
            let name = ds
                .diag_comm
                .as_ref()
                .ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(
                        "Corrupted DB: Service has no DiagComm".to_owned(),
                    )
                })?
                .short_name
                .to_string();
            let sdgs = ds
                .diag_comm
                .as_ref()
                .and_then(|d| d.sdgs.as_ref())
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

            let long_name = ds.diag_comm.as_ref().and_then(|d| {
                d.long_name
                    .as_ref()
                    .and_then(|ln| option_str_to_string(ln.value.as_ref()))
            });

            let request_id = ds
                .request
                .as_ref()
                .ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(format!("Service {} has no request.", &name))
                })?
                .r#ref
                .as_ref()
                .ok_or_else(|| ref_optional_none("Request.ref_pb"))?
                .value;

            let sid_rq = requests
                .get(&request_id)
                .and_then(|r| {
                    r.params
                        .iter()
                        .filter_map(|p| parameters.get(p))
                        .find_map(|p| {
                            if STRINGS
                                .get(p.short_name)
                                .is_some_and(|sn| sn.to_lowercase() == "sid_rq")
                            {
                                match &p.value {
                                    ParameterValue::CodedConst(c) => {
                                        STRINGS.get(c.value).and_then(|v| v.parse::<u8>().ok())
                                    }
                                    _ => unreachable!(), // sid_rq is always a coded const!
                                }
                            } else {
                                None
                            }
                        })
                })
                .ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(format!(
                        "Service {name} has no SID_RQ parameter."
                    ))
                })?;

            let precondition_states: Vec<u32> = if let Some(dc) = ds.diag_comm.as_ref() {
                dc.pre_condition_state_refs
                    .iter()
                    .flat_map(|pre_cond_ref| {
                        pre_cond_ref
                            .r#ref
                            .map(|cond_ref| cond_ref.value)
                            .into_iter()
                            .flat_map(|pre_cond_id| {
                                ecu_data
                                    .pre_condition_state_refs
                                    .iter()
                                    .filter(move |p| p.id.is_some_and(|id| id.value == pre_cond_id))
                                    .filter_map(|p| p.state?.r#ref.map(|st_ref| st_ref.value))
                            })
                    })
                    .collect()
            } else {
                Vec::new()
            };

            let transitions = if let Some(dc) = ds.diag_comm.as_ref() {
                dc.state_transition_refs
                    .iter()
                    .filter_map(|st| st.r#ref)
                    .filter_map(|st_ref| {
                        ecu_data.state_transition_refs.iter().find(|transition| {
                            transition.id.is_some_and(|id| id.value == st_ref.value)
                        })
                    })
                    .map(|transition_ref| {
                        ecu_data.state_transitions.iter().find(|transition| {
                            transition.id.is_some_and(|id| {
                                transition_ref
                                    .state_transition
                                    .is_some_and(|s| s.r#ref.is_some_and(|r| r.value == id.value))
                            })
                        })
                    })
                    .filter_map(|transition| {
                        if let Some(transition) = transition {
                            let target_state = ecu_data
                                .states
                                .iter()
                                .find(|s| s.short_name == transition.target_short_name_ref)?;

                            let source_state = ecu_data
                                .states
                                .iter()
                                .find(|s| s.short_name == transition.source_short_name_ref)?;

                            let source_id = source_state.id.as_ref()?.value;
                            let target_id = target_state.id.as_ref()?.value;

                            Some((source_id, target_id))
                        } else {
                            None
                        }
                    })
                    .collect::<HashMap<u32, u32>>()
            } else {
                HashMap::new()
            };

            Ok((
                diagservice_id,
                DiagnosticService {
                    service_id: sid_rq,
                    request_id,
                    pos_responses,
                    neg_responses,
                    com_param_refs: com_params,
                    short_name: STRINGS.get_or_insert(&name),
                    semantic: ds
                        .diag_comm
                        .as_ref()
                        .map_or(StringId::MAX, |dc| STRINGS.get_or_insert(&dc.semantic)),
                    long_name,
                    sdgs,
                    precondition_states,
                    transitions,
                },
            ))
        })
        .collect::<Result<DiagnosticServiceMap, DiagServiceError>>()?;
    Ok(services)
}

impl From<response::ResponseType> for ResponseType {
    fn from(response_type: response::ResponseType) -> Self {
        match response_type {
            response::ResponseType::PosResponse => ResponseType::Positive,
            response::ResponseType::NegResponse => ResponseType::Negative,
            response::ResponseType::GlobalNegResponse => ResponseType::GlobalNegative,
        }
    }
}

impl TryFrom<i32> for ResponseType {
    type Error = DiagServiceError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        response::ResponseType::try_from(value)
            .map_err(|_| {
                DiagServiceError::InvalidDatabase(format!("ResponseType {value} not found"))
            })
            .map(Self::from)
    }
}
