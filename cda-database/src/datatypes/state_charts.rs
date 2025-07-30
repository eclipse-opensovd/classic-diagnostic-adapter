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

use cda_interfaces::{DiagServiceError, STRINGS, StringId, service_ids};
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;
use hashbrown::{HashMap, HashSet};

use crate::{
    datatypes::{DiagnosticServiceMap, Id, ref_optional_none},
    proto::dataformat::{self},
};

pub type BaseStateChartMap = HashMap<String, Id>;
pub type StateChartMap = HashMap<Id, StateChart>;

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct StateTransition {
    pub session: Option<Id>,
    pub security_access: Option<Id>,
    pub authentication: Option<Id>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct State {
    pub id: Id,
    pub short_name: StringId,
    pub transitions: HashMap<Id, StateTransition>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct StateChart {
    pub short_name: StringId,
    pub semantic: StringId,
    pub states: HashMap<Id, State>,
    pub default_state: Id,
}

pub fn get_state_charts(
    ecu_data: &dataformat::EcuData,
    services: &DiagnosticServiceMap,
) -> Result<(StateChartMap, HashMap<String, Id>), DiagServiceError> {
    let mut state_chart_lookup: HashMap<String, Id> = HashMap::new();
    let state_charts = ecu_data
        .state_charts
        .iter()
        .map(|chart| {
            let states = chart
                .states
                .iter()
                .filter_map(|state| state.r#ref.as_ref())
                .map(|state_id| {
                    let state = ecu_data
                        .states
                        .iter()
                        .find(|state| state.id.as_ref() == Some(state_id))
                        .ok_or_else(|| {
                            DiagServiceError::InvalidDatabase(format!(
                                "State with id {state_id:?} not found in ecu data."
                            ))
                        })?;

                    let short_name_id = STRINGS.get_or_insert(&state.short_name.to_lowercase());
                    let transitions =
                        process_state_transitions(state, services).unwrap_or_default();

                    Ok((
                        state_id.value,
                        State {
                            id: state_id.value,
                            short_name: short_name_id,
                            transitions,
                        },
                    ))
                })
                .collect::<Result<HashMap<Id, State>, DiagServiceError>>()?;

            state_chart_lookup.insert(
                chart.semantic.to_string().to_uppercase(),
                chart
                    .id
                    .as_ref()
                    .ok_or_else(|| ref_optional_none("StateChart.id"))?
                    .value,
            );

            let default_state = states
                .values()
                .find(|state| {
                    STRINGS
                        .get(state.short_name)
                        .is_some_and(|name| name == chart.start_state_short_name_ref.to_lowercase())
                })
                .map(|state| state.id)
                .ok_or_else(|| ref_optional_none("DefaultState"))?;

            Ok((
                chart
                    .id
                    .as_ref()
                    .ok_or_else(|| ref_optional_none("StateChart.id"))?
                    .value,
                StateChart {
                    short_name: STRINGS.get_or_insert(&chart.short_name.to_lowercase()),
                    semantic: STRINGS.get_or_insert(&chart.semantic.to_uppercase()),
                    states,
                    default_state,
                },
            ))
        })
        .collect::<Result<StateChartMap, DiagServiceError>>()?;

    Ok((state_charts, state_chart_lookup))
}

fn process_state_transitions(
    source_state: &dataformat::State,
    services: &DiagnosticServiceMap,
) -> Result<HashMap<Id, StateTransition>, DiagServiceError> {
    let services: Vec<_> = services
        .iter()
        .filter(|(_id, service)| {
            service
                .transitions
                .iter()
                .any(|(from, _)| source_state.id.is_some_and(|id| from == &id.value))
        })
        .collect();

    let target_states = services
        .iter()
        .flat_map(|(_id, service)| service.transitions.values().copied())
        .collect::<HashSet<_>>();

    target_states
        .iter()
        .map(|target_id| {
            let service_for_target_state: Vec<_> = services
                .iter()
                .filter(|(_id, service)| service.transitions.iter().any(|(_, to)| to == target_id))
                .collect();

            let session = service_for_target_state
                .iter()
                .find(|(_id, service)| service.service_id == service_ids::SESSION_CONTROL)
                .map(|(id, _service)| **id);

            let security_access = service_for_target_state
                .iter()
                .find(|(_id, service)| service.service_id == service_ids::SECURITY_ACCESS)
                .map(|(id, _service)| **id);

            let authentication = service_for_target_state
                .iter()
                .find(|(_id, service)| service.service_id == service_ids::AUTHENTICATION)
                .map(|(id, _service)| **id);

            Ok((
                *target_id,
                StateTransition {
                    session,
                    security_access,
                    authentication,
                },
            ))
        })
        .collect::<Result<HashMap<_, _>, DiagServiceError>>()
}
