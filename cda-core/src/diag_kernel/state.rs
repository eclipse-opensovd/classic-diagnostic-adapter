/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
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
use cda_interfaces::{
    DiagServiceError, EcuStateManager, datatypes::semantics, dlt_ctx, service_ids,
};
use cda_plugin_security::SecurityPlugin;

use super::ecumanager::EcuManager;

impl<S: SecurityPlugin> EcuStateManager for EcuManager<S> {
    async fn set_service_state(&self, sid: u8, value: String) {
        tracing::debug!("Setting service state: SID: {sid}, Value: {value}");
        self.ecu_service_states.write().await.insert(sid, value);
    }

    async fn get_service_state(&self, sid: u8) -> Option<String> {
        self.ecu_service_states.read().await.get(&sid).cloned()
    }

    async fn session(&self) -> Result<String, DiagServiceError> {
        self.ecu_service_states
            .read()
            .await
            .get(&service_ids::SESSION_CONTROL)
            .cloned()
            .ok_or(DiagServiceError::InvalidState(
                "ECU session is none".to_string(),
            ))
    }

    fn default_session(&self) -> Result<String, DiagServiceError> {
        self.default_state(semantics::SESSION)
    }

    async fn security_access(&self) -> Result<String, DiagServiceError> {
        self.ecu_service_states
            .read()
            .await
            .get(&service_ids::SECURITY_ACCESS)
            .cloned()
            .ok_or(DiagServiceError::InvalidState(
                "ECU security is none".to_string(),
            ))
    }

    async fn lookup_session_change(
        &self,
        target_session_name: &str,
    ) -> Result<cda_interfaces::DiagComm, DiagServiceError> {
        let current_session_name = self
            .ecu_service_states
            .read()
            .await
            .get(&service_ids::SESSION_CONTROL)
            .cloned()
            .ok_or(DiagServiceError::InvalidState(
                "ECU session is none".to_string(),
            ))?;

        self.lookup_state_transition_for_active(
            semantics::SESSION,
            &current_session_name,
            target_session_name,
        )
    }

    /// Set default states for diagnostic services if not already set.
    /// This prevents overriding the actual session/security state during re-detection.
    async fn set_default_states(&self) -> Result<(), DiagServiceError> {
        // todo read this from the variant detection instead of assuming default, see #110
        // Only set default state if not already set - otherwise we'd override
        // the actual session/security state during re-detection.
        // This prevents an issue if the variant detection is running _after_
        // the session has been changed.
        // For example when switching to 'extended' immediately after the service
        // signals 'ready'

        let mut states = self.ecu_service_states.write().await;
        states
            .entry(service_ids::SESSION_CONTROL)
            .or_insert(self.default_state(semantics::SESSION)?);
        states
            .entry(service_ids::SECURITY_ACCESS)
            .or_insert(self.default_state(semantics::SECURITY)?);
        states
            .entry(service_ids::CONTROL_DTC_SETTING)
            .or_insert_with(|| "on".to_owned());
        states
            .entry(service_ids::COMMUNICATION_CONTROL)
            .or_insert_with(|| "enablerxandenabletx".to_owned());
        Ok(())
    }
}

impl<S: SecurityPlugin> EcuManager<S> {
    fn lookup_state_transition(
        diag_comm: &datatypes::DiagComm,
        state_chart: &datatypes::StateChart,
        current_state: &str,
    ) -> Option<String> {
        diag_comm
            .state_transition_refs()?
            .iter()
            .find_map(|st_ref| {
                let state_transition = st_ref.state_transition()?;
                // Only return a target if the service's state transition
                // matches one in this state chart.
                // We match by source and target to ensure a SecurityAccess service
                // (which references SECURITY state chart transitions) won't accidentally
                // match transitions in the SESSION state chart.
                let transition_source = state_transition.source_short_name_ref()?;
                let transition_target = state_transition.target_short_name_ref()?;

                // Check if this transition exists in the state chart and starts from current state
                if state_chart.state_transitions()?.iter().any(|chart_st| {
                    chart_st.source_short_name_ref() == Some(transition_source)
                        && chart_st.target_short_name_ref() == Some(transition_target)
                        && transition_source == current_state
                }) {
                    Some(transition_target.to_owned())
                } else {
                    None
                }
            })
    }

    pub(in crate::diag_kernel) async fn lookup_state_transition_by_diagcomm_for_active(
        &self,
        diag_comm: &datatypes::DiagComm<'_>,
    ) -> (Option<String>, Option<String>) {
        let diag_layers = self.get_diag_layers_from_variant_and_parent_refs();

        let state_chart_session = diag_layers.iter().find_map(|dl| {
            dl.state_charts().and_then(|charts| {
                charts.iter().find(|c| {
                    c.semantic()
                        .is_some_and(|n| n.eq_ignore_ascii_case(semantics::SESSION))
                })
            })
        });
        let state_chart_security = diag_layers.iter().find_map(|dl| {
            dl.state_charts().and_then(|charts| {
                charts.iter().find(|c| {
                    c.semantic()
                        .is_some_and(|n| n.eq_ignore_ascii_case(semantics::SECURITY))
                })
            })
        });

        let states = self.ecu_service_states.write().await;
        let new_session = states
            .get(&service_ids::SESSION_CONTROL)
            .as_ref()
            .and_then(|session| {
                state_chart_session
                    .and_then(|sc| Self::lookup_state_transition(diag_comm, &(sc.into()), session))
            });
        let new_security = states
            .get(&service_ids::SECURITY_ACCESS)
            .as_ref()
            .and_then(|session| {
                state_chart_security
                    .and_then(|sc| Self::lookup_state_transition(diag_comm, &(sc.into()), session))
            });
        drop(states);

        (new_session, new_security)
    }

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    pub(in crate::diag_kernel) fn lookup_state_transition_for_active(
        &self,
        semantic: &str,
        current_state: &str,
        target_state: &str,
    ) -> Result<cda_interfaces::DiagComm, DiagServiceError> {
        let semantic_transitions = self
            .get_diag_layers_from_variant_and_parent_refs()
            .iter()
            .filter_map(|dl| dl.state_charts())
            .flat_map(|charts| charts.iter())
            .find_map(|c| {
                if c.semantic()
                    .is_some_and(|n| n.eq_ignore_ascii_case(semantic))
                {
                    c.state_transitions()
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                tracing::error!(
                    ecu_name = self.ecu_name,
                    semantic = %semantic,
                    "State chart with given semantic not found in base variant"
                );
                DiagServiceError::NotFound(format!(
                    "State chart with semantic '{semantic}' not found in base variant"
                ))
            })?;

        let find_service_for_state = |source_state: &str| {
            self.get_services_from_variant_and_parent_refs(|s| {
                s.diag_comm()
                    .and_then(|dc| dc.state_transition_refs())
                    .is_some_and(|st_refs| {
                        st_refs.iter().any(|st_ref| {
                            st_ref.state_transition().is_some_and(|st| {
                                st.source_short_name_ref()
                                    .is_some_and(|n| n.eq_ignore_ascii_case(source_state))
                                    && st
                                        .target_short_name_ref()
                                        .is_some_and(|n| n.eq_ignore_ascii_case(target_state))
                                    && semantic_transitions.iter().any(|semantic| semantic == st)
                            })
                        })
                    })
            })
            .into_iter()
            .next()
        };

        // Try the current state first. If no matching service is found, fall back
        // to the default state so that services reachable from the default are
        // always available regardless of the actual ECU state.
        let service = find_service_for_state(current_state)
            .or_else(|| {
                let default_state = self.default_state(semantic).ok()?;
                if default_state.eq_ignore_ascii_case(current_state) {
                    return None; // already tried this state
                }
                tracing::debug!(
                    current_state,
                    default_state = %default_state,
                    target_state,
                    semantic,
                    "No service found for current state, falling back to default state"
                );
                find_service_for_state(&default_state)
            })
            .ok_or_else(|| {
                tracing::error!(
                    current_state,
                    target_state,
                    semantic,
                    "Failed to find service for state transition"
                );
                DiagServiceError::NotFound(format!(
                    "No service found for state transition {current_state} -> {target_state} \
                     ({semantic})"
                ))
            })?;

        service.try_into()
    }

    pub(in crate::diag_kernel) fn lookup_state_chart(
        &self,
        semantic: &str,
    ) -> Result<datatypes::StateChart<'_>, DiagServiceError> {
        self.get_diag_layers_from_variant_and_parent_refs()
            .into_iter()
            .filter_map(|dl| dl.state_charts())
            .flat_map(|sc| sc.iter())
            .find(|sc| sc.semantic().is_some_and(|sem| sem == semantic))
            .map(datatypes::StateChart)
            .ok_or_else(|| {
                DiagServiceError::NotFound(format!(
                    "State chart with semantic '{semantic}' not found in base variant"
                ))
            })
    }

    pub(in crate::diag_kernel) fn default_state(
        &self,
        semantic: &str,
    ) -> Result<String, DiagServiceError> {
        self.lookup_state_chart(semantic)?
            .start_state_short_name_ref()
            .map(ToOwned::to_owned)
            .ok_or(DiagServiceError::InvalidDatabase(
                "No start state defined in state chart".to_owned(),
            ))
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{DynamicPlugin, PayloadEncoder, diagservices::UdsPayloadData};

    use super::*;
    use crate::diag_kernel::test_utils::ecu_manager_builder::{
        ServiceSecurityTransition, create_ecu_manager_with_preconditions_and_functional_group,
        create_ecu_manager_with_state_transitions,
    };

    macro_rules! skip_sec_plugin {
        () => {{
            let skip_sec_plugin: DynamicPlugin = Box::new(());
            skip_sec_plugin
        }};
    }

    #[tokio::test]
    async fn test_state_transition_source_allowed_as_valid_security_state() {
        let (ecu_manager, dc) =
            create_ecu_manager_with_state_transitions(ServiceSecurityTransition::LockedToExtended);

        {
            let mut ecu_states = ecu_manager.ecu_service_states.write().await;
            ecu_states.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_string());
            ecu_states.insert(service_ids::SECURITY_ACCESS, "LockedSecurity".to_string());
        }

        let payload_data = UdsPayloadData::Raw(vec![service_ids::WRITE_DATA_BY_IDENTIFIER]);

        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(
            result.is_ok(),
            "Service should be allowed from source state of state transition. Error: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_state_precondition() {
        let (ecu_manager, dc) =
            create_ecu_manager_with_state_transitions(ServiceSecurityTransition::LockedToExtended);

        {
            let mut ecu_states = ecu_manager.ecu_service_states.write().await;
            ecu_states.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_string());
            ecu_states.insert(
                service_ids::SECURITY_ACCESS,
                "ProgrammingSecurity".to_string(),
            );
        }

        let payload_data = UdsPayloadData::Raw(vec![service_ids::WRITE_DATA_BY_IDENTIFIER]);

        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(
            result.is_ok(),
            "Service should be allowed when in precondition state"
        );
    }

    #[tokio::test]
    async fn test_invalid_security_state_rejected() {
        let (ecu_manager, dc) = create_ecu_manager_with_state_transitions(
            ServiceSecurityTransition::ExtendedToProgramming,
        );

        {
            let mut ecu_states = ecu_manager.ecu_service_states.write().await;
            ecu_states.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_string());
            ecu_states.insert(service_ids::SECURITY_ACCESS, "LockedSecurity".to_string());
        }

        let payload_data = UdsPayloadData::Raw(vec![service_ids::WRITE_DATA_BY_IDENTIFIER]);

        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(
            result.is_err(),
            "Service should NOT be allowed when neither current nor default security state is in \
             the allowed set"
        );
    }

    #[tokio::test]
    async fn test_functional_group_service_skips_precondition_check() {
        let (ecu_manager, dc, sid) = create_ecu_manager_with_preconditions_and_functional_group();

        {
            let mut ecu_states = ecu_manager.ecu_service_states.write().await;
            ecu_states.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_string());
            ecu_states.insert(service_ids::SECURITY_ACCESS, "LockedSecurity".to_string());
        }

        let variant_result = ecu_manager
            .create_uds_payload(
                &dc,
                &skip_sec_plugin!(),
                Some(UdsPayloadData::Raw(vec![sid])),
                None,
            )
            .await;
        assert!(
            variant_result.is_err(),
            "Variant service should be rejected when preconditions are not met"
        );

        let fg_result = ecu_manager
            .create_uds_payload(
                &dc,
                &skip_sec_plugin!(),
                Some(UdsPayloadData::Raw(vec![sid])),
                Some("TestFunctionalGroup"),
            )
            .await;
        assert!(
            fg_result.is_ok(),
            "Functional group service should skip precondition check. Error: {:?}",
            fg_result.err()
        );
    }
}
