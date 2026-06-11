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

use cda_database::datatypes;
use cda_interfaces::{
    DiagServiceError, DynamicPlugin, HashSet, SecurityAccess,
    datatypes::semantics,
    dlt_ctx, service_ids,
    util::starts_with_ignore_ascii_case,
};
use cda_plugin_security::SecurityPlugin;

use super::ecumanager::EcuManager;

impl<S: SecurityPlugin> EcuManager<S> {
    pub(crate) async fn set_service_state(&self, sid: u8, value: String) {
        tracing::debug!("Setting service state: SID: {sid}, Value: {value}");
        self.ecu_service_states.write().await.insert(sid, value);
    }

    pub(crate) async fn get_service_state(&self, sid: u8) -> Option<String> {
        self.ecu_service_states.read().await.get(&sid).cloned()
    }

    pub(crate) async fn lookup_session_change(
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

    pub(crate) async fn lookup_security_access_change(
        &self,
        level: &str,
        seed_service: Option<&String>,
        has_key: bool,
    ) -> Result<SecurityAccess, DiagServiceError> {
        let current_security_name = self.security_access().await?;

        if has_key {
            let security_service = self.lookup_state_transition_for_active(
                semantics::SECURITY,
                &current_security_name,
                level,
            )?;
            Ok(SecurityAccess::SendKey(security_service))
        } else {
            let request_seed_service = self
                .lookup_services_by_sid(service_ids::SECURITY_ACCESS)?
                .into_iter()
                .find(|service| {
                    let service: datatypes::DiagService = (**service).into();

                    let Some(sid) = service.request_id() else {
                        return false;
                    };
                    let Some((sub_func, _)) = service.request_sub_function_id() else {
                        return false;
                    };

                    let name_matches = if let Some(seed_service_name) = seed_service {
                        service.diag_comm().is_some_and(|dc| {
                            dc.short_name().is_some_and(|n| {
                                let n = n.replace('_', "");
                                starts_with_ignore_ascii_case(&n, seed_service_name)
                            })
                        })
                    } else {
                        true
                    };

                    // ISO 14229-1:2020 specifies the given ranges for request seed
                    // 2 parameters: sid_rq and sub_func
                    // needed because the ranges for request seed and send key overlap
                    sid == service_ids::SECURITY_ACCESS
                        && matches!(sub_func, 1 | 3..=5 | 7..=41)
                        && service
                            .request()
                            .is_some_and(|r| r.params().is_some_and(|p| p.len() >= 2))
                        && name_matches
                })
                .ok_or_else(|| {
                    DiagServiceError::NotFound(format!(
                        "No matching 'request seed' SecurityAccess service found for level \
                         '{level}'{}",
                        seed_service
                            .as_ref()
                            .map(|s| format!(" and seed service '{s}'"))
                            .unwrap_or_default()
                    ))
                })?;

            let request_seed_service = request_seed_service.try_into()?;

            Ok(SecurityAccess::RequestSeed(request_seed_service))
        }
    }

    pub(crate) async fn get_send_key_param_name(
        &self,
        diag_service: &cda_interfaces::DiagComm,
    ) -> Result<String, DiagServiceError> {
        let mapped_service = self.lookup_diag_service(diag_service, None, None).await?;
        let request = mapped_service
            .request()
            .ok_or(DiagServiceError::RequestNotSupported(format!(
                "Service '{}' is not supported",
                diag_service.name
            )))?;

        request
            .params()
            .and_then(|params| {
                params.iter().find_map(|p| {
                    if p.semantic().is_some_and(|s| s == semantics::DATA) {
                        p.short_name().map(ToOwned::to_owned)
                    } else {
                        None
                    }
                })
            })
            .ok_or(DiagServiceError::InvalidDatabase(
                "No parameter found for sending key".to_owned(),
            ))
    }

    pub(crate) async fn session(&self) -> Result<String, DiagServiceError> {
        self.ecu_service_states
            .read()
            .await
            .get(&service_ids::SESSION_CONTROL)
            .cloned()
            .ok_or(DiagServiceError::InvalidState(
                "ECU session is none".to_string(),
            ))
    }

    pub(crate) fn default_session(&self) -> Result<String, DiagServiceError> {
        self.default_state(semantics::SESSION)
    }

    pub(crate) async fn security_access(&self) -> Result<String, DiagServiceError> {
        self.ecu_service_states
            .read()
            .await
            .get(&service_ids::SECURITY_ACCESS)
            .cloned()
            .ok_or(DiagServiceError::InvalidState(
                "ECU security is none".to_string(),
            ))
    }

    pub(crate) fn default_security_access(&self) -> Result<String, DiagServiceError> {
        self.default_state(semantics::SECURITY)
    }

    pub(crate) async fn is_service_allowed(
        &self,
        service: &cda_interfaces::DiagComm,
        security_plugin: &DynamicPlugin,
    ) -> Result<(), DiagServiceError> {
        let mapped_service = self.lookup_diag_service(service, None, None).await?;
        self.check_service_access(security_plugin, &mapped_service)
            .await
    }

    /// Set default states for diagnostic services if not already set.
    /// This prevents overriding the actual session/security state during re-detection.
    pub(crate) async fn set_default_states(&self) -> Result<(), DiagServiceError> {
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

    pub(crate) fn lookup_state_transition(
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

    pub(crate) async fn lookup_state_transition_by_diagcomm_for_active(
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
    pub(crate) fn lookup_state_transition_for_active(
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

    pub(crate) fn lookup_state_chart(
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

    pub(crate) fn default_state(&self, semantic: &str) -> Result<String, DiagServiceError> {
        self.lookup_state_chart(semantic)?
            .start_state_short_name_ref()
            .map(ToOwned::to_owned)
            .ok_or(DiagServiceError::InvalidDatabase(
                "No start state defined in state chart".to_owned(),
            ))
    }

    /// Validate security access via plugin
    /// allows passing a `Box::new(())` to skip security checks
    /// this is used internally, when we don't want to have this run the check again
    #[tracing::instrument(
        skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    pub(crate) async fn check_service_access(
        &self,
        security_plugin: &DynamicPlugin,
        service: &datatypes::DiagService<'_>,
    ) -> Result<(), DiagServiceError> {
        let diag_comm = service
            .diag_comm()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Service has no DiagComm".to_owned(),
            ))?;
        self.check_service_preconditions(&diag_comm.into()).await?;
        Self::check_security_plugin(security_plugin, service)
    }

    /// Validate security access via plugin
    /// allows passing a `Box::new(())` to skip security checks
    /// this is used internally, when we don't want to have this run the check again
    #[tracing::instrument(
        skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    pub(crate) fn check_security_plugin(
        security_plugin: &DynamicPlugin,
        service: &datatypes::DiagService,
    ) -> Result<(), DiagServiceError> {
        if let Some(()) = security_plugin.downcast_ref::<()>() {
            tracing::info!("Void security plugin provided, skipping security check");
            return Ok(());
        }
        let security_plugin = security_plugin
            .downcast_ref::<S>()
            .ok_or(DiagServiceError::InvalidSecurityPlugin)
            .map(SecurityPlugin::as_security_plugin)?;

        security_plugin.validate_service(service)
    }

    /// Returns true if the security plugin allows the user to see this service.
    /// Reuses [`Self::check_security_plugin`] which handles void plugins (always allowed)
    /// and real plugins (delegates to [`SecurityApi::validate_service`]).
    pub(crate) fn is_service_visible(
        security_plugin: &DynamicPlugin,
        service: &datatypes::DiagService<'_>,
    ) -> bool {
        Self::check_security_plugin(security_plugin, service).is_ok()
    }

    pub(crate) async fn check_service_preconditions(
        &self,
        diag_comm: &datatypes::DiagComm<'_>,
    ) -> Result<(), DiagServiceError> {
        let Some(pre_condition_state_ref) = diag_comm
            .pre_condition_state_refs()
            .filter(|refs| !refs.is_empty())
        else {
            return Ok(());
        };

        // Only take state transitions into account if present.
        let state_transition_refs = diag_comm
            .state_transition_refs()
            .filter(|refs| !refs.is_empty())
            .unwrap_or_default();

        // Get current ECU states
        let (ecu_session, ecu_security_level) = {
            let ecu_states = self.ecu_service_states.read().await;

            let session = ecu_states
                .get(&service_ids::SESSION_CONTROL)
                .cloned()
                .ok_or(DiagServiceError::InvalidState(
                    "ECU session is none".to_string(),
                ))?
                .to_ascii_lowercase();

            let security = ecu_states
                .get(&service_ids::SECURITY_ACCESS)
                .cloned()
                .ok_or(DiagServiceError::InvalidState(
                    "ECU security level is none".to_string(),
                ))?
                .to_ascii_lowercase();

            (session, security)
        };

        let get_state_names = |semantic| {
            Ok(self
                .lookup_state_chart(semantic)?
                .states()
                .into_iter()
                .flatten()
                .filter_map(|s| s.short_name())
                .map(str::to_ascii_lowercase)
                .collect::<HashSet<_>>())
        };

        let session_states = get_state_names(semantics::SESSION)?;
        let security_states = get_state_names(semantics::SECURITY)?;

        let precondition_states: Vec<_> = pre_condition_state_ref
            .iter()
            .filter_map(|state_ref| state_ref.state())
            .filter_map(|state| state.short_name())
            .map(str::to_ascii_lowercase)
            .collect();

        let (mut allowed_security, mut allowed_session): (HashSet<_>, HashSet<_>) =
            precondition_states.into_iter().fold(
                (HashSet::default(), HashSet::default()),
                |(mut security, mut session), state_name| {
                    if security_states.contains(&state_name) {
                        security.insert(state_name);
                    } else if session_states.contains(&state_name) {
                        session.insert(state_name);
                    }
                    (security, session)
                },
            );

        // add state transition sources to allowed security states
        state_transition_refs
            .iter()
            .filter_map(|st_ref| {
                st_ref
                    .state_transition()
                    .and_then(|st| st.source_short_name_ref())
            })
            .map(str::to_ascii_lowercase)
            .for_each(|state| {
                allowed_security.insert(state.clone());
                allowed_session.insert(state);
            });

        // Resolve the default states from the MDD state charts. When checking
        // preconditions we also accept the default state as a valid "current" state,
        // so that services whose preconditions include the default are always reachable
        // regardless of the actual ECU state.
        let default_session = self.default_state(semantics::SESSION)?.to_ascii_lowercase();
        let default_security = self
            .default_state(semantics::SECURITY)?
            .to_ascii_lowercase();

        let validate_state = |required: &HashSet<String>,
                               current: &str,
                               default: &str,
                               state_type: &str|
         -> Result<(), DiagServiceError> {
            if required.is_empty() || required.contains(current) || required.contains(default) {
                Ok(())
            } else {
                Err(DiagServiceError::InvalidState(format!(
                    "{service} - {state_type} mismatch. Required one of: {required:?}, Current: \
                     {current}",
                    service = diag_comm.short_name().unwrap_or("None"),
                )))
            }
        };

        validate_state(
            &allowed_security,
            &ecu_security_level,
            &default_security,
            "Security level",
        )?;
        validate_state(&allowed_session, &ecu_session, &default_session, "Session")
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{EcuManager, diagservices::UdsPayloadData};
    use cda_plugin_security::DefaultSecurityPluginData;

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
