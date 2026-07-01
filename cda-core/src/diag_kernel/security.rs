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
    DiagServiceError, DynamicPlugin, EcuSecurity, EcuStateManager, HashSet, SecurityAccess,
    datatypes::semantics,
    dlt_ctx, service_ids,
    util::{contains_ignore_ascii_case, std_ext},
};
use cda_plugin_security::SecurityPlugin;

use super::ecumanager::EcuManager;

impl<S: SecurityPlugin> EcuSecurity for EcuManager<S> {
    async fn lookup_security_access_change(
        &self,
        level: &str,
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
            // Find the RequestSeed service for the requested level by searching all SID 0x27
            // services in the ISO 14229-1 RequestSeed subfunction range and selecting the one
            // whose short name contains the level name (underscores stripped, case-insensitive).
            // 2 request parameters (SID + subfunction, no key payload) distinguishes RequestSeed
            // from SendKey services whose subfunctions overlap in the ISO range.
            let level_sub_func: Option<u32> = level
                .split('_')
                .next_back()
                .and_then(|l| u32::from_str_radix(l, 16).ok().or_else(|| l.parse().ok()));
            let level_stripped = level.replace('_', "");
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

                    sid == service_ids::SECURITY_ACCESS
                        && matches!(sub_func, 1 | 3..=5 | 7..=41)
                        && service
                            .request()
                            .is_some_and(|r| r.params().is_some_and(|p| p.len() >= 2))
                        // Try matching by name first, if that did not yield a result,
                        // check if the subfunction ID matches the level.
                        && (service.diag_comm().is_some_and(|dc| {
                            dc.short_name().is_some_and(|n| {
                                contains_ignore_ascii_case(&n.replace('_', ""), &level_stripped)
                            })
                        })  || Some(sub_func) == level_sub_func)
                })
                .ok_or_else(|| {
                    DiagServiceError::NotFound(format!(
                        "No matching 'request seed' SecurityAccess service found for level \
                         '{level}'"
                    ))
                })?;

            let request_seed_service = request_seed_service.try_into()?;
            tracing::debug!(
                "Found request_seed_service: {request_seed_service:?}, sub function id \
                 {level_sub_func:?}"
            );

            Ok(SecurityAccess::RequestSeed(request_seed_service))
        }
    }

    async fn get_send_key_param_name(
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

    fn default_security_access(&self) -> Result<String, DiagServiceError> {
        self.default_state(semantics::SECURITY)
    }

    async fn is_service_allowed(
        &self,
        service: &cda_interfaces::DiagComm,
        security_plugin: &DynamicPlugin,
    ) -> Result<(), DiagServiceError> {
        let mapped_service = self.lookup_diag_service(service, None, None).await?;
        self.check_service_access(security_plugin, &mapped_service)
            .await
    }
}

impl<S: SecurityPlugin> EcuManager<S> {
    /// Validate security access via plugin.
    /// Allows passing a `Box::new(())` to skip security checks;
    /// this is used internally when we don't want to run the check again.
    #[tracing::instrument(
        skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    pub(in crate::diag_kernel) async fn check_service_access(
        &self,
        security_plugin: &DynamicPlugin,
        service: &datatypes::DiagService<'_>,
    ) -> Result<(), DiagServiceError> {
        let diag_comm = service
            .diag_comm()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Service has no DiagComm".to_owned(),
            ))?;
        self.check_service_preconditions(&diag_comm.into())?;
        check_security_plugin::<S>(security_plugin, service)
    }

    fn check_service_preconditions(
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
            let ss = std_ext::lock_read(&self.runtime_state.service_states);

            let session = ss
                .get(&service_ids::SESSION_CONTROL)
                .cloned()
                .ok_or(DiagServiceError::InvalidState(
                    "ECU session is none".to_string(),
                ))?
                .to_ascii_lowercase();

            let security = ss
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

/// Returns true if the security plugin allows the user to see this service.
/// Reuses [`Self::check_security_plugin`] which handles void plugins (always allowed)
/// and real plugins (delegates to [`SecurityApi::validate_service`]).
pub(in crate::diag_kernel) fn is_service_visible<S: SecurityPlugin>(
    security_plugin: &DynamicPlugin,
    service: &datatypes::DiagService<'_>,
) -> bool {
    check_security_plugin::<S>(security_plugin, service).is_ok()
}

/// Validate security access via plugin.
/// Allows passing a `Box::new(())` to skip security checks;
/// this is used internally when we don't want to run the check again.
#[tracing::instrument(
    skip_all,
    fields(
        dlt_context = dlt_ctx!("CORE"),
    )
)]
pub(in crate::diag_kernel) fn check_security_plugin<S: SecurityPlugin>(
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

#[cfg(test)]
mod tests {
    use cda_interfaces::{DiagServiceError, EcuSecurity, SecurityAccess, service_ids};

    use crate::diag_kernel::test_utils::ecu_manager_builder::create_ecu_manager_with_security_access_services;

    /// Name-based lookup: level name is contained in the service's `short_name`
    /// (underscores stripped, case-insensitive). The matching service is returned
    /// as `SecurityAccess::RequestSeed`.
    #[tokio::test]
    async fn test_lookup_security_access_request_seed_by_name() {
        let (ecu_manager, _, request_seed_12_name, _) =
            create_ecu_manager_with_security_access_services();
        {
            let mut guard = ecu_manager.runtime_state.service_states.write().unwrap();
            guard.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_owned());
            guard.insert(service_ids::SECURITY_ACCESS, "LockedSecurity".to_owned());
        }

        let result = ecu_manager
            .lookup_security_access_change("level_12", false)
            .await;
        assert!(
            result.is_ok(),
            "name-based lookup for level_12 failed: {:?}",
            result.err()
        );
        let SecurityAccess::RequestSeed(dc) = result.unwrap() else {
            panic!("expected SecurityAccess::RequestSeed");
        };
        assert_eq!(dc.name, request_seed_12_name);
    }

    /// Per-id lookup with a bare hex-encoded trailing suffix (no "0x" prefix).
    /// `"access_12"` -> trailing segment "12" -> `from_str_radix("12", 16)` = 18 = 0x12
    /// -> sub-func 0x12 -> matches `RequestSeed_level_12`.
    #[tokio::test]
    async fn test_lookup_security_access_request_seed_by_subfunction_id_hex() {
        let (ecu_manager, _, request_seed_12_name, _) =
            create_ecu_manager_with_security_access_services();
        {
            let mut guard = ecu_manager.runtime_state.service_states.write().unwrap();
            guard.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_owned());
            guard.insert(service_ids::SECURITY_ACCESS, "LockedSecurity".to_owned());
        }

        // "access_12" -> trailing "12" -> from_str_radix("12", 16) = 18 -> sub-func 0x12
        let result = ecu_manager
            .lookup_security_access_change("access_12", false)
            .await;
        assert!(
            result.is_ok(),
            "subfunction-id bare-hex fallback lookup failed: {:?}",
            result.err()
        );
        let SecurityAccess::RequestSeed(dc) = result.unwrap() else {
            panic!("expected SecurityAccess::RequestSeed");
        };
        assert_eq!(dc.name, request_seed_12_name);
    }

    /// A level that cannot be resolved either by name or by subfunction ID must
    /// return `Err(DiagServiceError::NotFound)`.
    #[tokio::test]
    async fn test_lookup_security_access_request_seed_not_found() {
        let (ecu_manager, ..) = create_ecu_manager_with_security_access_services();
        {
            let mut guard = ecu_manager.runtime_state.service_states.write().unwrap();
            guard.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_owned());
            guard.insert(service_ids::SECURITY_ACCESS, "LockedSecurity".to_owned());
        }

        // "unknown_99" - name not in any service, sub-func 99 (0x63) is outside
        // the RequestSeed range (1 | 3..=5 | 7..=41) so no service matches.
        let result = ecu_manager
            .lookup_security_access_change("unknown_99", false)
            .await;
        assert!(
            matches!(result, Err(DiagServiceError::NotFound(_))),
            "expected NotFound for unresolvable level, got {:?}",
            result.err()
        );
    }

    /// `has_key = true` path: `lookup_security_access_change` must delegate to
    /// `lookup_state_transition_for_active` on the SECURITY state chart and
    /// return `SecurityAccess::SendKey` pointing at the service that carries the
    /// `LockedSecurity -> ExtendedSecurity` transition ref.
    #[tokio::test]
    async fn test_lookup_security_access_send_key_via_state_transition() {
        let (ecu_manager, _, _, send_key_01_name) =
            create_ecu_manager_with_security_access_services();
        {
            let mut guard = ecu_manager.runtime_state.service_states.write().unwrap();
            guard.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_owned());
            guard.insert(service_ids::SECURITY_ACCESS, "LockedSecurity".to_owned());
        }

        // Transition LockedSecurity -> ExtendedSecurity; SendKey_level_01 carries that ref.
        let result = ecu_manager
            .lookup_security_access_change("ExtendedSecurity", true)
            .await;
        assert!(result.is_ok(), "SendKey lookup failed: {:?}", result.err());
        let SecurityAccess::SendKey(dc) = result.unwrap() else {
            panic!("expected SecurityAccess::SendKey");
        };
        assert_eq!(dc.name, send_key_01_name);
    }
}
