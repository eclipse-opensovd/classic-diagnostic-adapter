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

use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use cda_interfaces::{
    DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, ResetOutcome, UdsAuthentication,
    UdsTransport,
    authentication::{
        AuthenticationState, AuthenticationStatus, AuthenticationSubFunction,
        return_value_completes_authentication,
    },
    diagservices::{DiagServiceResponse, DiagServiceResponseType, UdsPayloadData},
    dlt_ctx,
};

use crate::{UdsManager, types::ResetType};

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    /// Derives the new tracked state from a positive response.
    /// Returns the new state and whether it completed the authentication.
    async fn authentication_state_after_positive(
        &self,
        ecu_name: &str,
        sub_function: AuthenticationSubFunction,
        raw_response: &[u8],
        expiration: Option<Duration>,
    ) -> Result<(AuthenticationState, bool), DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name)?.read().await;
        let previous = ecu.authentication_state();

        if sub_function == AuthenticationSubFunction::DeAuthenticate {
            let state = AuthenticationState::deauthenticated(Some(sub_function));
            ecu.set_authentication_state(state.clone());
            return Ok((state, false));
        }

        let completes = match ecu.authentication_return_value(sub_function, raw_response) {
            Ok(Some(value)) => return_value_completes_authentication(sub_function, value),
            Ok(None) => {
                tracing::warn!(
                    ecu_name,
                    %sub_function,
                    "No authenticationReturnParameter defined in the diagnostic description"
                );
                false
            }
            Err(e) => {
                tracing::warn!(
                    ecu_name,
                    %sub_function,
                    error = %e,
                    "Failed to read authenticationReturnParameter"
                );
                false
            }
        };

        let state = if completes {
            AuthenticationState {
                status: AuthenticationStatus::Authenticated,
                last_subfunction: Some(sub_function),
                expires_at: expiration
                    .filter(|e| !e.is_zero())
                    .and_then(|e| SystemTime::now().checked_add(e)),
            }
        } else {
            // Intermediate steps (e.g. requestChallengeForAuthentication) do not
            // change the authenticated status or a running expiration.
            AuthenticationState {
                last_subfunction: Some(sub_function),
                ..previous
            }
        };
        ecu.set_authentication_state(state.clone());
        Ok((state, completes))
    }
}

#[async_trait]
impl<S: EcuGateway, T: EcuManager> UdsAuthentication for UdsManager<S, T> {
    #[tracing::instrument(skip_all,
        fields(ecu_name, %sub_function, dlt_context = dlt_ctx!("UDS"))
    )]
    async fn authenticate(
        &self,
        ecu_name: &str,
        sub_function: AuthenticationSubFunction,
        parameters: Option<UdsPayloadData>,
        security_plugin: &DynamicPlugin,
        expiration: Option<Duration>,
    ) -> Result<Self::Response, DiagServiceError> {
        if sub_function == AuthenticationSubFunction::DeAuthenticate && expiration.is_some() {
            return Err(DiagServiceError::InvalidRequest(
                "mode_expiration must not be set for deAuthenticate".to_owned(),
            ));
        }

        let ecu = self.uds_ecu_variant_detection_concluded(ecu_name).await?;
        let service = ecu
            .read()
            .await
            .lookup_authentication_service(sub_function)?;

        tracing::info!(ecu_name, %sub_function, "Sending authentication request");
        let response = self
            .send(ecu_name, service, security_plugin, parameters, true)
            .await?;

        match response.response_type() {
            DiagServiceResponseType::Positive => {
                let (state, completes) = self
                    .authentication_state_after_positive(
                        ecu_name,
                        sub_function,
                        response.get_raw(),
                        expiration,
                    )
                    .await?;
                if completes {
                    // Restarts a running expiration, or cancels it without expiration.
                    self.start_reset_task(ecu_name, expiration, ResetType::Authentication)
                        .await;
                } else if !state.is_authenticated() {
                    self.cancel_reset(ecu_name, ResetType::Authentication).await;
                }
                tracing::info!(
                    ecu_name,
                    %sub_function,
                    status = state.status.name(),
                    "Authentication request answered positively"
                );
            }
            DiagServiceResponseType::Negative => {
                // An authenticated server stays authenticated until a new
                // authentication completes or the state is explicitly left
                // (ISO 14229-1:2020 clause 10.6.4). Tracked state and a running
                // expiration are kept, so the deAuthenticate on expiration or
                // cleanup is still sent.
                tracing::warn!(
                    ecu_name,
                    %sub_function,
                    "Authentication request answered negatively, tracked state unchanged"
                );
            }
        }
        Ok(response)
    }

    async fn reset_ecu_authentication(
        &self,
        ecu_name: &str,
    ) -> Result<ResetOutcome, DiagServiceError> {
        // Cancel any existing expiration to prevent double resetting
        self.cancel_reset(ecu_name, ResetType::Authentication).await;

        let ecu = self.uds_ecu_db(ecu_name)?;
        if !ecu.read().await.authentication_state().is_authenticated() {
            tracing::debug!(ecu_name, "Not authenticated, nothing to do");
            return Ok(ResetOutcome::Completed);
        }

        // Checked directly rather than through the send path, which would
        // request an activation: a reset must not switch communication on.
        let Ok(_guard) = self.communication_access.acquire() else {
            self.defer_reset(ecu_name, ResetType::Authentication).await;
            return Ok(ResetOutcome::Deferred);
        };

        // On failure the tracked state stays authenticated: the ECU may still
        // be unprotected (NRC 0x5D, ISO 14229-1:2020 Table A.1), and keeping
        // the state makes the next lock release or cleanup retry deAuthenticate.
        // A reset is housekeeping and must never be blocked by service validation or the
        // pre-send authorization.
        let void_plugin: DynamicPlugin = Box::new(());
        let response = self
            .authenticate(
                ecu_name,
                AuthenticationSubFunction::DeAuthenticate,
                None,
                &void_plugin,
                None,
            )
            .await?;

        match response.response_type() {
            DiagServiceResponseType::Positive => {
                tracing::info!(ecu_name, "ECU deauthenticated");
                Ok(ResetOutcome::Completed)
            }
            DiagServiceResponseType::Negative => Err(DiagServiceError::UnexpectedResponse(Some(
                "deAuthenticate negative response".to_owned(),
            ))),
        }
    }

    async fn get_ecu_authentication_state(
        &self,
        ecu_name: &str,
    ) -> Result<AuthenticationState, DiagServiceError> {
        Ok(self
            .uds_ecu_db(ecu_name)?
            .read()
            .await
            .authentication_state())
    }

    async fn has_authentication_services(&self, ecu_name: &str) -> bool {
        let Ok(ecu) = self.uds_ecu_variant_detection_concluded(ecu_name).await else {
            return false;
        };
        let ecu = ecu.read().await;
        AuthenticationSubFunction::ALL
            .into_iter()
            .any(|sf| ecu.lookup_authentication_service(sf).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use cda_interfaces::{
        DiagServiceError, DynamicPlugin, EcuStateManager, HashMap, ResetOutcome, ServicePayload,
        TransportResponse, UdsAuthentication,
        authentication::{AuthenticationState, AuthenticationStatus, AuthenticationSubFunction},
        datatypes::FaultConfig,
        diagservices::{DiagServiceResponse, DiagServiceResponseType},
        service_ids,
        util::tokio_ext,
    };
    use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
    use tokio::sync::RwLock;

    use crate::{
        UdsManager,
        test_helpers::{TestEcuDb, TestGateway},
        types::ResetType,
    };

    const ECU: &str = "TestECU";
    const POSITIVE: u8 = service_ids::AUTHENTICATION | cda_interfaces::UDS_ID_RESPONSE_BITMASK;

    fn plugin() -> DynamicPlugin {
        Box::new(())
    }

    /// Builds a manager whose gateway answers every request with `response`
    /// and counts the requests.
    fn manager(response: Vec<u8>) -> (UdsManager<TestGateway, TestEcuDb>, Arc<AtomicUsize>) {
        let sent = Arc::new(AtomicUsize::new(0));
        let sent_clone = Arc::clone(&sent);
        let gateway = TestGateway {
            send_fn: Arc::new(move |response_tx, _| {
                sent_clone.fetch_add(1, Ordering::SeqCst);
                let msg = TransportResponse::UdsResponse(ServicePayload {
                    data: response.clone(),
                    source_address: 0x0001,
                    target_address: 0x0E00,
                    new_session: None,
                    new_security: None,
                });
                response_tx.try_send(Ok(Some(msg))).ok();
                Ok(())
            }),
        };
        let ecus = Arc::new(HashMap::from_iter([(
            ECU.to_owned(),
            RwLock::new(TestEcuDb::new()),
        )]));
        (
            UdsManager::new_for_raw_payload_tests(
                gateway,
                ecus,
                FaultConfig::default(),
                enabled_communication_access_for_test(),
            ),
            sent,
        )
    }

    async fn state(manager: &UdsManager<TestGateway, TestEcuDb>) -> AuthenticationState {
        manager.get_ecu_authentication_state(ECU).await.unwrap()
    }

    async fn set_state(manager: &UdsManager<TestGateway, TestEcuDb>, state: AuthenticationState) {
        manager
            .uds_ecu_db(ECU)
            .unwrap()
            .read()
            .await
            .set_authentication_state(state);
    }

    fn authenticated() -> AuthenticationState {
        AuthenticationState {
            status: AuthenticationStatus::Authenticated,
            last_subfunction: Some(AuthenticationSubFunction::VerifyProofOfOwnershipBidirectional),
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn completed_authentication_sets_state_and_expiration() {
        let (manager, _) = manager(vec![POSITIVE, 0x07, 0x12]);

        let response = manager
            .authenticate(
                ECU,
                AuthenticationSubFunction::VerifyProofOfOwnershipBidirectional,
                None,
                &plugin(),
                Some(Duration::from_secs(60)),
            )
            .await
            .unwrap();

        assert_eq!(response.response_type(), DiagServiceResponseType::Positive);
        let state = state(&manager).await;
        assert!(state.is_authenticated());
        assert_eq!(
            state.last_subfunction,
            Some(AuthenticationSubFunction::VerifyProofOfOwnershipBidirectional)
        );
        assert!(state.expires_at.is_some());
        assert!(
            manager
                .authentication_reset_tasks
                .read()
                .await
                .contains_key(ECU)
        );
    }

    #[tokio::test]
    async fn completed_authentication_without_expiration_cancels_timer() {
        let (manager, _) = manager(vec![POSITIVE, 0x07, 0x12]);
        let sf = AuthenticationSubFunction::VerifyProofOfOwnershipBidirectional;
        manager
            .authenticate(ECU, sf, None, &plugin(), Some(Duration::from_secs(60)))
            .await
            .unwrap();
        manager
            .authenticate(ECU, sf, None, &plugin(), None)
            .await
            .unwrap();

        assert!(manager.authentication_reset_tasks.read().await.is_empty());
        assert!(state(&manager).await.expires_at.is_none());
    }

    #[tokio::test]
    async fn certificate_verified_completes_authentication() {
        let (manager, _) = manager(vec![POSITIVE, 0x02, 0x13]);
        manager
            .authenticate(
                ECU,
                AuthenticationSubFunction::VerifyCertificateBidirectional,
                None,
                &plugin(),
                None,
            )
            .await
            .unwrap();
        assert!(state(&manager).await.is_authenticated());
    }

    #[tokio::test]
    async fn transmit_certificate_does_not_authenticate_or_start_expiration() {
        let (manager, _) = manager(vec![POSITIVE, 0x04, 0x13]);
        manager
            .authenticate(
                ECU,
                AuthenticationSubFunction::TransmitCertificate,
                None,
                &plugin(),
                Some(Duration::from_secs(60)),
            )
            .await
            .unwrap();

        let state = state(&manager).await;
        assert_eq!(state.status, AuthenticationStatus::DeAuthenticated);
        assert_eq!(
            state.last_subfunction,
            Some(AuthenticationSubFunction::TransmitCertificate)
        );
        assert!(state.expires_at.is_none());
        assert!(manager.authentication_reset_tasks.read().await.is_empty());
    }

    #[tokio::test]
    async fn intermediate_step_does_not_authenticate() {
        // 0x11: CertificateVerified, OwnershipVerificationNecessary
        let (manager, _) = manager(vec![POSITIVE, 0x02, 0x11]);
        manager
            .authenticate(
                ECU,
                AuthenticationSubFunction::VerifyCertificateBidirectional,
                None,
                &plugin(),
                Some(Duration::from_secs(60)),
            )
            .await
            .unwrap();

        let state = state(&manager).await;
        assert_eq!(state.status, AuthenticationStatus::DeAuthenticated);
        assert_eq!(
            state.last_subfunction,
            Some(AuthenticationSubFunction::VerifyCertificateBidirectional)
        );
        assert!(manager.authentication_reset_tasks.read().await.is_empty());
    }

    #[tokio::test]
    async fn intermediate_step_keeps_authenticated_state() {
        let (manager, _) = manager(vec![POSITIVE, 0x08, 0x02]);
        set_state(&manager, authenticated()).await;
        manager
            .authenticate(
                ECU,
                AuthenticationSubFunction::AuthenticationConfiguration,
                None,
                &plugin(),
                None,
            )
            .await
            .unwrap();
        assert!(state(&manager).await.is_authenticated());
    }

    #[tokio::test]
    async fn negative_response_keeps_state_and_expiration() {
        let (manager, _) = manager(vec![service_ids::NEGATIVE_RESPONSE, 0x29, 0x58]);
        set_state(&manager, authenticated()).await;
        manager
            .start_reset_task(
                ECU,
                Some(Duration::from_secs(60)),
                ResetType::Authentication,
            )
            .await;

        let response = manager
            .authenticate(
                ECU,
                AuthenticationSubFunction::VerifyProofOfOwnershipBidirectional,
                None,
                &plugin(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(response.response_type(), DiagServiceResponseType::Negative);
        assert_eq!(state(&manager).await, authenticated());
        assert!(
            manager
                .authentication_reset_tasks
                .read()
                .await
                .contains_key(ECU)
        );
    }

    /// After a rejected authentication attempt the cleanup still deauthenticates.
    #[tokio::test]
    async fn reset_after_negative_response_sends_deauthenticate() {
        let (manager, sent) = manager(vec![service_ids::NEGATIVE_RESPONSE, 0x29, 0x22]);
        set_state(&manager, authenticated()).await;

        manager
            .authenticate(
                ECU,
                AuthenticationSubFunction::AuthenticationConfiguration,
                None,
                &plugin(),
                None,
            )
            .await
            .unwrap();
        let _ = manager.reset_ecu_authentication(ECU).await;

        assert_eq!(sent.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn deauthenticate_with_expiration_is_rejected() {
        let (manager, sent) = manager(vec![POSITIVE, 0x00, 0x10]);
        let result = manager
            .authenticate(
                ECU,
                AuthenticationSubFunction::DeAuthenticate,
                None,
                &plugin(),
                Some(Duration::from_secs(1)),
            )
            .await;
        assert!(matches!(result, Err(DiagServiceError::InvalidRequest(_))));
        assert_eq!(sent.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn reset_sends_deauthenticate_when_authenticated() {
        let (manager, sent) = manager(vec![POSITIVE, 0x00, 0x10]);
        set_state(&manager, authenticated()).await;

        let outcome = manager.reset_ecu_authentication(ECU).await.unwrap();

        assert_eq!(outcome, ResetOutcome::Completed);
        assert_eq!(sent.load(Ordering::SeqCst), 1);
        let state = state(&manager).await;
        assert_eq!(state.status, AuthenticationStatus::DeAuthenticated);
        assert_eq!(
            state.last_subfunction,
            Some(AuthenticationSubFunction::DeAuthenticate)
        );
    }

    #[tokio::test]
    async fn reset_is_noop_when_not_authenticated() {
        let (manager, sent) = manager(vec![POSITIVE, 0x00, 0x10]);
        let outcome = manager.reset_ecu_authentication(ECU).await.unwrap();
        assert_eq!(outcome, ResetOutcome::Completed);
        assert_eq!(sent.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn failed_reset_keeps_state_and_is_retried() {
        // NRC 0x5D deAuthenticationFailed
        let (manager, sent) = manager(vec![service_ids::NEGATIVE_RESPONSE, 0x29, 0x5D]);
        set_state(&manager, authenticated()).await;

        let result = manager.reset_ecu_authentication(ECU).await;

        assert!(matches!(
            result,
            Err(DiagServiceError::UnexpectedResponse(_))
        ));
        assert_eq!(state(&manager).await, authenticated());

        // The next cleanup tries again.
        let _ = manager.reset_ecu_authentication(ECU).await;
        assert_eq!(sent.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn expiration_sends_deauthenticate() {
        // The ECU answers every request with this, the return value 0x12 also
        // marks the authentication as completed; deAuthenticate ignores it.
        let (manager, sent) = manager(vec![POSITIVE, 0x07, 0x12]);
        manager
            .authenticate(
                ECU,
                AuthenticationSubFunction::VerifyProofOfOwnershipBidirectional,
                None,
                &plugin(),
                Some(Duration::from_millis(20)),
            )
            .await
            .unwrap();

        for _ in 0..100 {
            if !state(&manager).await.is_authenticated() {
                break;
            }
            tokio_ext::sleep_for(Duration::from_millis(10)).await;
        }

        assert_eq!(
            state(&manager).await.status,
            AuthenticationStatus::DeAuthenticated
        );
        assert_eq!(sent.load(Ordering::SeqCst), 2);
    }
}
