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

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use cda_interfaces::{
    Connectivity, DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, EcuState,
    PayloadDecoder, PendingNrc, ServicePayload, TransmissionParameters, TransportResponse,
    UdsTransport, UdsVariant, VariantDetection, VariantState, datatypes::RetryPolicy,
    diagservices::UdsPayloadData, dlt_ctx, service_ids,
};
use tokio::sync::{RwLock, Semaphore, mpsc};

use crate::{UdsEcuDb, UdsManager, types::UdsParameters};

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    #[tracing::instrument(
        skip(self, service, payload),
        fields(
            ecu_name,
            service_name = %service.name,
            has_payload = payload.is_some(),
            dlt_context = dlt_ctx!("UDS")
        )
    )]
    pub(crate) async fn send_with_optional_timeout(
        &self,
        ecu_name: &str,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
        timeout: Option<Duration>,
    ) -> Result<<T as PayloadDecoder>::Response, DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name)?;

        // Pre-send: run variant detection when required (see
        // `needs_variant_detection`). Detection also acts as a reachability
        // probe for ECUs marked Offline.
        {
            let status = ecu.read().await.ecu_status();
            if needs_variant_detection(&status) {
                tracing::info!(
                    ecu_name,
                    connectivity = ?status.connectivity,
                    variant_state = ?status.variant_state,
                    "Triggering variant detection before send"
                );
                if let Err(e) = self.detect_variant(ecu_name).await {
                    tracing::warn!(
                        ecu_name,
                        error = %e,
                        "Pre-send variant detection failed"
                    );
                }

                // Detection doubles as a reachability probe: if the ECU is still
                // Offline afterwards, the actual send is doomed to time out as
                // well - fail fast instead of waiting for a second timeout.
                if ecu.read().await.ecu_status().connectivity == Connectivity::Offline {
                    return Err(DiagServiceError::EcuOffline(ecu_name.to_owned()));
                }
            }
        }

        self.send_without_variant_guard(
            ecu_name,
            service,
            security_plugin,
            payload,
            map_to_json,
            timeout,
        )
        .await
    }

    /// Inner send path that skips the variant detection guard.
    /// Used by `detect_variant` to avoid infinite recursion.
    pub(crate) async fn send_without_variant_guard(
        &self,
        ecu_name: &str,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
        timeout: Option<Duration>,
    ) -> Result<<T as PayloadDecoder>::Response, DiagServiceError> {
        let start = Instant::now();
        tracing::debug!(
            service = ?service,
            payload = ?payload.as_ref()
                .map(ToString::to_string),
            "Sending UDS request"
        );
        let ecu = self.uds_ecu_db(ecu_name)?;

        let payload = {
            let ecu = ecu.read().await;
            ecu.create_uds_payload(&service, security_plugin, payload, None)
                .await?
        };

        let payload_build_after = start.elapsed();

        let response = self
            .send_with_raw_payload(ecu_name, payload.clone(), timeout, true)
            .await;
        let response_after = start.elapsed().saturating_sub(payload_build_after);

        let response = match response {
            Ok(msg) => {
                self.uds_ecu_db(ecu_name)
                    .expect("ECU name has been already checked")
                    .read()
                    .await
                    .convert_from_uds(
                        &service,
                        &msg.expect("response expected"),
                        map_to_json,
                        None,
                    )
                    .await
            }
            Err(e) => Err(e),
        };

        let response_mapped = start
            .elapsed()
            .saturating_sub(payload_build_after)
            .saturating_sub(response_after);
        tracing::debug!(
            total_duration = ?start.elapsed(),
            payload_build_duration = ?payload_build_after,
            response_duration = ?response_after,
            mapping_duration = ?response_mapped,
            "UDS request timing breakdown"
        );

        response
    }
}

impl<S: EcuGateway, T: UdsEcuDb + VariantDetection> UdsManager<S, T> {
    #[allow(
        clippy::needless_continue,
        reason = "Explicit continue improves readability to make it clearer, which loop is being \
                  continued"
    )]
    #[allow(
        clippy::too_many_lines,
        reason = "Splitting the send/receive flow would reduce readability"
    )]
    #[tracing::instrument(
        skip(self, payload),
        fields(ecu_name,
            expect_response,
            payload_size = payload.data.len(),
            dlt_context = dlt_ctx!("UDS"))
    )]
    pub(crate) async fn send_with_raw_payload(
        &self,
        ecu_name: &str,
        payload: ServicePayload,
        timeout: Option<Duration>,
        expect_response: bool,
    ) -> Result<Option<ServicePayload>, DiagServiceError> {
        // todo: do we need to ensure that we do not send here
        // when we have an ongoing data transfer as well?
        let start = std::time::Instant::now();

        let ecu = self.uds_ecu_db(ecu_name)?;
        let (uds_params, transmission_params) = Self::ecu_send_params(ecu).await;
        let sent_sid = *payload.data.first().ok_or(DiagServiceError::BadPayload(
            "Cannot sent message without SID".to_owned(),
        ))?;
        let ecu_sem_key = ecu.read().await.request_lock_key();

        let semaphore = {
            Arc::clone(
                self.ecu_semaphores
                    .lock()
                    .await
                    .entry(ecu_sem_key.clone())
                    .or_insert_with(|| Arc::new(Semaphore::new(1))),
            )
        };

        // todo: what timeout should we use to wait till the ecu is 'free'?
        let ecu_sem = tokio::time::timeout(Duration::from_secs(10), semaphore.acquire())
            .await
            .map_err(|_| {
                tracing::error!(
                    ecu = ecu_name,
                    request_lock_key = %ecu_sem_key,
                    "Timeout waiting for ecu to become available for requests."
                );
                DiagServiceError::Timeout
            })?;

        let rx_timeout = timeout.unwrap_or(uds_params.timeout_default);
        let mut rx_timeout_next = None;

        // outer loop to retry sending frames, resend frames must deal with (N)ACK again
        let (response_tx, mut response_rx) = mpsc::channel(2);
        let (response, sent_after) = 'send: loop {
            self.gateway
                .send(
                    transmission_params.clone(),
                    payload.clone(),
                    response_tx.clone(),
                    expect_response,
                )
                .await?;
            let sent_after = start.elapsed();

            // responses might be disabled, i.e. for functional tester presents...
            if !expect_response {
                // ...but wait until the message was (n)ack'd
                response_rx.recv().await;
                return Ok(None);
            }

            // inner loop, deals with UDS frames only, i.e. used to read repeated frames
            // for response pending, without sending a new frame in between.
            let uds_result = 'read_uds_messages: loop {
                match tokio::time::timeout(
                    rx_timeout_next.unwrap_or(rx_timeout),
                    response_rx.recv(),
                )
                .await
                {
                    Ok(Some(result)) => match result {
                        Ok(Some(TransportResponse::UdsResponse(msg))) => {
                            // if we received a response matching our sent SID, return it
                            // other responses are logged as warnings and ignored.
                            if !msg.data.is_empty() && msg.is_response_for_sid(sent_sid) {
                                // Validate that echo bytes (e.g. DID) in the response
                                // match those in the request (ISO 14229-1).
                                if !msg.has_matching_echo_bytes(&payload.data) {
                                    tracing::warn!(
                                        "Response has correct SID but mismatched echo bytes (e.g. \
                                         DID). Request: {:02X?}, Response: {:02X?}",
                                        payload.data,
                                        msg.data
                                    );
                                    continue 'read_uds_messages;
                                }
                                tracing::debug!("Received expected UDS message: {:?}", msg);
                                break 'read_uds_messages Ok(msg);
                            }
                            tracing::warn!("Received unexpected UDS message: {:?}", msg);
                        }
                        Ok(Some(TransportResponse::Pending(pending))) => match pending {
                            PendingNrc::BusyRepeatRequest { .. } => {
                                if let Err(e) = validate_timeout_by_policy(
                                    ecu_name,
                                    &uds_params.rc_21_retry_policy,
                                    &start.elapsed(),
                                    &uds_params.rc_21_completion_timeout,
                                ) {
                                    break 'read_uds_messages Err(e);
                                }
                                let sleep_time = uds_params.rc_21_repeat_request_time;
                                tracing::debug!(
                                    sleep_time = ?sleep_time,
                                    "BusyRepeatRequest received, resending after delay"
                                );
                                cda_interfaces::util::tokio_ext::sleep_for(sleep_time).await;
                                continue 'send; // continue 'send, will resend the message
                            }
                            PendingNrc::TemporarilyNotAvailable { .. } => {
                                if let Err(e) = validate_timeout_by_policy(
                                    ecu_name,
                                    &uds_params.rc_94_retry_policy,
                                    &start.elapsed(),
                                    &uds_params.rc_94_completion_timeout,
                                ) {
                                    break 'read_uds_messages Err(e);
                                }
                                let sleep_time = uds_params.rc_94_repeat_request_time;
                                tracing::debug!(
                                    sleep_time = ?sleep_time,
                                    "TemporarilyNotAvailable received, resending after delay"
                                );
                                cda_interfaces::util::tokio_ext::sleep_for(sleep_time).await;
                                continue 'send; // continue 'send, will resend the message
                            }
                            PendingNrc::ResponsePending { .. } => {
                                if let Err(e) = validate_timeout_by_policy(
                                    ecu_name,
                                    &uds_params.rc_78_retry_policy,
                                    &start.elapsed(),
                                    &uds_params.rc_78_completion_timeout,
                                ) {
                                    break 'read_uds_messages Err(e);
                                }
                                tracing::debug!(
                                    "ResponsePending received, continue waiting for final response"
                                );
                                rx_timeout_next = Some(uds_params.rc_78_timeout);
                                continue 'read_uds_messages; // continue reading UDS frames
                            }
                        },
                        Ok(response) => {
                            break 'read_uds_messages Err(DiagServiceError::UnexpectedResponse(
                                Some(format!("Unexpected response received: {response:?}")),
                            ));
                        }
                        Err(e) => {
                            tracing::debug!(
                                error = ?e,
                                "Error receiving UDS response from gateway"
                            );
                            // i.e. happens when the response is a NACK
                            // or no (n)ack was received before timeout.
                            // The Gateway will handle these cases and only
                            // return this error if there is no recovery path left.
                            // The UdsManager cannot do anything else, so we
                            // just forward the error to the caller.
                            break 'read_uds_messages Err(e);
                        }
                    },
                    Ok(None) => {
                        tracing::warn!("None response received");
                        break 'read_uds_messages Err(DiagServiceError::UnexpectedResponse(Some(
                            "None response received".to_owned(),
                        )));
                    }
                    Err(_) => {
                        // error means the tokio::time::timeout
                        // elapsed before a response was received
                        tracing::debug!(
                            "Timeout waiting for UDS response from gateway after {:?}",
                            rx_timeout_next.unwrap_or(rx_timeout)
                        );
                        break 'read_uds_messages Err(DiagServiceError::Timeout);
                    }
                }
            };
            tracing::debug!("Finished reading UDS messages from gateway");
            break 'send (uds_result, sent_after);
        };
        drop(response_rx);
        drop(ecu_sem);

        // Post-send: if a service send (not tester present) timed out,
        // the ECU is unreachable - notify the coordinator.
        // The coordinator will suppress this if variant detection is in progress.
        if matches!(response, Err(DiagServiceError::Timeout))
            && sent_sid != service_ids::TESTER_PRESENT
        {
            self.state_coordinator
                .handle_ecu_disconnected(ecu_name)
                .await;
        }

        if let Ok(ref msg) = response
            && msg.is_positive_response_for_sid(sent_sid)
        {
            let ecu_mgr = self
                .uds_ecu_db(ecu_name)
                .expect("ECU name has been already checked");
            let ecu_read = ecu_mgr.read().await;
            if let Some(new_session) = payload.new_session {
                ecu_read
                    .set_service_state(service_ids::SESSION_CONTROL, new_session)
                    .await;
            }
            if let Some(new_security) = payload.new_security {
                ecu_read
                    .set_service_state(service_ids::SECURITY_ACCESS, new_security)
                    .await;
            }
        }

        let finish = start.elapsed().saturating_sub(sent_after);
        tracing::debug!(
            total_duration = ?start.elapsed(),
            send_duration = ?sent_after,
            receive_duration = ?finish,
            "Raw UDS request timing breakdown"
        );

        response.map(Option::from)
    }

    pub(crate) async fn ecu_send_params(
        ecu: &RwLock<T>,
    ) -> (UdsParameters, TransmissionParameters) {
        let (uds_params, transmission_params) = {
            let ecu = ecu.read().await;
            (
                UdsParameters {
                    timeout_default: ecu.timeout_default(),
                    rc_21_retry_policy: ecu.rc_21_retry_policy(),
                    rc_21_completion_timeout: ecu.rc_21_completion_timeout(),
                    rc_21_repeat_request_time: ecu.rc_21_repeat_request_time(),
                    rc_78_retry_policy: ecu.rc_78_retry_policy(),
                    rc_78_completion_timeout: ecu.rc_78_completion_timeout(),
                    rc_78_timeout: ecu.rc_78_timeout(),
                    rc_94_retry_policy: ecu.rc_94_retry_policy(),
                    rc_94_completion_timeout: ecu.rc_94_completion_timeout(),
                    rc_94_repeat_request_time: ecu.rc_94_repeat_request_time(),
                },
                TransmissionParameters {
                    gateway_address: ecu.logical_gateway_address(),
                    timeout_ack: ecu.diagnostic_ack_timeout(),
                    ecu_name: ecu.ecu_name(),
                    repeat_request_count_transmission: ecu.repeat_request_count_transmission(),
                },
            )
        };
        (uds_params, transmission_params)
    }
}

#[async_trait::async_trait]
impl<S: EcuGateway, T: EcuManager> UdsTransport for UdsManager<S, T> {
    type Response = <T as PayloadDecoder>::Response;

    async fn send_with_timeout(
        &self,
        ecu_name: &str,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
        timeout: Duration,
    ) -> Result<Self::Response, DiagServiceError> {
        self.send_with_optional_timeout(
            ecu_name,
            service,
            security_plugin,
            payload,
            map_to_json,
            Some(timeout),
        )
        .await
    }

    async fn send(
        &self,
        ecu_name: &str,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
    ) -> Result<Self::Response, DiagServiceError> {
        self.send_with_optional_timeout(
            ecu_name,
            service,
            security_plugin,
            payload,
            map_to_json,
            None,
        )
        .await
    }

    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    async fn send_genericservice(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        payload: Vec<u8>,
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>, DiagServiceError> {
        tracing::trace!(ecu_name = %ecu_name, payload = ?payload, "Sending raw UDS packet");

        let payload = self
            .uds_ecu_db(ecu_name)?
            .read()
            .await
            .check_genericservice(security_plugin, payload)
            .await?;

        match self
            .send_with_raw_payload(ecu_name, payload, timeout, true)
            .await?
        {
            Some(response) => Ok(response.data),
            None => Ok(Vec::new()),
        }
    }
}

/// Decide whether variant detection must run before sending a UDS request.
///
/// Detection is required when
/// - the variant has not been tested yet (initial boot, or reconnect cleared
///   the variant to `NotTested`), or
/// - the ECU is `Offline` with a previously known variant state
///   (`Detected`/`NotDetected`). This covers ECUs behind a gateway: they share
///   the gateway's transport connection and never receive a per-ECU reconnect
///   event, so detection doubles as a reachability probe to bring them back
///   `Online`.
///
/// `Duplicate` ECUs are excluded: resolving a duplicate requires manual
/// intervention, re-running detection on every send would be pointless.
pub(crate) fn needs_variant_detection(status: &EcuState) -> bool {
    matches!(status.variant_state, VariantState::NotTested)
        || (status.connectivity == Connectivity::Offline
            && matches!(
                status.variant_state,
                VariantState::Detected { .. } | VariantState::NotDetected
            ))
}

#[tracing::instrument(skip_all,
    fields(dlt_context = dlt_ctx!("UDS"))
)]
pub(crate) fn validate_timeout_by_policy(
    ecu_name: &str,
    policy: &RetryPolicy,
    elapsed: &Duration,
    completion_timeout: &Duration,
) -> Result<(), DiagServiceError> {
    match policy {
        RetryPolicy::Disabled => {
            tracing::debug!(ecu_name = %ecu_name, "Disabled busy repeat policy, aborting");
            Err(DiagServiceError::Timeout)
        }
        RetryPolicy::ContinueUntilTimeout => {
            if elapsed > completion_timeout {
                tracing::warn!(ecu_name = %ecu_name, "Busy repeat took too long, aborting");
                Err(DiagServiceError::Timeout)
            } else {
                tracing::debug!(ecu_name = %ecu_name, "Received busy repeat request, retrying");
                Ok(())
            }
        }
        RetryPolicy::ContinueUnlimited => {
            tracing::debug!(
                ecu_name = %ecu_name,
                "Received busy repeat request, retrying with unlimited retries"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use cda_interfaces::datatypes::RetryPolicy;

    use super::*;

    #[test]
    fn test_validate_timeout_by_policy_disabled() {
        let result = validate_timeout_by_policy(
            "ECU1",
            &RetryPolicy::Disabled,
            &Duration::from_secs(1),
            &Duration::from_secs(5),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_timeout_by_policy_continue_until_timeout_not_expired() {
        let result = validate_timeout_by_policy(
            "ECU1",
            &RetryPolicy::ContinueUntilTimeout,
            &Duration::from_secs(1),
            &Duration::from_secs(5),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_timeout_by_policy_continue_until_timeout_expired() {
        let result = validate_timeout_by_policy(
            "ECU1",
            &RetryPolicy::ContinueUntilTimeout,
            &Duration::from_secs(10),
            &Duration::from_secs(5),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_timeout_by_policy_continue_until_timeout_equal() {
        let result = validate_timeout_by_policy(
            "ECU1",
            &RetryPolicy::ContinueUntilTimeout,
            &Duration::from_secs(5),
            &Duration::from_secs(5),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_timeout_by_policy_continue_unlimited() {
        let result = validate_timeout_by_policy(
            "ECU1",
            &RetryPolicy::ContinueUnlimited,
            &Duration::from_secs(100),
            &Duration::from_secs(1),
        );
        assert!(result.is_ok());
    }

    fn ecu_state(connectivity: Connectivity, variant_state: VariantState) -> EcuState {
        EcuState {
            connectivity,
            variant_state,
            variant_index: None,
        }
    }

    fn detected_variant() -> VariantState {
        VariantState::Detected {
            name: "TestVariant".to_owned(),
            is_base_variant: false,
            is_fallback: false,
        }
    }

    #[test]
    fn test_needs_variant_detection_not_tested() {
        // NotTested always triggers detection, regardless of connectivity.
        assert!(needs_variant_detection(&ecu_state(
            Connectivity::Online,
            VariantState::NotTested
        )));
        assert!(needs_variant_detection(&ecu_state(
            Connectivity::Offline,
            VariantState::NotTested
        )));
    }

    #[test]
    fn test_needs_variant_detection_offline_with_known_variant() {
        // Offline ECUs with a previously known variant state must be re-probed.
        // This is the recovery path for ECUs behind a gateway, which never
        // receive a per-ECU reconnect event.
        assert!(needs_variant_detection(&ecu_state(
            Connectivity::Offline,
            detected_variant()
        )));
        assert!(needs_variant_detection(&ecu_state(
            Connectivity::Offline,
            VariantState::NotDetected
        )));
    }

    #[test]
    fn test_needs_variant_detection_online_skips_detection() {
        assert!(!needs_variant_detection(&ecu_state(
            Connectivity::Online,
            detected_variant()
        )));
        assert!(!needs_variant_detection(&ecu_state(
            Connectivity::Online,
            VariantState::NotDetected
        )));
    }

    #[test]
    fn test_needs_variant_detection_duplicate_never_triggers() {
        // Duplicates require manual resolution, no automatic re-detection.
        assert!(!needs_variant_detection(&ecu_state(
            Connectivity::Online,
            VariantState::Duplicate
        )));
        assert!(!needs_variant_detection(&ecu_state(
            Connectivity::Offline,
            VariantState::Duplicate
        )));
    }
}

#[cfg(test)]
mod send_tests {
    use std::{
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use cda_interfaces::{
        DiagServiceError, EcuAddresses, EcuGateway, EcuRuntimeState, EcuStateManager,
        FunctionalTransport, HashMap, HashMapExtensions, NetworkTopology, PendingNrc,
        PhysicalTransport, ServicePayload, TransmissionParameters, TransportResponse,
        VariantDetection, datatypes::FaultConfig,
    };
    use tokio::sync::{RwLock, mpsc};

    use crate::{
        UdsEcuDb, UdsManager, state_coordinator::EcuStateCoordinator, test_helpers::TestEcuDb,
    };

    impl<S: EcuGateway, T: UdsEcuDb + VariantDetection + EcuAddresses> UdsManager<S, T> {
        /// Test-only constructor that creates a `UdsManager` without spawning
        /// background tasks (variant detection, etc.), so `T` only needs the
        /// narrower trait bounds required by `send_with_raw_payload`.
        fn new_for_raw_payload_tests(
            gateway: S,
            ecus: Arc<HashMap<String, RwLock<T>>>,
            fault_config: FaultConfig,
            update_in_progress: Arc<AtomicBool>,
        ) -> Self {
            let runtime_states: HashMap<String, EcuRuntimeState> = ecus
                .keys()
                .map(|name| (name.clone(), EcuRuntimeState::new()))
                .collect();
            let (redetect_tx, _redetect_rx) = tokio::sync::mpsc::channel(8);
            let state_coordinator = EcuStateCoordinator::new(runtime_states, redetect_tx);
            Self {
                ecus,
                gateway,
                data_transfers: Arc::new(tokio::sync::Mutex::new(HashMap::default())),
                ecu_semaphores: Arc::new(tokio::sync::Mutex::new(HashMap::default())),
                tester_present_tasks: Arc::new(RwLock::new(HashMap::default())),
                session_reset_tasks: Arc::new(RwLock::new(HashMap::default())),
                security_reset_tasks: Arc::new(RwLock::new(HashMap::default())),
                state_coordinator,
                functional_description_database: String::new(),
                fault_config,
                update_in_progress,
            }
        }
    }

    /// A test gateway whose `send` behavior is configurable via a closure.
    #[derive(Clone)]
    struct TestGateway {
        send_fn: Arc<TestGatewaySendFn>,
    }

    type TestGatewaySendFn = dyn Fn(
            mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
            bool,
        ) -> Result<(), DiagServiceError>
        + Send
        + Sync;

    impl PhysicalTransport for TestGateway {
        async fn shutdown(&mut self) {}

        fn send(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
            expect_uds_reply: bool,
        ) -> impl Future<Output = Result<(), DiagServiceError>> + Send {
            let result = (self.send_fn)(response_sender, expect_uds_reply);
            async move { result }
        }

        async fn ecu_online<T: EcuAddresses>(
            &self,
            _ecu_name: &str,
            _ecu_db: &RwLock<T>,
        ) -> Result<(), DiagServiceError> {
            Ok(())
        }
    }

    impl FunctionalTransport for TestGateway {
        async fn send_functional(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            _expected_ecu_logical_addrs: HashMap<u16, String>,
            _timeout: Duration,
            _expect_positive_response: bool,
        ) -> Result<HashMap<String, Result<ServicePayload, DiagServiceError>>, DiagServiceError>
        {
            Ok(HashMap::new())
        }
    }

    impl NetworkTopology for TestGateway {
        async fn get_gateway_network_address(&self, _logical_address: u16) -> Option<String> {
            None
        }
    }

    // Test helpers

    fn make_test_payload(sid: u8, data: &[u8]) -> ServicePayload {
        let mut payload_data = vec![sid];
        payload_data.extend_from_slice(data);
        ServicePayload {
            data: payload_data,
            source_address: 0x0E00,
            target_address: 0x0001,
            new_session: None,
            new_security: None,
        }
    }

    fn make_manager(gateway: TestGateway) -> UdsManager<TestGateway, TestEcuDb> {
        let ecus = Arc::new(HashMap::from_iter([(
            "TestECU".to_string(),
            RwLock::new(TestEcuDb::new()),
        )]));
        UdsManager::new_for_raw_payload_tests(
            gateway,
            ecus,
            FaultConfig::default(),
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn make_manager_no_ecus(gateway: TestGateway) -> UdsManager<TestGateway, TestEcuDb> {
        let ecus = Arc::new(HashMap::new());
        UdsManager::new_for_raw_payload_tests(
            gateway,
            ecus,
            FaultConfig::default(),
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn make_gateway() -> TestGateway {
        TestGateway {
            send_fn: Arc::new(|response_tx, _| {
                let msg = TransportResponse::UdsResponse(ServicePayload {
                    data: vec![0x50, 0x01],
                    source_address: 0x0001,
                    target_address: 0x0E00,
                    new_session: None,
                    new_security: None,
                });
                response_tx.try_send(Ok(Some(msg))).ok();
                Ok(())
            }),
        }
    }

    // Tests

    #[tokio::test]
    async fn test_send_with_raw_payload_positive_response() {
        let gateway = make_gateway();
        let manager = make_manager(gateway);
        let payload = make_test_payload(0x10, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

        assert!(result.is_ok());
        let response = result.expect("should be Ok");
        assert!(response.is_some());
        let msg = response.expect("should have message");
        assert_eq!(msg.data, vec![0x50, 0x01]);
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_no_response_expected() {
        let gateway = TestGateway {
            send_fn: Arc::new(|response_tx, _| {
                // Gateway sends an ack (None) indicating message was sent
                response_tx.try_send(Ok(None)).ok();
                Ok(())
            }),
        };
        let manager = make_manager(gateway);
        let payload = make_test_payload(0x10, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, false)
            .await;

        assert!(result.is_ok());
        assert!(result.expect("should be Ok").is_none());
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_ecu_not_found() {
        let gateway = TestGateway {
            send_fn: Arc::new(|_, _| Ok(())),
        };
        let manager = make_manager_no_ecus(gateway);
        let payload = make_test_payload(0x10, &[0x01]);

        let result = manager
            .send_with_raw_payload("NonExistent", payload, None, true)
            .await;

        assert!(result.is_err());
        assert!(
            matches!(result, Err(DiagServiceError::NotFound(_))),
            "Expected NotFound error"
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_empty_payload_returns_bad_payload() {
        let gateway = TestGateway {
            send_fn: Arc::new(|_, _| Ok(())),
        };
        let manager = make_manager(gateway);
        let empty_payload = ServicePayload {
            data: vec![],
            source_address: 0x0E00,
            target_address: 0x0001,
            new_session: None,
            new_security: None,
        };

        let result = manager
            .send_with_raw_payload("TestECU", empty_payload, None, true)
            .await;

        assert!(result.is_err());
        assert!(
            matches!(result, Err(DiagServiceError::BadPayload(_))),
            "Expected BadPayload error"
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_gateway_send_error() {
        let gateway = TestGateway {
            send_fn: Arc::new(|_, _| Err(DiagServiceError::EcuOffline("TestECU".to_string()))),
        };
        let manager = make_manager(gateway);
        let payload = make_test_payload(0x10, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

        assert!(result.is_err());
        assert!(
            matches!(result, Err(DiagServiceError::EcuOffline(_))),
            "Expected EcuOffline error"
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_timeout() {
        let gateway = TestGateway {
            send_fn: Arc::new(|_response_tx, _| {
                // Don't send any response - channel will be empty, causing timeout
                Ok(())
            }),
        };
        let manager = make_manager(gateway);
        let payload = make_test_payload(0x10, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, Some(Duration::from_millis(50)), true)
            .await;

        assert!(result.is_err());
        assert!(
            matches!(result, Err(DiagServiceError::Timeout)),
            "Expected Timeout error"
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_busy_repeat_request_then_success() {
        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let gateway = TestGateway {
            send_fn: Arc::new(move |response_tx, _| {
                let count = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if count == 0 {
                    response_tx
                        .try_send(Ok(Some(TransportResponse::Pending(
                            PendingNrc::BusyRepeatRequest {
                                source_address: 0x0001,
                            },
                        ))))
                        .ok();
                } else {
                    let msg = TransportResponse::UdsResponse(ServicePayload {
                        data: vec![0x50, 0x01],
                        source_address: 0x0001,
                        target_address: 0x0E00,
                        new_session: None,
                        new_security: None,
                    });
                    response_tx.try_send(Ok(Some(msg))).ok();
                }
                Ok(())
            }),
        };
        let manager = make_manager(gateway);
        let payload = make_test_payload(0x10, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

        assert!(result.is_ok());
        let msg = result.expect("should be Ok").expect("should have message");
        assert_eq!(msg.data, vec![0x50, 0x01]);
        assert!(call_count.load(std::sync::atomic::Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_response_pending_then_success() {
        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let gateway = TestGateway {
            send_fn: Arc::new(move |response_tx, _| {
                let count = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if count == 0 {
                    // First send ResponsePending, then the actual message
                    response_tx
                        .try_send(Ok(Some(TransportResponse::Pending(
                            PendingNrc::ResponsePending {
                                source_address: 0x0001,
                            },
                        ))))
                        .ok();
                    response_tx
                        .try_send(Ok(Some(TransportResponse::UdsResponse(ServicePayload {
                            data: vec![0x50, 0x01],
                            source_address: 0x0001,
                            target_address: 0x0E00,
                            new_session: None,
                            new_security: None,
                        }))))
                        .ok();
                }
                Ok(())
            }),
        };
        let manager = make_manager(gateway);
        let payload = make_test_payload(0x10, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

        assert!(result.is_ok());
        let msg = result.expect("should be Ok").expect("should have message");
        assert_eq!(msg.data, vec![0x50, 0x01]);
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_temporarily_not_available_then_success() {
        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let gateway = TestGateway {
            send_fn: Arc::new(move |response_tx, _| {
                let count = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if count == 0 {
                    response_tx
                        .try_send(Ok(Some(TransportResponse::Pending(
                            PendingNrc::TemporarilyNotAvailable {
                                source_address: 0x0001,
                            },
                        ))))
                        .ok();
                } else {
                    let msg = TransportResponse::UdsResponse(ServicePayload {
                        data: vec![0x50, 0x01],
                        source_address: 0x0001,
                        target_address: 0x0E00,
                        new_session: None,
                        new_security: None,
                    });
                    response_tx.try_send(Ok(Some(msg))).ok();
                }
                Ok(())
            }),
        };
        let manager = make_manager(gateway);
        let payload = make_test_payload(0x10, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

        assert!(result.is_ok());
        let msg = result.expect("should be Ok").expect("should have message");
        assert_eq!(msg.data, vec![0x50, 0x01]);
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_negative_response() {
        let gateway = TestGateway {
            send_fn: Arc::new(|response_tx, _| {
                // NRC 0x7F, SID 0x10, NRC code 0x22 (conditionsNotCorrect)
                let msg = TransportResponse::UdsResponse(ServicePayload {
                    data: vec![0x7F, 0x10, 0x22],
                    source_address: 0x0001,
                    target_address: 0x0E00,
                    new_session: None,
                    new_security: None,
                });
                response_tx.try_send(Ok(Some(msg))).ok();
                Ok(())
            }),
        };
        let manager = make_manager(gateway);
        let payload = make_test_payload(0x10, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

        assert!(result.is_ok());
        let msg = result.expect("should be Ok").expect("should have message");
        // Negative response: 0x7F + original SID + NRC
        assert_eq!(msg.data, vec![0x7F, 0x10, 0x22]);
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_custom_timeout() {
        let gateway = make_gateway();
        let manager = make_manager(gateway);
        let payload = make_test_payload(0x10, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, Some(Duration::from_secs(1)), true)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_sets_session_state_on_positive_response() {
        let gateway = TestGateway {
            send_fn: Arc::new(|response_tx, _| {
                let msg = TransportResponse::UdsResponse(ServicePayload {
                    data: vec![0x50, 0x03],
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
            "TestECU".to_string(),
            RwLock::new(TestEcuDb::new()),
        )]));
        let manager: UdsManager<TestGateway, TestEcuDb> = UdsManager::new_for_raw_payload_tests(
            gateway,
            Arc::clone(&ecus),
            FaultConfig::default(),
            Arc::new(AtomicBool::new(false)),
        );

        // Payload with new_session set - should be stored on positive response
        let payload = ServicePayload {
            data: vec![0x10, 0x03],
            source_address: 0x0E00,
            target_address: 0x0001,
            new_session: Some("extended".to_string()),
            new_security: None,
        };

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

        assert!(result.is_ok());

        // Verify the session state was stored
        let ecu = ecus.get("TestECU").expect("ECU should exist");
        let ecu_read = ecu.read().await;
        let session_state = ecu_read
            .get_service_state(cda_interfaces::service_ids::SESSION_CONTROL)
            .await;
        assert_eq!(session_state, Some("extended".to_string()));
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_channel_error() {
        let gateway = TestGateway {
            send_fn: Arc::new(|response_tx, _| {
                // Send an error through the channel
                response_tx
                    .try_send(Err(DiagServiceError::NoResponse("Test error".to_string())))
                    .ok();
                Ok(())
            }),
        };
        let manager = make_manager(gateway);
        let payload = make_test_payload(0x10, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

        assert!(result.is_err());
        assert!(
            matches!(result, Err(DiagServiceError::NoResponse(_))),
            "Expected NoResponse error"
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_mismatched_echo_bytes_skipped() {
        let gateway = TestGateway {
            send_fn: Arc::new(|response_tx, _| {
                // First: a message with correct SID response but wrong DID (echo bytes)
                // ReadDataByIdentifier (0x22) response SID is 0x62
                let wrong_did = TransportResponse::UdsResponse(ServicePayload {
                    data: vec![0x62, 0xF2, 0x00, 0xAA],
                    source_address: 0x0001,
                    target_address: 0x0E00,
                    new_session: None,
                    new_security: None,
                });
                response_tx.try_send(Ok(Some(wrong_did))).ok();
                // Then: the correct response with matching DID
                let correct = TransportResponse::UdsResponse(ServicePayload {
                    data: vec![0x62, 0xF1, 0x90, 0xBB],
                    source_address: 0x0001,
                    target_address: 0x0E00,
                    new_session: None,
                    new_security: None,
                });
                response_tx.try_send(Ok(Some(correct))).ok();
                Ok(())
            }),
        };
        let manager = make_manager(gateway);
        // ReadDataByIdentifier for DID 0xF190
        let payload = make_test_payload(0x22, &[0xF1, 0x90]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

        assert!(result.is_ok());
        let msg = result.expect("should be Ok").expect("should have message");
        // Should have received the second message (correct DID)
        assert_eq!(msg.data, vec![0x62, 0xF1, 0x90, 0xBB]);
    }
}
