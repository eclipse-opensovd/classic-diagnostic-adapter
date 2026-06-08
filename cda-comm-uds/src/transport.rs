/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use cda_interfaces::{
    DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, ServicePayload,
    TransmissionParameters, UdsResponse, UdsTransport,
    datatypes::RetryPolicy,
    diagservices::{DiagServiceResponse, UdsPayloadData},
    dlt_ctx, service_ids,
};
use tokio::sync::{RwLock, Semaphore, mpsc};

use crate::{UdsManager, types::UdsParameters};

impl<S: EcuGateway, R: DiagServiceResponse, T: EcuManager<Response = R>> UdsManager<S, R, T> {
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
    ) -> Result<R, DiagServiceError> {
        let start = Instant::now();
        tracing::debug!(
            service = ?service,
            payload = ?payload.as_ref()
                .map(std::string::ToString::to_string),
            "Sending UDS request"
        );
        let ecu = self.ecu_manager(ecu_name)?;
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
                self.ecu_manager(ecu_name)
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

    // allowed for clarity, to make it clearer which of the loops is being continued
    #[allow(clippy::needless_continue)]
    // allow too many lines, as it is better to keep this together for now
    #[allow(clippy::too_many_lines)]
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

        let ecu = self.ecu_manager(ecu_name)?;
        let (uds_params, transmission_params) = Self::ecu_send_params(ecu).await;
        let ecu_logical_address = ecu.read().await.logical_address();
        let sent_sid = *payload.data.first().ok_or(DiagServiceError::BadPayload(
            "Cannot sent message without SID".to_owned(),
        ))?;

        let semaphore = {
            Arc::clone(
                self.ecu_semaphores
                    .lock()
                    .await
                    .entry(ecu_logical_address)
                    .or_insert_with(|| Arc::new(Semaphore::new(1))),
            )
        };

        // todo: what timeout should we use to wait till the ecu is 'free'?
        let ecu_sem = tokio::time::timeout(Duration::from_secs(10), semaphore.acquire())
            .await
            .map_err(|_| {
                tracing::error!(
                    ecu = ecu_name,
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
                        Ok(Some(UdsResponse::Message(msg))) => {
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
                        Ok(Some(UdsResponse::BusyRepeatRequest(_))) => {
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
                        Ok(Some(UdsResponse::TemporarilyNotAvailable(_))) => {
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
                        Ok(Some(UdsResponse::ResponsePending(_))) => {
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

        if let Ok(ref msg) = response
            && msg.is_positive_response_for_sid(sent_sid)
        {
            let ecu_mgr = self
                .ecu_manager(ecu_name)
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
impl<S: EcuGateway, R: DiagServiceResponse, T: EcuManager<Response = R>> UdsTransport
    for UdsManager<S, R, T>
{
    type Response = R;

    async fn send_with_timeout(
        &self,
        ecu_name: &str,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
        timeout: Duration,
    ) -> Result<R, DiagServiceError> {
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
    ) -> Result<R, DiagServiceError> {
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
            .ecu_manager(ecu_name)?
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
}

#[cfg(test)]
mod send_tests {
    use std::{
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use cda_interfaces::{
        DiagComm, DiagServiceError, DynamicPlugin, EcuAddressProvider, EcuGateway, EcuManager,
        EcuSchemaProvider, EcuState, EcuVariant, FunctionalDescriptionConfig, HashMap,
        HashMapExtensions, HashSet, Protocol, SchemaDescription, SecurityAccess, ServicePayload,
        TransmissionParameters, UdsResponse,
        datatypes::{
            AddressingMode, ComplexComParamValue, ComponentConfigurationsInfo, ComponentDataInfo,
            ComponentOperationsInfo, DiagnosticServiceAffixPosition, DtcLookup,
            DtcReadInformationFunction, FaultConfig, RetryPolicy, RoutineSubfunctions, SdSdg,
            TesterPresentSendType, single_ecu,
        },
        diagservices::{
            DiagServiceJsonResponse, DiagServiceResponse, DiagServiceResponseType, MappedNRC,
            UdsPayloadData,
        },
    };
    use tokio::sync::{RwLock, mpsc};

    use crate::UdsManager;

    // Manual mock: DiagServiceResponse
    #[derive(Clone, Debug)]
    struct TestResponse {
        data: Vec<u8>,
    }

    impl DiagServiceResponse for TestResponse {
        fn is_empty(&self) -> bool {
            self.data.is_empty()
        }

        fn service_name(&self) -> String {
            "TestService".to_string()
        }

        fn get_raw(&self) -> &[u8] {
            &self.data
        }

        fn into_json(self) -> Result<DiagServiceJsonResponse, DiagServiceError> {
            unimplemented!()
        }

        fn as_nrc(&self) -> Result<MappedNRC, DiagServiceError> {
            unimplemented!()
        }

        fn get_dtcs(
            &self,
        ) -> Result<
            Vec<(
                cda_interfaces::datatypes::DtcField,
                cda_interfaces::datatypes::DtcRecord,
            )>,
            DiagServiceError,
        > {
            unimplemented!()
        }

        fn response_type(&self) -> DiagServiceResponseType {
            DiagServiceResponseType::Positive
        }
    }

    /// A test gateway whose `send` behavior is configurable via a closure.
    #[derive(Clone)]
    struct TestGateway {
        send_fn: Arc<TestGatewaySendFn>,
    }

    type TestGatewaySendFn = dyn Fn(
            mpsc::Sender<Result<Option<UdsResponse>, DiagServiceError>>,
            bool,
        ) -> Result<(), DiagServiceError>
        + Send
        + Sync;

    impl EcuGateway for TestGateway {
        async fn get_gateway_network_address(&self, _logical_address: u16) -> Option<String> {
            None
        }

        fn send(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            response_sender: mpsc::Sender<Result<Option<UdsResponse>, DiagServiceError>>,
            expect_uds_reply: bool,
        ) -> impl Future<Output = Result<(), DiagServiceError>> + Send {
            let result = (self.send_fn)(response_sender, expect_uds_reply);
            async move { result }
        }

        async fn ecu_online<T: EcuAddressProvider>(
            &self,
            _ecu_name: &str,
            _ecu_db: &RwLock<T>,
        ) -> Result<(), DiagServiceError> {
            Ok(())
        }

        async fn send_functional(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            _expected_ecu_logical_addrs: HashMap<u16, String>,
            _timeout: Duration,
            _expect_positive_response: bool,
        ) -> Result<HashMap<String, Result<UdsResponse, DiagServiceError>>, DiagServiceError>
        {
            Ok(HashMap::new())
        }
    }

    // Manual mock: EcuManager (TestEcuDb)

    /// Minimal `EcuManager` implementation for testing `send_with_raw_payload`.
    struct TestEcuDb {
        service_states: tokio::sync::Mutex<std::collections::HashMap<u8, String>>,
    }

    impl TestEcuDb {
        fn new() -> Self {
            Self {
                service_states: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }
    }

    // EcuAddressProvider
    impl EcuAddressProvider for TestEcuDb {
        fn tester_address(&self) -> u16 {
            0x0E00
        }
        fn logical_address(&self) -> u16 {
            0x0001
        }
        fn logical_gateway_address(&self) -> u16 {
            0x0000
        }
        fn logical_functional_address(&self) -> u16 {
            0xFFFF
        }
        fn ecu_name(&self) -> String {
            "TestECU".to_string()
        }
        fn logical_address_eq<T: EcuAddressProvider>(&self, other: &T) -> bool {
            self.logical_address() == other.logical_address()
        }
    }

    // DoipComParamProvider
    impl cda_interfaces::DoipComParamProvider for TestEcuDb {
        fn nack_number_of_retries(&self) -> &HashMap<u8, u32> {
            // Return a static reference by leaking - acceptable in tests only
            static EMPTY: std::sync::OnceLock<HashMap<u8, u32>> = std::sync::OnceLock::new();
            EMPTY.get_or_init(HashMap::new)
        }
        fn diagnostic_ack_timeout(&self) -> Duration {
            Duration::from_secs(2)
        }
        fn retry_period(&self) -> Duration {
            Duration::from_millis(100)
        }
        fn routing_activation_timeout(&self) -> Duration {
            Duration::from_secs(5)
        }
        fn repeat_request_count_transmission(&self) -> u32 {
            3
        }
        fn connection_timeout(&self) -> Duration {
            Duration::from_secs(5)
        }
        fn connection_retry_delay(&self) -> Duration {
            Duration::from_secs(1)
        }
        fn connection_retry_attempts(&self) -> u32 {
            3
        }
    }

    // UdsComParamProvider
    impl cda_interfaces::UdsComParamProvider for TestEcuDb {
        fn tester_present_retry_policy(&self) -> bool {
            false
        }
        fn tester_present_addr_mode(self) -> AddressingMode {
            unimplemented!()
        }
        fn tester_present_response_expected(self) -> bool {
            unimplemented!()
        }
        fn tester_present_send_type(self) -> TesterPresentSendType {
            unimplemented!()
        }
        fn tester_present_message(self) -> Vec<u8> {
            unimplemented!()
        }
        fn tester_present_exp_pos_resp(self) -> Vec<u8> {
            unimplemented!()
        }
        fn tester_present_exp_neg_resp(self) -> Vec<u8> {
            unimplemented!()
        }
        fn tester_present_time(&self) -> Duration {
            Duration::from_secs(2)
        }
        fn repeat_req_count_app(&self) -> u32 {
            3
        }
        fn rc_21_retry_policy(&self) -> RetryPolicy {
            RetryPolicy::ContinueUntilTimeout
        }
        fn rc_21_completion_timeout(&self) -> Duration {
            Duration::from_secs(10)
        }
        fn rc_21_repeat_request_time(&self) -> Duration {
            Duration::from_millis(10)
        }
        fn rc_78_retry_policy(&self) -> RetryPolicy {
            RetryPolicy::ContinueUntilTimeout
        }
        fn rc_78_completion_timeout(&self) -> Duration {
            Duration::from_secs(30)
        }
        fn rc_78_timeout(&self) -> Duration {
            Duration::from_secs(5)
        }
        fn rc_94_retry_policy(&self) -> RetryPolicy {
            RetryPolicy::ContinueUntilTimeout
        }
        fn rc_94_completion_timeout(&self) -> Duration {
            Duration::from_secs(10)
        }
        fn rc_94_repeat_request_time(&self) -> Duration {
            Duration::from_millis(10)
        }
        fn timeout_default(&self) -> Duration {
            Duration::from_secs(5)
        }
    }

    // EcuSchemaProvider
    impl EcuSchemaProvider for TestEcuDb {
        async fn schema_for_request(
            &self,
            _service: &DiagComm,
        ) -> Result<SchemaDescription, DiagServiceError> {
            unimplemented!()
        }
        async fn schema_for_responses(
            &self,
            _service: &DiagComm,
        ) -> Result<SchemaDescription, DiagServiceError> {
            unimplemented!()
        }
        async fn schema_for_fg_request(
            &self,
            _service: &DiagComm,
            _functional_group_name: &str,
        ) -> Result<SchemaDescription, DiagServiceError> {
            unimplemented!()
        }
    }

    // EcuManager
    impl EcuManager for TestEcuDb {
        type Response = TestResponse;

        fn is_physical_ecu(&self) -> bool {
            true
        }
        fn variant(&self) -> EcuVariant {
            EcuVariant {
                name: Some("TestVariant".to_string()),
                is_base_variant: true,
                is_fallback: false,
                state: EcuState::Online,
                logical_address: 0x0001,
            }
        }
        fn state(&self) -> EcuState {
            EcuState::Online
        }
        fn protocol(&self) -> &Protocol {
            // Leaked for test lifetime; acceptable in test code.
            static PROTO: std::sync::OnceLock<Protocol> = std::sync::OnceLock::new();
            PROTO.get_or_init(Protocol::default)
        }
        fn is_loaded(&self) -> bool {
            true
        }
        fn functional_groups(&self) -> Vec<String> {
            vec![]
        }
        fn set_duplicating_ecu_names(&mut self, _duplicate_ecus: HashSet<String>) {}
        fn duplicating_ecu_names(&self) -> Option<&HashSet<String>> {
            None
        }
        fn mark_as_duplicate(&mut self) {}
        fn mark_as_no_variant_detected(&mut self) {}
        fn load(&mut self) -> Result<(), DiagServiceError> {
            Ok(())
        }
        async fn detect_variant<V: DiagServiceResponse + Sized>(
            &mut self,
            _service_responses: HashMap<String, V>,
        ) -> Result<(), DiagServiceError> {
            Ok(())
        }
        fn get_variant_detection_requests(&self) -> &HashMap<String, DiagComm> {
            static EMPTY: std::sync::OnceLock<HashMap<String, DiagComm>> =
                std::sync::OnceLock::new();
            EMPTY.get_or_init(HashMap::new)
        }
        fn comparams(&self) -> Result<ComplexComParamValue, DiagServiceError> {
            unimplemented!()
        }
        async fn sdgs(&self, _service: Option<&DiagComm>) -> Result<Vec<SdSdg>, DiagServiceError> {
            Ok(vec![])
        }
        async fn convert_from_uds(
            &self,
            _diag_service: &DiagComm,
            _payload: &ServicePayload,
            _map_to_json: bool,
            _functional_group_name: Option<&str>,
        ) -> Result<Self::Response, DiagServiceError> {
            unimplemented!()
        }
        async fn check_genericservice(
            &self,
            _security_plugin: &DynamicPlugin,
            _rawdata: Vec<u8>,
        ) -> Result<ServicePayload, DiagServiceError> {
            unimplemented!()
        }
        async fn create_uds_payload(
            &self,
            _diag_service: &DiagComm,
            _security_plugin: &DynamicPlugin,
            _data: Option<UdsPayloadData>,
            _functional_group_name: Option<&str>,
        ) -> Result<ServicePayload, DiagServiceError> {
            unimplemented!()
        }
        async fn convert_request_from_uds(
            &self,
            _diag_service: &DiagComm,
            _payload: &ServicePayload,
            _map_to_json: bool,
        ) -> Result<Self::Response, DiagServiceError> {
            unimplemented!()
        }
        fn lookup_single_ecu_job(
            &self,
            _job_name: &str,
        ) -> Result<single_ecu::Job, DiagServiceError> {
            unimplemented!()
        }
        fn set_service_state(&self, sid: u8, value: String) -> impl Future<Output = ()> + Send {
            let states = &self.service_states;
            async move {
                states.lock().await.insert(sid, value);
            }
        }
        fn get_service_state(&self, sid: u8) -> impl Future<Output = Option<String>> + Send {
            let states = &self.service_states;
            async move { states.lock().await.get(&sid).cloned() }
        }
        async fn lookup_session_change(
            &self,
            _session: &str,
        ) -> Result<DiagComm, DiagServiceError> {
            unimplemented!()
        }
        async fn lookup_security_access_change(
            &self,
            _level: &str,
            _has_key: bool,
        ) -> Result<SecurityAccess, DiagServiceError> {
            unimplemented!()
        }
        async fn get_send_key_param_name(
            &self,
            _diag_service: &DiagComm,
        ) -> Result<String, DiagServiceError> {
            unimplemented!()
        }
        async fn session(&self) -> Result<String, DiagServiceError> {
            Ok("default".to_string())
        }
        fn default_session(&self) -> Result<String, DiagServiceError> {
            Ok("default".to_string())
        }
        async fn security_access(&self) -> Result<String, DiagServiceError> {
            Ok("locked".to_string())
        }
        fn default_security_access(&self) -> Result<String, DiagServiceError> {
            Ok("locked".to_string())
        }
        fn lookup_service_through_func_class(
            &self,
            _func_class_name: &str,
            _service_id: u8,
        ) -> Result<DiagComm, DiagServiceError> {
            unimplemented!()
        }
        fn lookup_diagcomms_by_request_prefix(
            &self,
            _service_bytes: &[u8],
        ) -> Result<Vec<DiagComm>, DiagServiceError> {
            unimplemented!()
        }
        fn lookup_service_by_sid_and_name(
            &self,
            _service_id: u8,
            _name: &str,
            _functional_group_name: Option<&str>,
        ) -> Result<DiagComm, DiagServiceError> {
            unimplemented!()
        }
        fn get_request_parameter_metadata(
            &self,
            _service_name: &str,
        ) -> Result<Vec<cda_interfaces::ServiceParameterMetadata>, DiagServiceError> {
            unimplemented!()
        }
        fn get_response_parameter_metadata(
            &self,
            _service_name: &str,
        ) -> Result<Vec<cda_interfaces::ResponseParameterInfo>, DiagServiceError> {
            unimplemented!()
        }
        fn get_mux_cases_for_service(
            &self,
            _service_name: &str,
        ) -> Result<Vec<cda_interfaces::MuxCaseInfo>, DiagServiceError> {
            unimplemented!()
        }
        fn get_components_data_info(
            &self,
            _security_plugin: &DynamicPlugin,
        ) -> Vec<ComponentDataInfo> {
            unimplemented!()
        }
        fn get_functional_group_data_info(
            &self,
            _security_plugin: &DynamicPlugin,
            _functional_group_name: &str,
        ) -> Result<Vec<ComponentDataInfo>, DiagServiceError> {
            unimplemented!()
        }
        fn get_components_configurations_info(
            &self,
            _security_plugin: &DynamicPlugin,
        ) -> Result<Vec<ComponentConfigurationsInfo>, DiagServiceError> {
            unimplemented!()
        }
        fn get_components_operations_info(
            &self,
            _security_plugin: &DynamicPlugin,
        ) -> Vec<ComponentOperationsInfo> {
            unimplemented!()
        }
        fn get_routine_subfunctions(
            &self,
            _service_name: &str,
            _security_plugin: &DynamicPlugin,
        ) -> Result<RoutineSubfunctions, DiagServiceError> {
            unimplemented!()
        }
        fn get_functional_group_operations_info(
            &self,
            _security_plugin: &DynamicPlugin,
            _functional_group_name: &str,
        ) -> Result<Vec<ComponentOperationsInfo>, DiagServiceError> {
            unimplemented!()
        }
        fn get_functional_group_routine_subfunctions(
            &self,
            _security_plugin: &DynamicPlugin,
            _functional_group_name: &str,
            _service_name: &str,
        ) -> Result<RoutineSubfunctions, DiagServiceError> {
            unimplemented!()
        }
        fn get_components_single_ecu_jobs_info(&self) -> Vec<ComponentDataInfo> {
            unimplemented!()
        }
        fn lookup_dtc_services(
            &self,
            _service_types: Vec<DtcReadInformationFunction>,
        ) -> Result<HashMap<DtcReadInformationFunction, DtcLookup>, DiagServiceError> {
            unimplemented!()
        }
        async fn is_service_allowed(
            &self,
            _service: &DiagComm,
            _security_plugin: &DynamicPlugin,
        ) -> Result<(), DiagServiceError> {
            Ok(())
        }
        fn revision(&self) -> String {
            "1.0.0".to_string()
        }
        fn convert_service_14_response(
            &self,
            _diag_comm: DiagComm,
            _response: ServicePayload,
        ) -> Result<Self::Response, DiagServiceError> {
            unimplemented!()
        }

        async fn init_default_states(&self) -> Result<(), DiagServiceError> {
            unimplemented!()
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

    fn make_manager(gateway: TestGateway) -> UdsManager<TestGateway, TestResponse, TestEcuDb> {
        let ecus = Arc::new(HashMap::from_iter([(
            "TestECU".to_string(),
            RwLock::new(TestEcuDb::new()),
        )]));
        let (_tx, rx) = mpsc::channel(1);
        UdsManager::new(
            gateway,
            ecus,
            rx,
            &FunctionalDescriptionConfig {
                description_database: "functional_groups".to_string(),
                enabled_functional_groups: None,
                protocol_position: DiagnosticServiceAffixPosition::Suffix,
            },
            FaultConfig::default(),
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn make_manager_no_ecus(
        gateway: TestGateway,
    ) -> UdsManager<TestGateway, TestResponse, TestEcuDb> {
        let ecus = Arc::new(HashMap::new());
        let (_tx, rx) = mpsc::channel(1);
        UdsManager::new(
            gateway,
            ecus,
            rx,
            &FunctionalDescriptionConfig {
                description_database: "functional_groups".to_string(),
                enabled_functional_groups: None,
                protocol_position: DiagnosticServiceAffixPosition::Suffix,
            },
            FaultConfig::default(),
            Arc::new(AtomicBool::new(false)),
        )
    }

    // Tests

    #[tokio::test]
    async fn test_send_with_raw_payload_positive_response() {
        let gateway = TestGateway {
            send_fn: Arc::new(|response_tx, _| {
                let msg = UdsResponse::Message(ServicePayload {
                    data: vec![0x50, 0x01],
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
                        .try_send(Ok(Some(UdsResponse::BusyRepeatRequest(0x0001))))
                        .ok();
                } else {
                    let msg = UdsResponse::Message(ServicePayload {
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
                        .try_send(Ok(Some(UdsResponse::ResponsePending(0x0001))))
                        .ok();
                    response_tx
                        .try_send(Ok(Some(UdsResponse::Message(ServicePayload {
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
                        .try_send(Ok(Some(UdsResponse::TemporarilyNotAvailable(0x0001))))
                        .ok();
                } else {
                    let msg = UdsResponse::Message(ServicePayload {
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
                let msg = UdsResponse::Message(ServicePayload {
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
        let gateway = TestGateway {
            send_fn: Arc::new(|response_tx, _| {
                let msg = UdsResponse::Message(ServicePayload {
                    data: vec![0x50, 0x01],
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
            .send_with_raw_payload("TestECU", payload, Some(Duration::from_secs(1)), true)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_sets_session_state_on_positive_response() {
        let gateway = TestGateway {
            send_fn: Arc::new(|response_tx, _| {
                let msg = UdsResponse::Message(ServicePayload {
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
        let (_tx, rx) = mpsc::channel(1);
        let manager = UdsManager::new(
            gateway,
            Arc::clone(&ecus),
            rx,
            &FunctionalDescriptionConfig {
                description_database: "functional_groups".to_string(),
                enabled_functional_groups: None,
                protocol_position: DiagnosticServiceAffixPosition::Suffix,
            },
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
                let wrong_did = UdsResponse::Message(ServicePayload {
                    data: vec![0x62, 0xF2, 0x00, 0xAA],
                    source_address: 0x0001,
                    target_address: 0x0E00,
                    new_session: None,
                    new_security: None,
                });
                response_tx.try_send(Ok(Some(wrong_did))).ok();
                // Then: the correct response with matching DID
                let correct = UdsResponse::Message(ServicePayload {
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
