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
    Connectivity, DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, EcuSecurity,
    EcuState, PayloadDecoder, PendingNrc, ServicePayload, TransmissionParameters,
    TransportResponse, UdsTransport, VariantDetection, VariantState,
    communication_control::CommunicationGuard,
    datatypes::RetryPolicy,
    diagservices::{DiagServiceResponse, UdsPayloadData},
    dlt_ctx,
    request_authorization::{UdsRequestSendContext, UdsRequestTarget},
    service_ids,
};
use tokio::{
    sync::{OwnedSemaphorePermit, RwLock, mpsc},
    task::{AbortHandle, JoinHandle},
};

use crate::{ResolvedEcu, UdsEcuDb, UdsManager, VariantReadyEcu, types::UdsParameters};

/// Grace period for a per-request gateway task to finish cooperatively.
///
/// Dropping the previous attempt's response channel only *signals* that task
/// to stop; it does not guarantee the task has released whatever per-ECU
/// resource it holds (e.g. a `DoIP` connection mutex, or - critically for CAN,
/// which has no equivalent per-connection lock - an ISO-TP socket bound to
/// the same CAN ID pair the next attempt is about to open). Awaiting the
/// handle closes that gap. After this grace period, the stale task is aborted
/// and joined before another attempt may start.
const RETRY_TEARDOWN_GRACE: Duration = Duration::from_millis(500);

struct SupervisedGatewayTask {
    abort_handle: AbortHandle,
    supervisor: JoinHandle<()>,
}

impl SupervisedGatewayTask {
    fn new(gateway_task: JoinHandle<()>, ecu_permits: Arc<[OwnedSemaphorePermit]>) -> Self {
        let abort_handle = gateway_task.abort_handle();
        let supervisor = tokio::spawn(async move {
            log_gateway_task_result(gateway_task.await);
            drop(ecu_permits);
        });
        Self {
            abort_handle,
            supervisor,
        }
    }
}

impl Drop for SupervisedGatewayTask {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}

fn log_gateway_task_result(result: Result<(), tokio::task::JoinError>) {
    if let Err(error) = result
        && !error.is_cancelled()
    {
        tracing::debug!(%error, "Gateway task ended abnormally");
    }
}

/// Reports whether `security_plugin` is the void plugin that CDA-internal traffic is sent with.
///
/// Requests originating from a caller always carry the plugin created from their token.
pub(crate) fn is_void_plugin(security_plugin: &DynamicPlugin) -> bool {
    security_plugin.downcast_ref::<()>().is_some()
}

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    /// Sends `service` using the ECU's configured default response timeout.
    ///
    /// See [`Self::send_service_with_timeout`] for the caller's obligations.
    pub(crate) async fn send_service(
        &self,
        // Not used here beyond forwarding: holding the borrow for the whole
        // call keeps the caller's `CommunicationGuard` alive, so communication
        // cannot be disabled mid-request.
        communication: &CommunicationGuard,
        ecu: &VariantReadyEcu<'_, T>,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
    ) -> Result<<T as PayloadDecoder>::Response, DiagServiceError> {
        self.send_service_with_timeout(
            communication,
            ecu,
            service,
            security_plugin,
            payload,
            map_to_json,
            None,
        )
        .await
    }

    /// Sends `service`, overriding the ECU's default response timeout when
    /// `timeout` is `Some`.
    ///
    /// The borrowed
    /// [`CommunicationGuard`](CommunicationGuard)
    /// proves the caller holds communication open; it must outlive this call,
    /// so communication cannot be shut down mid-request. See
    /// [`Self::send_with_raw_payload`].
    #[tracing::instrument(
        skip(self, _communication, ecu, security_plugin, payload),
        fields(
            ecu_name = ecu.name(),
            service_name = %service.name,
            has_payload = payload.is_some(),
            dlt_context = dlt_ctx!("UDS")
        )
    )]
    #[allow(
        clippy::too_many_arguments,
        reason = "Two of the arguments are proof rather than data: the `CommunicationGuard` and \
                  the `VariantReadyEcu` carry no payload, they only prove the caller holds the \
                  guards this send needs."
    )]
    pub(crate) async fn send_service_with_timeout(
        &self,
        // Never read: the parameter exists only to force callers to hold a
        // `CommunicationGuard` for the whole send. Borrowing it here ties the
        // guard's lifetime to this call, so communication cannot be disabled
        // between the admission check and the request completing.
        _communication: &CommunicationGuard,
        ecu: &VariantReadyEcu<'_, T>,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
        timeout: Option<Duration>,
    ) -> Result<<T as PayloadDecoder>::Response, DiagServiceError> {
        self.ensure_variant_ready_for_send(ecu).await?;

        self.send_without_variant_guard(
            ecu,
            service,
            security_plugin,
            payload,
            map_to_json,
            timeout,
        )
        .await
    }

    /// Inner send path that skips the variant detection guard.
    /// Used by variant detection's `gather_detection_responses` to avoid
    /// infinite recursion.
    pub(crate) async fn send_without_variant_guard(
        &self,
        ecu: &ResolvedEcu<'_, T>,
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

        let payload = {
            let ecu = ecu.read().await;
            ecu.create_uds_payload(&service, security_plugin, payload, None)
                .await?
        };

        let payload_build_after = start.elapsed();

        let response = self
            .send_authorized_raw_payload(ecu, payload.clone(), Some(security_plugin), timeout)
            .await;
        let response_after = start.elapsed().saturating_sub(payload_build_after);

        let response = match response {
            Ok(Some(msg)) => {
                ecu.read()
                    .await
                    .convert_from_uds(&service, &msg, map_to_json, None)
                    .await
            }
            Ok(None) => {
                // Only reachable when the request carried the
                // suppress-positive-response bit: the ECU legitimately
                // did not respond. This is a success, not an error - mirror the
                // treatment already applied on the raw path (`send_genericservice`,
                // which maps `Ok(None)` to an empty result) by returning a
                // positive, empty response. Callers render it as no-content.
                Ok(<T as PayloadDecoder>::Response::empty_positive(
                    service.clone(),
                ))
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

impl<S: EcuGateway, T: UdsEcuDb + VariantDetection + EcuSecurity> UdsManager<S, T> {
    /// Authorizes a fully resolved UDS request for a physical ECU through the security plugin.
    ///
    /// Samples the lock relevant to the ECU immediately before consulting the plugin. The void
    /// plugin marks CDA-internal traffic (variant detection, resets) and is never checked.
    ///
    /// # Errors
    /// Returns [`DiagServiceError::RequestNotAllowed`] if the plugin rejects the request.
    pub(crate) async fn authorize_physical_send(
        &self,
        ecu: &RwLock<T>,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        payload: &ServicePayload,
    ) -> Result<(), DiagServiceError> {
        if is_void_plugin(security_plugin) {
            return Ok(());
        }
        let target = UdsRequestTarget::Ecu {
            name: ecu_name.to_owned(),
            additional_fields: Vec::new(),
        };
        let context = UdsRequestSendContext {
            lock: self.request_lock_provider.current_lock(&target).await,
            target,
            payload,
        };
        ecu.read()
            .await
            .validate_request_send(security_plugin, &context)
            .await
    }

    /// Sends an internal raw payload to the ECU without caller authorization.
    ///
    /// Used for housekeeping traffic (tester present, session/security resets) that carries
    /// no request-scoped credentials and therefore skips the pre-send authorization hook.
    pub(crate) async fn send_with_raw_payload(
        &self,
        ecu: &ResolvedEcu<'_, T>,
        payload: ServicePayload,
        timeout: Option<Duration>,
    ) -> Result<Option<ServicePayload>, DiagServiceError> {
        self.send_authorized_raw_payload(ecu, payload, None, timeout)
            .await
    }

    #[allow(
        clippy::needless_continue,
        reason = "Explicit continue improves readability to make it clearer, which loop is being \
                  continued"
    )]
    /// Sends the raw payload to the ECU.
    ///
    /// Does not check communication readiness: callers hold a
    /// [`CommunicationGuard`](cda_interfaces::communication_control::CommunicationGuard)
    /// for the duration of the call. Variant detection is the exception, running
    /// while communication is still `Enabling` and no guard can be acquired.
    #[allow(
        clippy::too_many_lines,
        reason = "Splitting the send/receive flow would reduce readability"
    )]
    ///
    /// When `security_plugin` is provided, the request is authorized immediately before every
    /// transmission attempt (including retries), and nothing is sent if it is denied.
    #[tracing::instrument(
        skip(self, ecu, payload, security_plugin),
        fields(
            ecu_name = ecu.name(),
            expect_response = tracing::field::Empty,
            payload_size = payload.data.len(),
            dlt_context = dlt_ctx!("UDS")
        )
    )]
    pub(crate) async fn send_authorized_raw_payload(
        &self,
        ecu: &ResolvedEcu<'_, T>,
        payload: ServicePayload,
        security_plugin: Option<&DynamicPlugin>,
        timeout: Option<Duration>,
    ) -> Result<Option<ServicePayload>, DiagServiceError> {
        // Inspect the subfunction byte for `suppressPosRspMsgIndicationBit` (bit 7).
        // When set, the ECU is not expected to send a positive response, so the
        // absence of a response must not be treated as a timeout/error (mirrors
        // the same check already applied for functional sends, see
        // `send_functional_to_gateway`).
        let expect_response = !payload.is_suppress_positive_response();
        tracing::Span::current().record("expect_response", expect_response);

        // todo: do we need to ensure that we do not send here
        // when we have an ongoing data transfer as well?
        let start = std::time::Instant::now();

        let (uds_params, transmission_params) = Self::ecu_send_params(ecu).await;
        // The key this handle was resolved by, which is what the state
        // coordinator is keyed on. `transmission_params.ecu_name` is the
        // database's own spelling and does not necessarily match it.
        let ecu_name = ecu.name();
        let sent_sid = *payload.data.first().ok_or(DiagServiceError::BadPayload(
            "Cannot sent message without SID".to_owned(),
        ))?;
        let ecu_sem_key = ecu.read().await.request_lock_key();

        let ecu_permits = Arc::from(
            self.request_ecu_permits(vec![ecu_sem_key.clone()])
                .await
                .map_err(|error| {
                    tracing::error!(
                        ecu = ecu_name,
                        request_lock_key = %ecu_sem_key,
                        %error,
                        "Failed waiting for ECU request permit"
                    );
                    error
                })?,
        );
        let mut gateway_task = None;

        let rx_timeout = timeout.unwrap_or(uds_params.timeout_default);
        let mut rx_timeout_next = None;

        // Counts application-layer retries per ISO 14229-2:2021 Table 9
        // ("Client error handling"): a transmission failure, a raw receive
        // error, or a plain timeout with no response at all shall each cause
        // the client to repeat the last request, up to `CP_RepeatReqCountApp`
        // times (independent of, and not to be confused with, the NRC
        // 0x21/0x78/0x94 busy-repeat handling below, which has its own,
        // separate time-bounded retry policy).
        let mut app_retry_count: u32 = 0;

        // outer loop to retry sending frames, resend frames must deal with (N)ACK again
        let (response, sent_after) = 'send: loop {
            // Create a fresh response channel for every attempt. Each
            // `continue 'send` (transmission/receive error, plain timeout, or
            // NRC 0x21/0x94 busy-repeat) drops the previous attempt's
            // `response_rx` together with its sole `response_tx`, which in turn
            // fires `response_sender.closed()` in the gateway's per-request
            // task, signaling it to tear itself down.
            //
            // Reusing a single channel across attempts (as done previously)
            // kept every prior gateway task alive and subscribed to the same
            // sender; a stale task could then push a late response or error
            // into the shared channel and trip the receive-error branch below,
            // causing a retry to fire immediately instead of only after this
            // attempt's `rx_timeout` had elapsed.
            let (response_tx, mut response_rx) = mpsc::channel(2);

            // Dropping the previous attempt's channel only *signals* its
            // gateway task to stop; it does not guarantee that task has
            // actually finished releasing whatever per-ECU resource it holds
            // (e.g. a DoIP connection mutex, or an ISO-TP socket for CAN,
            // which has no equivalent lock). Await its handle before sending
            // the next attempt. A task exceeding `RETRY_TEARDOWN_GRACE` is
            // aborted and joined, so retries never overlap the stale task.
            if let Some(task) = gateway_task.take() {
                await_gateway_task(task, ecu_name).await;
            }

            if let Some(security_plugin) = security_plugin {
                self.authorize_physical_send(ecu, ecu_name, security_plugin, &payload)
                    .await?;
            }

            match self
                .gateway
                .send(
                    transmission_params.clone(),
                    payload.clone(),
                    response_tx,
                    expect_response,
                )
                .await
            {
                Ok(handle) => {
                    gateway_task =
                        Some(SupervisedGatewayTask::new(handle, Arc::clone(&ecu_permits)));
                }
                Err(e) => {
                    if app_retry_count < uds_params.repeat_req_count_app {
                        app_retry_count = app_retry_count.saturating_add(1);
                        tracing::debug!(
                            ecu_name,
                            attempt = app_retry_count,
                            max_attempts = uds_params.repeat_req_count_app,
                            error = %e,
                            "Transmission error, repeating request (CP_RepeatReqCountApp)"
                        );
                        rx_timeout_next = None;
                        continue 'send;
                    }
                    return Err(e);
                }
            }
            let sent_after = start.elapsed();

            // responses might be disabled, i.e. for functional tester presents...
            if !expect_response {
                // ...but wait until the message was (n)ack'd. Bounded by `rx_timeout`
                // so a gateway that never (n)acks and never closes the channel cannot
                // block this call forever.
                if tokio::time::timeout(rx_timeout, response_rx.recv())
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        ecu_name,
                        "Timed out waiting for (n)ack on a request with no expected response"
                    );
                }
                drop(response_rx);
                if let Some(task) = gateway_task.take() {
                    await_gateway_task(task, ecu_name).await;
                }
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
                            // BusyRepeatRequest and TemporarilyNotAvailable differ
                            // only in which com-params drive
                            // them: both mean "retry the whole request after a
                            // delay", unlike ResponsePending which keeps waiting below.
                            PendingNrc::BusyRepeatRequest { .. }
                            | PendingNrc::TemporarilyNotAvailable { .. } => {
                                let (nrc, policy, completion_timeout, sleep_time) =
                                    if matches!(pending, PendingNrc::BusyRepeatRequest { .. }) {
                                        (
                                            "BusyRepeatRequest",
                                            &uds_params.rc_21_retry_policy,
                                            &uds_params.rc_21_completion_timeout,
                                            uds_params.rc_21_repeat_request_time,
                                        )
                                    } else {
                                        (
                                            "TemporarilyNotAvailable",
                                            &uds_params.rc_94_retry_policy,
                                            &uds_params.rc_94_completion_timeout,
                                            uds_params.rc_94_repeat_request_time,
                                        )
                                    };
                                if let Err(e) = validate_timeout_by_policy(
                                    ecu_name,
                                    policy,
                                    &start.elapsed(),
                                    completion_timeout,
                                ) {
                                    break 'read_uds_messages Err(e);
                                }
                                tracing::debug!(
                                    sleep_time = ?sleep_time,
                                    "{nrc} received, resending after delay"
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
                            // Per ISO 14229-2 Table 9 ("Response reception" error),
                            // repeat the last request up to CP_RepeatReqCountApp
                            // times before giving up.
                            if app_retry_count < uds_params.repeat_req_count_app {
                                app_retry_count = app_retry_count.saturating_add(1);
                                tracing::debug!(
                                    ecu_name,
                                    attempt = app_retry_count,
                                    max_attempts = uds_params.repeat_req_count_app,
                                    "Repeating request after receive error (CP_RepeatReqCountApp)"
                                );
                                rx_timeout_next = None;
                                continue 'send;
                            }
                            break 'read_uds_messages Err(e);
                        }
                    },
                    Ok(None) => {
                        // The gateway closed the response channel without
                        // delivering a usable response for this request (e.g.
                        // its per-request task ended after forwarding only
                        // non-matching frames, such as a wrong-DID echo that
                        // was ignored above). This is a "no response" condition
                        // per ISO 14229-2 Table 9, not an unexpected response:
                        // treat it exactly like a plain timeout, applying the
                        // CP_RepeatReqCountApp retry policy and ultimately
                        // surfacing DiagServiceError::Timeout.
                        tracing::debug!(
                            "Response channel closed with no matching response for request"
                        );
                        if app_retry_count < uds_params.repeat_req_count_app {
                            app_retry_count = app_retry_count.saturating_add(1);
                            tracing::debug!(
                                ecu_name,
                                attempt = app_retry_count,
                                max_attempts = uds_params.repeat_req_count_app,
                                "Repeating request after response channel closed \
                                 (CP_RepeatReqCountApp)"
                            );
                            rx_timeout_next = None;
                            continue 'send;
                        }
                        break 'read_uds_messages Err(DiagServiceError::Timeout);
                    }
                    Err(_) => {
                        // error means the tokio::time::timeout
                        // elapsed before a response was received
                        tracing::debug!(
                            "Timeout waiting for UDS response from gateway after {:?}",
                            rx_timeout_next.unwrap_or(rx_timeout)
                        );
                        // Per ISO 14229-2 Table 9 (`tP_Client`/`tP*_Client`
                        // timeout), repeat the last request up to
                        // CP_RepeatReqCountApp times before giving up. This is
                        // independent of NRC 0x21/0x78/0x94 busy-repeat
                        // handling above, which is not affected by this
                        // counter and keeps its own, separate time-bounded
                        // retry policy.
                        if app_retry_count < uds_params.repeat_req_count_app {
                            app_retry_count = app_retry_count.saturating_add(1);
                            tracing::debug!(
                                ecu_name,
                                attempt = app_retry_count,
                                max_attempts = uds_params.repeat_req_count_app,
                                "Repeating request after timeout (CP_RepeatReqCountApp)"
                            );
                            rx_timeout_next = None;
                            continue 'send;
                        }
                        break 'read_uds_messages Err(DiagServiceError::Timeout);
                    }
                }
            };
            tracing::debug!("Finished reading UDS messages from gateway");
            // `response_rx` (and its `response_tx`) are dropped here as this
            // attempt's scope ends, closing the channel and releasing the
            // gateway's per-request task and the ECU lock it holds.
            break 'send (uds_result, sent_after);
        };
        if let Some(task) = gateway_task.take() {
            await_gateway_task(task, ecu_name).await;
        }

        // Post-send: if a service send (not tester present) timed out,
        // the ECU is unreachable - notify the coordinator.
        // The coordinator will suppress this if variant detection is in progress.
        if matches!(response, Err(DiagServiceError::Timeout))
            && sent_sid != service_ids::TESTER_PRESENT
        {
            ecu.data()
                .state_coordinator()
                .handle_ecu_disconnected(ecu_name)
                .await;
        }

        if let Ok(ref msg) = response
            && msg.is_positive_response_for_sid(sent_sid)
        {
            let ecu_read = ecu.read().await;
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
            // An ECU reset ends the authenticated state (ISO 14229-1 clause 10.6.4).
            // A pending expiration finds the ECU deauthenticated and sends nothing.
            if sent_sid == service_ids::ECU_RESET
                && ecu_read.authentication_state().is_authenticated()
            {
                tracing::info!(ecu_name, "ECU reset, authentication state reset");
                ecu_read.set_authentication_state(
                    cda_interfaces::authentication::AuthenticationState::default(),
                );
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
                    repeat_req_count_app: ecu.repeat_req_count_app(),
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
        let communication_guard = self.acquire_communication_guard()?;
        let data = self.ecu_data.read().await;
        let ecu = self
            .uds_ecu_variant_detection_concluded(&data, ecu_name)
            .await?;
        self.send_service_with_timeout(
            &communication_guard,
            &ecu,
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
        let communication_guard = self.acquire_communication_guard()?;
        let data = self.ecu_data.read().await;
        let ecu = self
            .uds_ecu_variant_detection_concluded(&data, ecu_name)
            .await?;
        self.send_service(
            &communication_guard,
            &ecu,
            service,
            security_plugin,
            payload,
            map_to_json,
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

        let _communication_guard = self.acquire_communication_guard()?;
        let data = self.ecu_data.read().await;
        let ecu = self
            .uds_ecu_variant_detection_concluded(&data, ecu_name)
            .await?;

        let payload = ecu
            .read()
            .await
            .check_genericservice(security_plugin, payload)
            .await?;

        match self
            .send_authorized_raw_payload(&ecu, payload, Some(security_plugin), timeout)
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

/// Waits for a per-request gateway task to terminate before releasing its resources.
///
/// Dropping the previous attempt's response channel only signals that task to
/// stop; this actually confirms it has finished (and released whatever
/// per-ECU resource it was holding), closing the race between a stale task
/// and the next attempt's fresh one. If the grace period elapses first, the
/// task is aborted and joined.
async fn await_gateway_task(mut task: SupervisedGatewayTask, ecu_name: &str) {
    match tokio::time::timeout(RETRY_TEARDOWN_GRACE, &mut task.supervisor).await {
        Ok(result) => log_gateway_task_result(result),
        Err(_elapsed) => {
            tracing::warn!(
                ecu_name,
                grace_period = ?RETRY_TEARDOWN_GRACE,
                "Gateway task did not finish within the teardown grace period; aborting it"
            );
            task.abort_handle.abort();
            log_gateway_task_result((&mut task.supervisor).await);
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
pub(crate) mod send_tests {
    use std::{
        sync::{Arc, Barrier as StdBarrier},
        time::{Duration, Instant},
    };

    use cda_interfaces::{
        DiagServiceError, DynamicPlugin, EcuGateway, EcuStateManager, FunctionalDescriptionConfig,
        HashMap, HashMapExtensions, PendingNrc, ReloadComponent, ResetOutcome, ServicePayload,
        TesterPresentType, TransportResponse, UDS_ID_RESPONSE_BITMASK, UdsComParams, UdsSecurity,
        UdsSession, UdsTesterPresent,
        communication_control::{
            ActivationCause, CommunicationAccess, CommunicationError, CommunicationGuard,
            CommunicationLifecycle, CommunicationOperation, CommunicationState, DisableError,
            DisableReason, VariantDetectionMode,
        },
        datatypes::FaultConfig,
        service_ids,
    };
    use cda_plugin_communication_management::lifecycle::{
        enabled_communication_access_for_test, enabled_communication_for_test,
    };
    use tokio::sync::{Barrier, Notify, RwLock, mpsc, oneshot};

    use super::RETRY_TEARDOWN_GRACE;
    use crate::{
        UdsManager, VehicleEcuData,
        state_coordinator::EcuStateCoordinator,
        test_helpers::{
            TEST_COMMUNICATION_RETRY_AFTER, TestEcuDb, TestGateway, UdsManagerParts,
            build_uds_manager, finished_task,
        },
        tester_present::TesterPresentTask,
        types::{ResetTask, TesterPresentTaskId},
    };

    async fn live_fault_scope<S: EcuGateway>(manager: &UdsManager<S, TestEcuDb>) -> String {
        manager
            .ecu_data
            .read()
            .await
            .fault_config()
            .user_memory_scope
            .clone()
    }

    fn disabled_communication_access() -> Arc<dyn CommunicationAccess> {
        struct Disabled;
        impl CommunicationAccess for Disabled {
            fn state(&self) -> CommunicationState {
                CommunicationState::Disabled
            }

            fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
                Err(CommunicationError::Disabled)
            }

            fn request_activate(&self, _cause: ActivationCause) -> CommunicationState {
                CommunicationState::Disabled
            }

            fn variant_detection(&self) -> VariantDetectionMode {
                VariantDetectionMode::Always
            }
        }
        Arc::new(Disabled)
    }

    /// Lifecycle phase modelled by [`FakeCommunicationAccess`].
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CommunicationPhase {
        Off,
        Enabling,
        Enabled,
        Disabling,
    }

    /// A `CommunicationAccess` fake with controllable `acquire` and
    /// `request_activate` behavior. Once "enabled" it delegates guard minting to
    /// [`enabled_communication_access_for_test`], so tests never mint a
    /// `CommunicationGuard` themselves.
    struct FakeCommunicationAccess {
        phase: std::sync::Mutex<CommunicationPhase>,
        activate_calls: std::sync::atomic::AtomicUsize,
        activate_succeeds: bool,
        real: Arc<dyn CommunicationAccess>,
    }

    impl FakeCommunicationAccess {
        fn new(initially_enabled: bool, activate_succeeds: bool) -> Arc<Self> {
            Arc::new(Self {
                phase: std::sync::Mutex::new(if initially_enabled {
                    CommunicationPhase::Enabled
                } else {
                    CommunicationPhase::Off
                }),
                activate_calls: std::sync::atomic::AtomicUsize::new(0),
                activate_succeeds,
                real: enabled_communication_access_for_test(),
            })
        }

        fn phase(&self) -> CommunicationPhase {
            *self.phase.lock().expect("fake phase lock poisoned")
        }

        fn set_phase(&self, phase: CommunicationPhase) {
            *self.phase.lock().expect("fake phase lock poisoned") = phase;
        }

        fn activate_call_count(&self) -> usize {
            self.activate_calls
                .load(std::sync::atomic::Ordering::SeqCst)
        }

        /// Models the window in which `initialize` runs: the transport is up,
        /// but the activation has not published `Enabled` yet.
        fn begin_enabling(&self) {
            self.set_phase(CommunicationPhase::Enabling);
        }

        /// Models the lifecycle worker publishing `Enabled`, which it does
        /// before calling any hook's `on_enabled`.
        fn finish_enabling(&self) {
            self.set_phase(CommunicationPhase::Enabled);
        }

        /// Models the activation ending without ever reaching `Enabled`, as
        /// happens when a later lifecycle hook or variant detection fails.
        fn abort_enabling(&self) {
            self.set_phase(CommunicationPhase::Off);
        }

        /// Models a disable being claimed. The controller moves the state to
        /// `Disabling` synchronously, before the worker deinitializes any hook,
        /// so once `Enabled` is published this can happen before the worker
        /// has called `on_enabled`.
        fn begin_disabling(&self) {
            self.set_phase(CommunicationPhase::Disabling);
        }

        /// Models the worker finishing a disable, after every hook's
        /// `deinitialize`.
        fn finish_disabling(&self) {
            self.set_phase(CommunicationPhase::Off);
        }
    }

    impl CommunicationAccess for FakeCommunicationAccess {
        fn state(&self) -> CommunicationState {
            match self.phase() {
                CommunicationPhase::Enabled => CommunicationState::Enabled,
                CommunicationPhase::Enabling => {
                    CommunicationState::Enabling(CommunicationOperation::EnableAndDetect)
                }
                CommunicationPhase::Off => CommunicationState::Disabled,
                CommunicationPhase::Disabling => CommunicationState::Disabling,
            }
        }

        fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
            match self.phase() {
                CommunicationPhase::Enabled => self.real.acquire(),
                CommunicationPhase::Enabling => Err(CommunicationError::Enabling),
                CommunicationPhase::Off => Err(CommunicationError::Disabled),
                CommunicationPhase::Disabling => Err(CommunicationError::Disabling),
            }
        }

        fn request_activate(&self, _cause: ActivationCause) -> CommunicationState {
            self.activate_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Fire-and-forget, like the real implementation. The fake models an
            // instant activation by flipping to `Enabled` synchronously, so a
            // retrying caller observes the effect.
            if self.activate_succeeds {
                self.set_phase(CommunicationPhase::Enabled);
                CommunicationState::Enabled
            } else {
                self.state()
            }
        }

        fn variant_detection(&self) -> VariantDetectionMode {
            VariantDetectionMode::Always
        }
    }

    struct BlockingCommunicationAccess {
        inner: Arc<dyn CommunicationAccess>,
        acquire_entered: Arc<Notify>,
        acquire_proceed: Arc<StdBarrier>,
    }

    impl CommunicationAccess for BlockingCommunicationAccess {
        fn state(&self) -> CommunicationState {
            self.inner.state()
        }

        fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
            self.acquire_entered.notify_one();
            self.acquire_proceed.wait();
            self.inner.acquire()
        }

        fn request_activate(&self, cause: ActivationCause) -> CommunicationState {
            self.inner.request_activate(cause)
        }

        fn variant_detection(&self) -> VariantDetectionMode {
            self.inner.variant_detection()
        }
    }

    /// Keeps a `response_sender` alive for the remainder of the test process,
    /// modelling a real gateway task that stays parked (holding its sender)
    /// after sending no usable response - e.g. an offline or answer-suppressing
    /// ECU that positively ACKs but never replies. This lets the caller's
    /// `rx_timeout` fire instead of the channel closing early (`recv() == None`).
    ///
    /// Closures that instead want to model a gateway which closes the channel
    /// after forwarding its frame(s) (e.g. the CAN gateway breaking after the
    /// first SID-matching response) must simply let the sender drop.
    fn park_sender(sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>) {
        type ParkedSenders = std::sync::Mutex<
            Vec<mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>>,
        >;
        static PARKED: std::sync::OnceLock<ParkedSenders> = std::sync::OnceLock::new();
        PARKED
            .get_or_init(|| std::sync::Mutex::new(Vec::new()))
            .lock()
            .unwrap()
            .push(sender);
    }

    /// Fake gateway behavior dedicated to exercising the retry-teardown
    /// synchronization in `send_with_raw_payload`: every `send` call
    /// immediately closes its response channel (as a stale gateway task would
    /// once it has forwarded its last usable message and moved to shutting
    /// down), but the *returned task handle* only resolves after `task_delay`,
    /// modelling a per-request task that is slow to actually finish (e.g. still
    /// releasing a connection lock or socket).
    ///
    /// Every invocation's timestamp is recorded in the returned `send_times`,
    /// so tests can assert on the gap between successive attempts to verify the
    /// caller waited for the previous attempt's handle before issuing the next
    /// one.
    fn slow_teardown_gateway(
        task_delay: Duration,
    ) -> (TestGateway, Arc<std::sync::Mutex<Vec<Instant>>>) {
        let send_times = Arc::new(std::sync::Mutex::new(Vec::new()));
        let gateway = TestGateway::new({
            let send_times = Arc::clone(&send_times);
            move |_, response_sender, _| {
                send_times.lock().unwrap().push(Instant::now());
                // Simulate the stale task's response-forwarding phase already
                // being over: drop the sender right away so the caller's
                // `recv()` observes the channel closing immediately, well
                // before `task_delay` elapses.
                drop(response_sender);
                Ok(tokio::task::spawn(async move {
                    cda_interfaces::util::tokio_ext::sleep_for(task_delay).await;
                }))
            }
        });
        (gateway, send_times)
    }

    struct GateCheckingDrop {
        drop_checked: Option<oneshot::Sender<bool>>,
        request_gate: Arc<std::sync::Mutex<Option<Arc<tokio::sync::Semaphore>>>>,
    }

    impl Drop for GateCheckingDrop {
        fn drop(&mut self) {
            let gate_was_held = self
                .request_gate
                .lock()
                .expect("request-gate lock must remain available")
                .as_ref()
                .is_some_and(|gate| Arc::clone(gate).try_acquire_owned().is_err());
            if let Some(drop_checked) = self.drop_checked.take() {
                let _ = drop_checked.send(gate_was_held);
            }
        }
    }

    /// A gateway whose per-request task answers once, then never finishes on
    /// its own and reports on destruction whether the request gate was still
    /// held.
    fn cancellation_gateway(
        teardown_started: oneshot::Sender<()>,
        drop_checked: oneshot::Sender<bool>,
        request_gate: Arc<std::sync::Mutex<Option<Arc<tokio::sync::Semaphore>>>>,
    ) -> TestGateway {
        let teardown_started = std::sync::Mutex::new(Some(teardown_started));
        let drop_checked = std::sync::Mutex::new(Some(drop_checked));
        TestGateway::new(move |_, response_sender, _| {
            let teardown_started = teardown_started
                .lock()
                .expect("teardown-started sender lock must remain available")
                .take();
            let drop_checked = drop_checked
                .lock()
                .expect("drop-checked sender lock must remain available")
                .take();
            let request_gate = Arc::clone(&request_gate);
            Ok(tokio::spawn(async move {
                let _gate_checking_drop = GateCheckingDrop {
                    drop_checked,
                    request_gate,
                };
                let response = ServicePayload {
                    data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01],
                    source_address: 0x0001,
                    target_address: 0x0E00,
                    new_session: None,
                    new_security: None,
                };
                let _ = response_sender
                    .send(Ok(Some(TransportResponse::UdsResponse(response))))
                    .await;
                response_sender.closed().await;
                if let Some(teardown_started) = teardown_started {
                    let _ = teardown_started.send(());
                }
                std::future::pending::<()>().await;
            }))
        })
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

    /// Resolves the single ECU `make_manager` registers, the way production
    /// callers resolve one before sending.
    async fn test_ecu<G: EcuGateway>(
        manager: &UdsManager<G, TestEcuDb>,
    ) -> tokio::sync::RwLockReadGuard<'_, RwLock<TestEcuDb>> {
        tokio::sync::RwLockReadGuard::map(manager.ecu_data.read().await, |data| {
            data.ecu("TestECU").expect("test ECU is registered")
        })
    }

    async fn send_test_raw<G: EcuGateway>(
        manager: &UdsManager<G, TestEcuDb>,
        payload: ServicePayload,
        timeout: Option<Duration>,
    ) -> Result<Option<ServicePayload>, DiagServiceError> {
        let data = manager.ecu_data.read().await;
        let ecu = UdsManager::<G, TestEcuDb>::resolve_ecu(&data, "TestECU")?;
        manager.send_with_raw_payload(&ecu, payload, timeout).await
    }

    fn make_manager(gateway: TestGateway) -> UdsManager<TestGateway, TestEcuDb> {
        make_manager_with_reloader(gateway).0
    }

    fn make_manager_with_reloader(
        gateway: TestGateway,
    ) -> (
        UdsManager<TestGateway, TestEcuDb>,
        Arc<dyn ReloadComponent<VehicleEcuData<TestEcuDb>>>,
    ) {
        let ecus = HashMap::from_iter([("TestECU".to_string(), RwLock::new(TestEcuDb::new()))]);
        let parts = build_uds_manager(
            gateway,
            ecus,
            FaultConfig::default(),
            disabled_communication_access(),
        );
        (parts.manager, parts.reloader)
    }

    fn make_manager_with_timeout_default(
        gateway: TestGateway,
        timeout_default: Duration,
    ) -> UdsManager<TestGateway, TestEcuDb> {
        let ecus = HashMap::from_iter([(
            "TestECU".to_string(),
            RwLock::new(TestEcuDb::with_timeout_default(timeout_default)),
        )]);
        build_uds_manager(
            gateway,
            ecus,
            FaultConfig::default(),
            disabled_communication_access(),
        )
        .manager
    }

    fn make_manager_with_timeout_default_and_repeat_req_count_app(
        gateway: TestGateway,
        timeout_default: Duration,
        repeat_req_count_app: u32,
    ) -> UdsManager<TestGateway, TestEcuDb> {
        let ecus = HashMap::from_iter([(
            "TestECU".to_string(),
            RwLock::new(TestEcuDb::with_timeout_default_and_repeat_req_count_app(
                timeout_default,
                repeat_req_count_app,
            )),
        )]);
        build_uds_manager(
            gateway,
            ecus,
            FaultConfig::default(),
            disabled_communication_access(),
        )
        .manager
    }

    async fn wait_for_connectivity(
        coordinator: &EcuStateCoordinator,
        expected: cda_interfaces::Connectivity,
    ) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while coordinator
                .get_handle("TestECU")
                .expect("coordinator handle")
                .connectivity()
                != expected
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("connectivity mutation must complete");
    }

    #[tokio::test]
    async fn ordinary_timeout_marks_ecu_offline() {
        let manager = make_manager(TestGateway::new(|_, response_tx, _| {
            park_sender(response_tx);
            Ok(finished_task())
        }));
        let data = manager.ecu_data.read().await;
        let ecu =
            UdsManager::<TestGateway, TestEcuDb>::resolve_ecu(&data, "TestECU").expect("test ECU");
        let coordinator = Arc::clone(data.state_coordinator());
        coordinator.handle_ecu_connected("TestECU").await;

        let result = manager
            .send_with_raw_payload(
                &ecu,
                make_test_payload(service_ids::SESSION_CONTROL, &[0x01]),
                Some(Duration::from_millis(10)),
            )
            .await;

        assert!(matches!(result, Err(DiagServiceError::Timeout)));
        wait_for_connectivity(&coordinator, cda_interfaces::Connectivity::Offline).await;
    }

    #[tokio::test]
    async fn detection_timeout_preserves_online_connectivity() {
        let manager = make_manager(TestGateway::new(|_, response_tx, _| {
            park_sender(response_tx);
            Ok(finished_task())
        }));
        let data = manager.ecu_data.read().await;
        let ecu =
            UdsManager::<TestGateway, TestEcuDb>::resolve_ecu(&data, "TestECU").expect("test ECU");
        let coordinator = Arc::clone(data.state_coordinator());
        coordinator.handle_ecu_connected("TestECU").await;
        assert_eq!(
            coordinator
                .get_handle("TestECU")
                .expect("coordinator handle")
                .connectivity(),
            cda_interfaces::Connectivity::Online
        );
        // What makes this a detection send rather than an ordinary one.
        coordinator.suppress_disconnect_handling("TestECU").await;

        let result = manager
            .send_with_raw_payload(
                &ecu,
                make_test_payload(service_ids::SESSION_CONTROL, &[0x01]),
                Some(Duration::from_millis(10)),
            )
            .await;

        assert!(matches!(result, Err(DiagServiceError::Timeout)));
        // `ask`, so it is answered only once the actor has drained the
        // disconnect the timeout queued: reading connectivity before this
        // would pass whether or not suppression worked.
        coordinator.restore_disconnect_handling("TestECU").await;
        assert_eq!(
            coordinator
                .get_handle("TestECU")
                .expect("coordinator handle")
                .connectivity(),
            cda_interfaces::Connectivity::Online
        );
    }

    #[tokio::test]
    async fn ordinary_timeout_is_not_suppressed_while_same_manager_detection_send_runs() {
        let detection_entered = Arc::new(Notify::new());
        let release_detection = Arc::new(Notify::new());
        let ecus = HashMap::from_iter([
            ("TestECU".to_owned(), RwLock::new(TestEcuDb::new())),
            (
                "DetectionECU".to_owned(),
                RwLock::new(TestEcuDb::with_identity("DetectionECU", 0x0002)),
            ),
        ]);
        let UdsManagerParts {
            manager,
            coordinator,
            ..
        } = build_uds_manager(
            TestGateway::new({
                let detection_entered = Arc::clone(&detection_entered);
                let release_detection = Arc::clone(&release_detection);
                move |transmission_params, response_sender, _| {
                    let is_detection_send = transmission_params.ecu_name == "DetectionECU";
                    let detection_entered = Arc::clone(&detection_entered);
                    let release_detection = Arc::clone(&release_detection);
                    Ok(tokio::spawn(async move {
                        if is_detection_send {
                            detection_entered.notify_one();
                            tokio::select! {
                                () = release_detection.notified() => {}
                                () = response_sender.closed() => {}
                            }
                        } else {
                            response_sender.closed().await;
                        }
                    }))
                }
            }),
            ecus,
            FaultConfig::default(),
            disabled_communication_access(),
        );
        coordinator.handle_ecu_connected("TestECU").await;

        let detection_manager = manager.clone();
        let detection = tokio::spawn(async move {
            let detection_data = detection_manager.ecu_data.read().await;
            let detection_ecu =
                UdsManager::<TestGateway, TestEcuDb>::resolve_ecu(&detection_data, "DetectionECU")?;
            detection_manager
                .send_with_raw_payload(
                    &detection_ecu,
                    make_test_payload(service_ids::SESSION_CONTROL, &[0x01]),
                    Some(Duration::from_secs(1)),
                )
                .await
        });
        detection_entered.notified().await;
        let data = manager.ecu_data.read().await;
        let diagnostic_ecu = UdsManager::<TestGateway, TestEcuDb>::resolve_ecu(&data, "TestECU")
            .expect("diagnostic ECU");
        let diagnostic_result = manager
            .send_with_raw_payload(
                &diagnostic_ecu,
                make_test_payload(service_ids::SESSION_CONTROL, &[0x01]),
                Some(Duration::from_millis(10)),
            )
            .await;

        assert!(matches!(diagnostic_result, Err(DiagServiceError::Timeout)));
        assert!(!detection.is_finished());
        wait_for_connectivity(&coordinator, cda_interfaces::Connectivity::Offline).await;

        release_detection.notify_one();
        assert!(matches!(
            detection.await.expect("detection task"),
            Err(DiagServiceError::Timeout)
        ));
    }

    fn make_manager_with_access(
        gateway: TestGateway,
        communication_access: Arc<dyn CommunicationAccess>,
    ) -> UdsManager<TestGateway, TestEcuDb> {
        let ecus = HashMap::new();
        build_uds_manager(gateway, ecus, FaultConfig::default(), communication_access).manager
    }

    fn make_gateway() -> TestGateway {
        TestGateway::new(|_, response_tx, _| {
            let msg = TransportResponse::UdsResponse(ServicePayload {
                data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01],
                source_address: 0x0001,
                target_address: 0x0E00,
                new_session: None,
                new_security: None,
            });
            response_tx.try_send(Ok(Some(msg))).ok();
            Ok(finished_task())
        })
    }

    #[tokio::test]
    async fn send_requires_communication_admission() {
        let manager = make_manager(make_gateway());

        let result = manager.acquire_communication_guard();

        assert!(matches!(
            result,
            Err(DiagServiceError::CommunicationNotReady { .. })
        ));
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_positive_response() {
        let gateway = make_gateway();
        let manager = make_manager(gateway);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = send_test_raw(&manager, payload, None).await;

        assert!(result.is_ok());
        let response = result.expect("should be Ok");
        assert!(response.is_some());
        let msg = response.expect("should have message");
        assert_eq!(
            msg.data,
            vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01]
        );
    }

    /// A request with `suppressPosRspMsgIndicationBit` set (here
    /// `ECUReset 0x81`) makes `send_with_raw_payload` expect no response, so it
    /// completes with `Ok(None)` once the frame is
    /// (n)ack'd - never a `Timeout`/`NoResponse` error - even though the ECU
    /// deliberately sends no response. `send_without_variant_guard` then
    /// converts this `Ok(None)` into a positive, empty decoded response via
    /// `DiagServiceResponse::empty_positive` (unit-tested in cda-core), which
    /// callers render as no-content instead of an error.
    #[tokio::test]
    async fn test_send_with_raw_payload_suppress_positive_response_returns_ok_none() {
        let gateway = TestGateway::new(|_, response_tx, _| {
            // Only an ack (None); the ECU sends no positive response.
            response_tx.try_send(Ok(None)).ok();
            Ok(finished_task())
        });
        let manager = make_manager(gateway);
        // ECUReset (0x11) with SPRMIB bit set on the subfunction byte (0x81).
        let payload = make_test_payload(service_ids::ECU_RESET, &[0x81]);
        assert!(
            payload.is_suppress_positive_response(),
            "test payload must have the suppress-positive-response bit set"
        );
        let result = send_test_raw(&manager, payload, None).await;

        assert!(result.is_ok(), "expected Ok(None), got {result:?}");
        assert!(
            result.expect("should be Ok").is_none(),
            "suppressed response must yield Ok(None), not a decoded payload"
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_empty_payload_returns_bad_payload() {
        let gateway = TestGateway::new(|_, _, _| Ok(finished_task()));
        let manager = make_manager(gateway);
        let empty_payload = ServicePayload {
            data: vec![],
            source_address: 0x0E00,
            target_address: 0x0001,
            new_session: None,
            new_security: None,
        };

        let result = send_test_raw(&manager, empty_payload, None).await;

        assert!(result.is_err());
        assert!(
            matches!(result, Err(DiagServiceError::BadPayload(_))),
            "Expected BadPayload error"
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_gateway_send_error() {
        let gateway =
            TestGateway::new(|_, _, _| Err(DiagServiceError::EcuOffline("TestECU".to_string())));
        let manager = make_manager(gateway);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = send_test_raw(&manager, payload, None).await;

        assert!(result.is_err());
        assert!(
            matches!(result, Err(DiagServiceError::EcuOffline(_))),
            "Expected EcuOffline error"
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_timeout() {
        let gateway = TestGateway::new(|_, response_tx, _| {
            // Model a parked gateway task: keep the channel open with no
            // response so the caller's rx_timeout fires (instead of the
            // channel closing early).
            park_sender(response_tx);
            Ok(finished_task())
        });
        let manager = make_manager(gateway);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = send_test_raw(&manager, payload, Some(Duration::from_millis(50))).await;

        assert!(result.is_err());
        assert!(
            matches!(result, Err(DiagServiceError::Timeout)),
            "Expected Timeout error"
        );
    }

    /// Regression test (mirrors the `test_wrong_did_in_response_returns_504`
    /// CAN integration test): when the ECU replies with the correct SID but a
    /// mismatched echo (e.g. wrong DID), that frame is ignored and the gateway
    /// then closes the response channel. This must surface as
    /// `DiagServiceError::Timeout` (HTTP 504), not `UnexpectedResponse` (HTTP
    /// 500). With a per-attempt channel, the closed channel yields
    /// `recv() == None`, which the read loop now treats as a "no response"
    /// condition per ISO 14229-2 Table 9.
    #[tokio::test]
    async fn test_send_with_raw_payload_wrong_echo_then_channel_close_is_timeout() {
        let gateway = TestGateway::new(|_, response_tx, _| {
            // Correct SID (0x62 for 0x22) but wrong DID (0xF200 instead of
            // 0xF190) plus fake data. The read loop matches the SID, sees
            // the mismatched echo bytes, ignores the frame, and loops back
            // to recv(); the gateway task then ends and drops its sender.
            let msg = TransportResponse::UdsResponse(ServicePayload {
                data: vec![
                    service_ids::READ_DATA_BY_IDENTIFIER | UDS_ID_RESPONSE_BITMASK,
                    0xF2,
                    0x00,
                    0x41,
                    0x42,
                    0x43,
                    0x44,
                ],
                source_address: 0x0001,
                target_address: 0x0E00,
                new_session: None,
                new_security: None,
            });
            response_tx.try_send(Ok(Some(msg))).ok();
            Ok(finished_task())
        });
        // No app-layer retries so the first channel-close resolves directly.
        let manager = make_manager_with_timeout_default_and_repeat_req_count_app(
            gateway,
            Duration::from_millis(50),
            0,
        );
        // Request: 22 F1 90 (ReadDataByIdentifier, DID 0xF190).
        let payload = make_test_payload(service_ids::READ_DATA_BY_IDENTIFIER, &[0xF1, 0x90]);

        let result = send_test_raw(&manager, payload, None).await;

        assert!(
            matches!(result, Err(DiagServiceError::Timeout)),
            "Expected Timeout (504) for wrong-DID response then channel close, got {result:?}"
        );
    }

    /// ISO 14229-2:2021 Table 9 ("Client error handling"): on a plain timeout
    /// with no response at all, the client shall repeat the last request, up
    /// to `CP_RepeatReqCountApp` times (worst case: `1 + N` total
    /// transmissions).
    #[tokio::test]
    async fn test_send_with_raw_payload_retries_on_timeout_up_to_repeat_req_count_app() {
        let send_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let send_count_clone = Arc::clone(&send_count);
        let gateway = TestGateway::new(move |_, response_tx, _| {
            send_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Never send any response - every attempt times out. Park the
            // sender so the channel stays open and the caller's rx_timeout
            // fires for each attempt.
            park_sender(response_tx);
            Ok(finished_task())
        });
        let repeat_req_count_app = 3;
        let manager = make_manager_with_timeout_default_and_repeat_req_count_app(
            gateway,
            Duration::from_millis(20),
            repeat_req_count_app,
        );
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = send_test_raw(&manager, payload, None).await;

        assert!(
            matches!(result, Err(DiagServiceError::Timeout)),
            "Expected Timeout error, got {result:?}"
        );
        assert_eq!(
            send_count.load(std::sync::atomic::Ordering::SeqCst),
            1 + repeat_req_count_app,
            "Expected exactly 1 original transmission + {repeat_req_count_app} repeats"
        );
    }

    /// ISO 14229-2:2021 Table 9: a request-transmission failure shall also be
    /// repeated up to `CP_RepeatReqCountApp` times, and should succeed once
    /// the gateway accepts a subsequent attempt.
    #[tokio::test]
    async fn test_send_with_raw_payload_retries_on_transmission_error_then_succeeds() {
        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let gateway = TestGateway::new(move |_, response_tx, _| {
            let count = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count < 2 {
                // First two attempts fail to transmit at all.
                return Err(DiagServiceError::SendFailed("simulated".to_owned()));
            }
            let msg = TransportResponse::UdsResponse(ServicePayload {
                data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01],
                source_address: 0x0001,
                target_address: 0x0E00,
                new_session: None,
                new_security: None,
            });
            response_tx.try_send(Ok(Some(msg))).ok();
            Ok(finished_task())
        });
        let manager = make_manager_with_timeout_default_and_repeat_req_count_app(
            gateway,
            Duration::from_secs(5),
            3,
        );
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = send_test_raw(&manager, payload, None).await;

        assert!(result.is_ok(), "Expected eventual success, got {result:?}");
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "Expected 2 failed transmission attempts + 1 successful one"
        );
    }

    /// Each retry owns a response channel. Closing a completed attempt prevents
    /// its late errors from reaching the current attempt, so every retry remains
    /// gated by the full timeout.
    #[tokio::test]
    async fn test_stale_task_error_does_not_cause_sub_timeout_retry() {
        // Holds the `response_tx` handed to the *previous* attempt, so we can
        // simulate a stale gateway task pushing a late error into it after the
        // next attempt has already started.
        type ResponseSender = mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>;
        let prev_tx: Arc<std::sync::Mutex<Option<ResponseSender>>> =
            Arc::new(std::sync::Mutex::new(None));
        let send_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

        let prev_tx_clone = Arc::clone(&prev_tx);
        let send_count_clone = Arc::clone(&send_count);
        let gateway = TestGateway::new(move |_, response_tx, _| {
            send_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Simulate the stale task of the *previous* attempt delivering a
            // late receive-error. Post-fix the previous sender is already
            // closed (its `response_rx` was dropped), so this is a no-op and
            // must not influence the current attempt.
            if let Some(stale) = prev_tx_clone.lock().unwrap().take() {
                let _ = stale.try_send(Err(DiagServiceError::NoResponse(
                    "stale task late error".to_owned(),
                )));
            }
            // Retain this attempt's sender as the "previous" one for the
            // next attempt, and otherwise never answer -> this attempt must
            // time out on its own channel.
            *prev_tx_clone.lock().unwrap() = Some(response_tx);
            Ok(finished_task())
        });

        let repeat_req_count_app = 2;
        let timeout = Duration::from_millis(50);
        let manager = make_manager_with_timeout_default_and_repeat_req_count_app(
            gateway,
            timeout,
            repeat_req_count_app,
        );
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let start = std::time::Instant::now();
        let result = send_test_raw(&manager, payload, None).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(DiagServiceError::Timeout)),
            "Expected Timeout error, got {result:?}"
        );
        assert_eq!(
            send_count.load(std::sync::atomic::Ordering::SeqCst),
            1 + repeat_req_count_app,
            "Expected exactly 1 original transmission + {repeat_req_count_app} repeats"
        );
        // The crux: each attempt (including retries) must wait its full timeout.
        // Pre-fix, the stale error tripped the receive-error branch and retries
        // fired near-instantly, so total elapsed was ~one timeout. Require the
        // total to be at least the sum for all attempts.
        let min_expected = timeout * (1 + repeat_req_count_app);
        assert!(
            elapsed >= min_expected,
            "Retries fired before their timeout elapsed: total {elapsed:?} < expected \
             {min_expected:?} (stale-task error must not trigger a sub-timeout retry)"
        );
    }

    /// NRC 0x21 (`BusyRepeatRequest`) busy-repeat handling is independent of
    /// `CP_RepeatReqCountApp`: once its own, time-bounded completion timeout
    /// is exhausted, the result must still be `Timeout`, without any
    /// additional application-layer retries layered on top (ISO 14229-2
    /// Table 9's repeat-on-timeout applies to a *raw* timeout with no
    /// response at all, not to NRC-driven busy-repeat exhaustion).
    #[tokio::test]
    async fn test_send_with_raw_payload_nrc_busy_repeat_exhaustion_not_subject_to_app_level_retry()
    {
        let send_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let send_count_clone = Arc::clone(&send_count);
        let gateway = TestGateway::new(move |_, response_tx, _| {
            send_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Always respond with NRC 0x21 (BusyRepeatRequest).
            response_tx
                .try_send(Ok(Some(TransportResponse::Pending(
                    PendingNrc::BusyRepeatRequest {
                        source_address: 0x0001,
                    },
                ))))
                .ok();
            Ok(finished_task())
        });
        // A short rc_21_completion_timeout via a short overall test bound:
        // TestEcuDb's rc_21_completion_timeout is 10s and rc_21_repeat_request_time
        // is 10ms, so this test would take too long to exhaust naturally;
        // instead, this test only asserts that the NRC-driven `continue 'send`
        // path (busy-repeat) is not itself gated by `repeat_req_count_app` by
        // running a bounded number of iterations and confirming the call
        // count exceeds `repeat_req_count_app` (which would be impossible if
        // the two mechanisms were conflated).
        let repeat_req_count_app = 1;
        let manager = make_manager_with_timeout_default_and_repeat_req_count_app(
            gateway,
            Duration::from_millis(50),
            repeat_req_count_app,
        );
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = tokio::time::timeout(
            Duration::from_millis(200),
            send_test_raw(&manager, payload, None),
        )
        .await;

        // The overall test-level timeout fires first (NRC busy-repeat keeps
        // going well past repeat_req_count_app+1 sends), proving the NRC loop
        // is not bounded by `repeat_req_count_app`.
        assert!(
            result.is_err(),
            "Expected the NRC busy-repeat loop to still be running after the test timeout"
        );
        assert!(
            send_count.load(std::sync::atomic::Ordering::SeqCst) > 1 + repeat_req_count_app,
            "NRC busy-repeat retries must not be bounded by CP_RepeatReqCountApp"
        );
    }

    /// Sends without an explicit timeout use the ECU's configured
    /// `CP_P6Max`-backed `UdsComParams::timeout_default`. Exercising the raw
    /// send keeps this test on the module's narrow `TestGateway` interface.
    #[tokio::test]
    async fn test_send_with_raw_payload_uses_configured_timeout_default_when_none() {
        let gateway = TestGateway::new(|_, response_tx, _| {
            // Don't send any response - the call must time out based on
            // the ECU's configured `timeout_default`. Park the sender so
            // the channel stays open until that timeout fires.
            park_sender(response_tx);
            Ok(finished_task())
        });
        let short_timeout = Duration::from_millis(100);
        let manager = make_manager_with_timeout_default(gateway, short_timeout);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let start = std::time::Instant::now();
        // No explicit timeout: must fall back to `uds_params.timeout_default`
        // (this is exactly what `send_without_variant_guard` does when
        // called from `gather_detection_responses` post-fix).
        let result = send_test_raw(&manager, payload, None).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(DiagServiceError::Timeout)),
            "Expected Timeout error, got {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "Expected timeout close to the configured {short_timeout:?}, but took {elapsed:?} (a \
             regression would hardcode ~10s here)"
        );
        assert!(
            elapsed >= short_timeout,
            "Timeout fired earlier than the configured {short_timeout:?}: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_busy_repeat_request_then_success() {
        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let gateway = TestGateway::new(move |_, response_tx, _| {
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
                    data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01],
                    source_address: 0x0001,
                    target_address: 0x0E00,
                    new_session: None,
                    new_security: None,
                });
                response_tx.try_send(Ok(Some(msg))).ok();
            }
            Ok(finished_task())
        });
        let manager = make_manager(gateway);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = send_test_raw(&manager, payload, None).await;

        assert!(result.is_ok());
        let msg = result.expect("should be Ok").expect("should have message");
        assert_eq!(
            msg.data,
            vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01]
        );
        assert!(call_count.load(std::sync::atomic::Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_response_pending_then_success() {
        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let gateway = TestGateway::new(move |_, response_tx, _| {
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
                        data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01],
                        source_address: 0x0001,
                        target_address: 0x0E00,
                        new_session: None,
                        new_security: None,
                    }))))
                    .ok();
            }
            Ok(finished_task())
        });
        let manager = make_manager(gateway);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = send_test_raw(&manager, payload, None).await;

        assert!(result.is_ok());
        let msg = result.expect("should be Ok").expect("should have message");
        assert_eq!(
            msg.data,
            vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01]
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_temporarily_not_available_then_success() {
        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let gateway = TestGateway::new(move |_, response_tx, _| {
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
                    data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01],
                    source_address: 0x0001,
                    target_address: 0x0E00,
                    new_session: None,
                    new_security: None,
                });
                response_tx.try_send(Ok(Some(msg))).ok();
            }
            Ok(finished_task())
        });
        let manager = make_manager(gateway);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = send_test_raw(&manager, payload, None).await;

        assert!(result.is_ok());
        let msg = result.expect("should be Ok").expect("should have message");
        assert_eq!(
            msg.data,
            vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01]
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_negative_response() {
        let gateway = TestGateway::new(|_, response_tx, _| {
            // NRC 0x7F, SID 0x10, NRC code 0x22 (conditionsNotCorrect)
            let msg = TransportResponse::UdsResponse(ServicePayload {
                data: vec![
                    service_ids::NEGATIVE_RESPONSE,
                    service_ids::SESSION_CONTROL,
                    0x22, /* conditionsNotCorrect */
                ],
                source_address: 0x0001,
                target_address: 0x0E00,
                new_session: None,
                new_security: None,
            });
            response_tx.try_send(Ok(Some(msg))).ok();
            Ok(finished_task())
        });
        let manager = make_manager(gateway);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = send_test_raw(&manager, payload, None).await;

        assert!(result.is_ok());
        let msg = result.expect("should be Ok").expect("should have message");
        // Negative response: 0x7F + original SID + NRC
        assert_eq!(
            msg.data,
            vec![
                service_ids::NEGATIVE_RESPONSE,
                service_ids::SESSION_CONTROL,
                0x22
            ]
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_custom_timeout() {
        let gateway = make_gateway();
        let manager = make_manager(gateway);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = send_test_raw(&manager, payload, Some(Duration::from_secs(1))).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_sets_session_state_on_positive_response() {
        let gateway = TestGateway::new(|_, response_tx, _| {
            let msg = TransportResponse::UdsResponse(ServicePayload {
                data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x03],
                source_address: 0x0001,
                target_address: 0x0E00,
                new_session: None,
                new_security: None,
            });
            response_tx.try_send(Ok(Some(msg))).ok();
            Ok(finished_task())
        });

        let ecus = HashMap::from_iter([("TestECU".to_string(), RwLock::new(TestEcuDb::new()))]);
        let manager: UdsManager<TestGateway, TestEcuDb> = build_uds_manager(
            gateway,
            ecus,
            FaultConfig::default(),
            disabled_communication_access(),
        )
        .manager;

        // Payload with new_session set - should be stored on positive response
        let payload = ServicePayload {
            data: vec![service_ids::SESSION_CONTROL, 0x03],
            source_address: 0x0E00,
            target_address: 0x0001,
            new_session: Some("extended".to_string()),
            new_security: None,
        };

        let result = send_test_raw(&manager, payload, None).await;

        assert!(result.is_ok());

        // Verify the session state was stored
        let ecu = test_ecu(&manager).await;
        let ecu_read = ecu.read().await;
        let session_state = ecu_read
            .get_service_state(cda_interfaces::service_ids::SESSION_CONTROL)
            .await;
        assert_eq!(session_state, Some("extended".to_string()));
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_channel_error() {
        let gateway = TestGateway::new(|_, response_tx, _| {
            // Send an error through the channel
            response_tx
                .try_send(Err(DiagServiceError::NoResponse("Test error".to_string())))
                .ok();
            Ok(finished_task())
        });
        let manager = make_manager(gateway);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = send_test_raw(&manager, payload, None).await;

        assert!(result.is_err());
        assert!(
            matches!(result, Err(DiagServiceError::NoResponse(_))),
            "Expected NoResponse error"
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_mismatched_echo_bytes_skipped() {
        let gateway = TestGateway::new(|_, response_tx, _| {
            // First: a message with correct SID response but wrong DID (echo bytes)
            // ReadDataByIdentifier (0x22) response SID is 0x62
            let wrong_did = TransportResponse::UdsResponse(ServicePayload {
                data: vec![
                    service_ids::READ_DATA_BY_IDENTIFIER | UDS_ID_RESPONSE_BITMASK,
                    0xF2,
                    0x00,
                    0xAA,
                ],
                source_address: 0x0001,
                target_address: 0x0E00,
                new_session: None,
                new_security: None,
            });
            response_tx.try_send(Ok(Some(wrong_did))).ok();
            // Then: the correct response with matching DID
            let correct = TransportResponse::UdsResponse(ServicePayload {
                data: vec![
                    service_ids::READ_DATA_BY_IDENTIFIER | UDS_ID_RESPONSE_BITMASK,
                    0xF1,
                    0x90,
                    0xBB,
                ],
                source_address: 0x0001,
                target_address: 0x0E00,
                new_session: None,
                new_security: None,
            });
            response_tx.try_send(Ok(Some(correct))).ok();
            Ok(finished_task())
        });
        let manager = make_manager(gateway);
        // ReadDataByIdentifier for DID 0xF190
        let payload = make_test_payload(service_ids::READ_DATA_BY_IDENTIFIER, &[0xF1, 0x90]);

        let result = send_test_raw(&manager, payload, None).await;

        assert!(result.is_ok());
        let msg = result.expect("should be Ok").expect("should have message");
        // Should have received the second message (correct DID)
        assert_eq!(
            msg.data,
            vec![
                service_ids::READ_DATA_BY_IDENTIFIER | UDS_ID_RESPONSE_BITMASK,
                0xF1,
                0x90,
                0xBB
            ]
        );
    }

    #[tokio::test]
    async fn test_cancelled_teardown_holds_gate_until_gateway_task_terminates() {
        let (teardown_started_tx, teardown_started_rx) = oneshot::channel();
        let (drop_checked_tx, drop_checked_rx) = oneshot::channel();
        let request_gate = Arc::new(std::sync::Mutex::new(None));
        let gateway = cancellation_gateway(
            teardown_started_tx,
            drop_checked_tx,
            Arc::clone(&request_gate),
        );
        let manager = Arc::new(make_manager(gateway));
        let first_manager = Arc::clone(&manager);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);
        let first_send =
            tokio::spawn(async move { send_test_raw(&first_manager, payload, None).await });

        teardown_started_rx
            .await
            .expect("gateway task must start final teardown");
        let gate = {
            let registry = manager.ecu_semaphores.lock().await;
            Arc::clone(registry.values().next().expect("request gate must exist"))
        };
        *request_gate
            .lock()
            .expect("request-gate lock must remain available") = Some(Arc::clone(&gate));
        first_send.abort();

        assert!(
            drop_checked_rx
                .await
                .expect("aborted gateway task must check gate during destruction"),
            "another send must not acquire request gate before stale task terminates"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while gate.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("request gate must release after gateway task termination");
        assert_eq!(gate.available_permits(), 1);
        let _ = first_send.await;
    }

    /// Regression test for the retry-teardown synchronization fix: the
    /// caller must await a previous attempt's gateway-task handle before
    /// issuing the next attempt, not just drop the response channel and hope
    /// the stale task has already finished.
    ///
    /// `slow_teardown_gateway` closes its response channel immediately (so the
    /// caller's read loop sees a fast "no response" and retries right away),
    /// but its returned task handle only resolves after `task_delay`. If the
    /// caller waited for the handle as designed, the gap between successive
    /// `send()` invocations must be at least `task_delay`; pre-fix, the next
    /// `send()` would fire almost immediately after the channel closed.
    #[tokio::test]
    async fn test_send_with_raw_payload_awaits_previous_task_before_next_retry() {
        let task_delay = Duration::from_millis(100);
        let (gateway, send_times) = slow_teardown_gateway(task_delay);
        // rx_timeout is intentionally larger than task_delay: without the
        // fix, retries fire right after the channel closes (near-instantly),
        // not after task_delay.
        let manager = make_manager_with_timeout_default_and_repeat_req_count_app(
            gateway,
            Duration::from_secs(5),
            2,
        );
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = send_test_raw(&manager, payload, None).await;

        assert!(
            matches!(result, Err(DiagServiceError::Timeout)),
            "Expected Timeout error, got {result:?}"
        );

        let times = send_times.lock().unwrap();
        assert_eq!(times.len(), 3, "Expected 1 original send + 2 retries");
        for pair in times.windows(2) {
            let (Some(a), Some(b)) = (pair.first(), pair.get(1)) else {
                panic!("windows(2) must yield exactly 2 elements");
            };
            let gap = b.duration_since(*a);
            assert!(
                gap >= task_delay,
                "Expected consecutive attempts to be at least task_delay ({task_delay:?}) apart, \
                 got {gap:?}"
            );
        }
    }

    /// A stale gateway task exceeding the grace period must be terminated
    /// before the retry starts.
    #[tokio::test]
    async fn test_send_with_raw_payload_aborts_stale_task_before_retry() {
        // Far longer than RETRY_TEARDOWN_GRACE (500ms): the task handle will
        // never resolve within the scope of this test.
        // Using 601 seconds to avoid triggering clippy's duration-subsec lint.
        let task_delay = Duration::from_secs(601);
        let (gateway, send_times) = slow_teardown_gateway(task_delay);
        let manager = make_manager_with_timeout_default_and_repeat_req_count_app(
            gateway,
            Duration::from_millis(50),
            1,
        );
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);
        let start = Instant::now();
        let result = send_test_raw(&manager, payload, None).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(DiagServiceError::Timeout)),
            "Expected Timeout error, got {result:?}"
        );
        let times = send_times.lock().unwrap();
        assert_eq!(times.len(), 2, "Expected 1 original send + 1 retry");
        let gap = times
            .get(1)
            .expect("2 elements")
            .duration_since(*times.first().expect("2 elements"));
        assert!(
            gap >= RETRY_TEARDOWN_GRACE,
            "Expected the retry to wait at least the teardown grace period \
             ({RETRY_TEARDOWN_GRACE:?}), got {gap:?}"
        );
        // Sanity bound: forced task termination keeps the call bounded.
        assert!(
            elapsed < Duration::from_secs(5),
            "Expected stale task abortion to keep the call bounded, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn acquire_communication_guard_returns_guard_immediately_when_already_enabled() {
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_access(make_gateway(), Arc::clone(&access) as _);

        let result = manager.acquire_communication_guard();

        assert!(result.is_ok());
        assert_eq!(access.activate_call_count(), 0);
    }

    /// The first call while not enabled returns `CommunicationNotReady`
    /// immediately rather than blocking through the activation it just fired. A
    /// later retry succeeds.
    #[tokio::test]
    async fn acquire_communication_guard_fires_background_trigger_and_returns_not_ready_immediately()
     {
        let access = FakeCommunicationAccess::new(false, true);
        let manager = make_manager_with_access(make_gateway(), Arc::clone(&access) as _);

        let first = manager.acquire_communication_guard();
        assert!(matches!(
            first,
            Err(DiagServiceError::CommunicationNotReady {
                retry_after: TEST_COMMUNICATION_RETRY_AFTER,
                ..
            })
        ));
        assert_eq!(access.activate_call_count(), 1);

        // The background trigger has taken effect by the time of a retry.
        assert_eq!(access.state(), CommunicationState::Enabled);
        let retry = manager.acquire_communication_guard();
        assert!(retry.is_ok());
        // The retry found communication already enabled, so no second trigger.
        assert_eq!(access.activate_call_count(), 1);
    }

    #[tokio::test]
    async fn acquire_communication_guard_surfaces_not_ready_when_activation_not_authorized() {
        let access = FakeCommunicationAccess::new(false, false);
        let manager = make_manager_with_access(make_gateway(), Arc::clone(&access) as _);

        let result = manager.acquire_communication_guard();

        assert!(matches!(
            result,
            Err(DiagServiceError::CommunicationNotReady {
                retry_after: TEST_COMMUNICATION_RETRY_AFTER,
                ..
            })
        ));
        assert_eq!(access.activate_call_count(), 1);
        assert_eq!(access.state(), CommunicationState::Disabled);
    }

    /// A request suspended inside `acquire()` has asked for admission but does
    /// not hold it, so an update must not be made to wait for it. It then reads
    /// whatever that update left behind.
    ///
    /// Multi-threaded because `CommunicationAccess::acquire` is synchronous:
    /// `BlockingCommunicationAccess` parks a worker thread, so a current-thread
    /// runtime deadlocks.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn not_yet_admitted_request_does_not_block_a_disable_lease() {
        let old_ecus = HashMap::from_iter([("TestECU".to_owned(), RwLock::new(TestEcuDb::new()))]);
        let (access, disable) = enabled_communication_for_test();
        let acquire_entered = Arc::new(Notify::new());
        let acquire_proceed = Arc::new(StdBarrier::new(2));
        let blocked_access = Arc::new(BlockingCommunicationAccess {
            inner: access,
            acquire_entered: Arc::clone(&acquire_entered),
            acquire_proceed: Arc::clone(&acquire_proceed),
        });
        let UdsManagerParts {
            manager, reloader, ..
        } = build_uds_manager(
            make_gateway(),
            old_ecus,
            FaultConfig::default(),
            blocked_access,
        );

        let request = tokio::spawn(async move {
            // The readiness guard and the name lookup are the caller's, exactly
            // as in production: pause at admission, then resolve against
            // whatever data the update left behind.
            let _communication_guard = manager.acquire_communication_guard()?;
            let data = manager.ecu_data.read().await;
            let ecu = UdsManager::<TestGateway, TestEcuDb>::resolve_ecu(&data, "TestECU")?;
            manager
                .send_with_raw_payload(
                    &ecu,
                    make_test_payload(service_ids::SESSION_CONTROL, &[0x01]),
                    Some(Duration::from_secs(1)),
                )
                .await
        });
        acquire_entered.notified().await;

        let lease = disable
            .disable(DisableReason::RuntimeUpdate)
            .await
            .expect("a request not yet admitted must not block the update");
        reloader.apply(ecu_data(HashMap::new())).await;
        lease.release().await.expect("communication resumes");

        acquire_proceed.wait();
        assert!(matches!(
            request.await.expect("request task"),
            Err(DiagServiceError::NotFound(_))
        ));
    }

    /// A lookup made after a runtime update observes the newly installed data;
    /// no ECU borrow taken from an earlier read can outlive the read guard it
    /// was resolved under.
    #[tokio::test]
    async fn applying_replaces_data_for_a_later_borrowed_lookup() {
        let old_ecus = HashMap::from_iter([(
            "TestECU".to_string(),
            RwLock::new(TestEcuDb::with_timeout_default(Duration::from_secs(1))),
        )]);
        let UdsManagerParts {
            manager, reloader, ..
        } = build_uds_manager(
            make_gateway(),
            old_ecus,
            FaultConfig::default(),
            disabled_communication_access(),
        );
        let data = manager.ecu_data.read().await;
        let old_timeout = data
            .ecus()
            .get("TestECU")
            .expect("ecu present before reload")
            .read()
            .await
            .timeout_default();
        assert_eq!(old_timeout, Duration::from_secs(1));
        drop(data);

        let new_ecus = HashMap::from_iter([(
            "TestECU".to_string(),
            RwLock::new(TestEcuDb::with_timeout_default(Duration::from_secs(9))),
        )]);
        reloader.apply(ecu_data(new_ecus)).await;
        let data = manager.ecu_data.read().await;
        let new_handle = data
            .ecus()
            .get("TestECU")
            .expect("ecu present after installation");
        assert_eq!(
            new_handle.read().await.timeout_default(),
            Duration::from_secs(9),
            "a lookup made after installation must observe the new data"
        );
    }

    #[tokio::test]
    async fn exclusive_disable_cannot_begin_until_admitted_request_completes() {
        let send_entered = Arc::new(Notify::new());
        let response_gate = Arc::new(Barrier::new(2));
        let gateway = TestGateway::new({
            let send_entered = Arc::clone(&send_entered);
            let response_gate = Arc::clone(&response_gate);
            move |_, response_tx, _| {
                send_entered.notify_one();
                let response_gate = Arc::clone(&response_gate);
                tokio::spawn(async move {
                    response_gate.wait().await;
                    let response = TransportResponse::UdsResponse(ServicePayload {
                        data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01],
                        source_address: 0x0001,
                        target_address: 0x0E00,
                        new_session: None,
                        new_security: None,
                    });
                    response_tx.send(Ok(Some(response))).await.ok();
                });
                Ok(finished_task())
            }
        });
        let (access, disable) = enabled_communication_for_test();
        let ecus = HashMap::from_iter([("TestECU".to_owned(), RwLock::new(TestEcuDb::new()))]);
        let manager = build_uds_manager(gateway, ecus, FaultConfig::default(), access).manager;
        let request = tokio::spawn(async move {
            // The readiness guard and the name lookup are the caller's, exactly
            // as in production: admission is taken first, then the ECU is
            // resolved out of the vehicle data that guard covers.
            let _communication_guard = manager.acquire_communication_guard()?;
            let data = manager.ecu_data.read().await;
            let ecu = UdsManager::<TestGateway, TestEcuDb>::resolve_ecu(&data, "TestECU")?;
            manager
                .send_with_raw_payload(
                    &ecu,
                    make_test_payload(service_ids::SESSION_CONTROL, &[0x01]),
                    Some(Duration::from_secs(1)),
                )
                .await
        });

        send_entered.notified().await;
        assert!(matches!(
            disable.disable(DisableReason::RuntimeUpdate).await,
            Err(DisableError::InUse)
        ));

        response_gate.wait().await;
        request
            .await
            .expect("request task")
            .expect("request completes before update admission");
        let lease = disable
            .disable(DisableReason::RuntimeUpdate)
            .await
            .expect("exclusive disable is admitted after request completion");
        drop(lease);
    }

    fn owner_test_manager(
        scope: &str,
    ) -> (
        UdsManager<TestGateway, TestEcuDb>,
        Arc<dyn ReloadComponent<VehicleEcuData<TestEcuDb>>>,
    ) {
        let parts = build_uds_manager(
            TestGateway::new(|_, _, _| Ok(finished_task())),
            HashMap::new(),
            FaultConfig {
                user_memory_scope: scope.to_owned(),
                ..FaultConfig::default()
            },
            enabled_communication_access_for_test(),
        );
        (parts.manager, parts.reloader)
    }

    fn owner_test_data(scope: &str) -> VehicleEcuData<TestEcuDb> {
        let (redetect_tx, _redetect_rx) = mpsc::channel(1);
        VehicleEcuData::new(
            HashMap::new(),
            &FunctionalDescriptionConfig::default(),
            FaultConfig {
                user_memory_scope: scope.to_owned(),
                ..FaultConfig::default()
            },
            Arc::new(EcuStateCoordinator::new(
                HashMap::new(),
                cda_interfaces::VariantDetectionSender::new(redetect_tx),
            )),
        )
    }

    /// The manager reads through the reloadable it was built with, so applying
    /// new data changes what it observes without replacing the manager.
    #[tokio::test]
    async fn applying_new_data_updates_what_the_uds_manager_reads() {
        let (manager, reloader) = owner_test_manager("current");
        assert_eq!(live_fault_scope(&manager).await, "current");
        reloader.apply(owner_test_data("replacement")).await;

        assert_eq!(live_fault_scope(&manager).await, "replacement");
    }

    fn ecu_data(ecus: HashMap<String, RwLock<TestEcuDb>>) -> VehicleEcuData<TestEcuDb> {
        let (redetect_tx, _redetect_rx) = mpsc::channel(1);
        VehicleEcuData::new(
            ecus,
            &FunctionalDescriptionConfig::default(),
            FaultConfig::default(),
            Arc::new(EcuStateCoordinator::new(
                HashMap::new(),
                cda_interfaces::VariantDetectionSender::new(redetect_tx),
            )),
        )
    }

    /// A manager over one detected ECU, with the given communication access.
    fn make_manager_with_ecu_and_access(
        gateway: TestGateway,
        communication_access: Arc<dyn CommunicationAccess>,
    ) -> UdsManager<TestGateway, TestEcuDb> {
        let ecus = HashMap::from_iter([(
            "TestECU".to_owned(),
            RwLock::new(TestEcuDb::with_detected_variant()),
        )]);
        build_uds_manager(gateway, ecus, FaultConfig::default(), communication_access).manager
    }

    #[tokio::test]
    async fn tester_present_starts_only_after_communication_is_ready() {
        let access = FakeCommunicationAccess::new(false, true);
        let manager = make_manager_with_ecu_and_access(make_gateway(), Arc::clone(&access) as _);
        let type_ = TesterPresentType::Ecu("TestECU".to_owned());

        let first = manager.start_tester_present(type_.clone()).await;

        assert!(matches!(
            first,
            Err(DiagServiceError::CommunicationNotReady {
                retry_after: TEST_COMMUNICATION_RETRY_AFTER,
                ..
            })
        ));
        assert!(!manager.check_tester_present_active(&type_).await);
        assert_eq!(access.activate_call_count(), 1);

        manager.start_tester_present(type_.clone()).await.unwrap();
        assert!(manager.check_tester_present_active(&type_).await);
        manager.stop_tester_present(type_).await.unwrap();
    }

    /// The state of a [`TesterPresentTask`] without its task handle, which can
    /// be neither cloned nor compared.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TesterPresentState {
        Running,
        Suspended,
    }

    impl From<&TesterPresentTask> for TesterPresentState {
        fn from(task: &TesterPresentTask) -> Self {
            match task {
                TesterPresentTask::Running(_) => Self::Running,
                TesterPresentTask::Suspended => Self::Suspended,
            }
        }
    }

    /// Reads whether `(type_, ecu)` is `Running`, `Suspended` or has no entry
    /// at all.
    ///
    /// `check_tester_present_active` intentionally treats `Suspended` the same
    /// as `Running` (a lock that wants tester present must not see it as
    /// absent just because communication is currently disabled), so tests
    /// that assert on the *actual* send state read the map directly instead.
    async fn tester_present_state(
        manager: &UdsManager<TestGateway, TestEcuDb>,
        type_: &TesterPresentType,
        ecu: &str,
    ) -> Option<TesterPresentState> {
        let tasks = manager.tester_present_tasks.read().await;
        tasks
            .get(&TesterPresentTaskId {
                type_: type_.clone(),
                ecu: ecu.to_owned(),
            })
            .map(TesterPresentState::from)
    }

    /// Disables communication the way the lifecycle worker does: the disable
    /// is claimed (`Disabling`), every hook is deinitialized, then the state
    /// settles at `Disabled`.
    async fn disable_communication(
        manager: &UdsManager<TestGateway, TestEcuDb>,
        access: &FakeCommunicationAccess,
    ) {
        access.begin_disabling();
        manager.deinitialize().await;
        access.finish_disabling();
    }

    /// Runs a successful activation the way the lifecycle worker does:
    /// `initialize` while `Enabling`, then `Enabled` is published, then
    /// `on_enabled`.
    async fn enable_communication(
        manager: &UdsManager<TestGateway, TestEcuDb>,
        access: &FakeCommunicationAccess,
    ) {
        access.begin_enabling();
        manager.initialize().await.unwrap();
        access.finish_enabling();
        manager.on_enabled().await;
    }

    /// `initialize()` only (re)starts the variant-detection listener; it must
    /// not resume tester present. Resuming happens later, from `on_enabled()`,
    /// once the state is actually `Enabled`.
    #[tokio::test]
    async fn initialize_does_not_resume_tester_present() {
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(make_gateway(), Arc::clone(&access) as _);
        let type_ = TesterPresentType::Ecu("TestECU".to_owned());

        manager.start_tester_present(type_.clone()).await.unwrap();
        disable_communication(&manager, &access).await;

        access.finish_enabling();
        manager.initialize().await.unwrap();

        assert_eq!(
            tester_present_state(&manager, &type_, "TestECU").await,
            Some(TesterPresentState::Suspended),
            "initialize() must not resume tester present"
        );

        manager.stop_tester_present(type_).await.unwrap();
    }

    /// A disable -> enable cycle resumes every suspended entry by the time
    /// `on_enabled()` returns: no task, no wait.
    #[tokio::test]
    async fn on_enabled_resumes_suspended_entries() {
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(make_gateway(), Arc::clone(&access) as _);
        let type_ = TesterPresentType::Ecu("TestECU".to_owned());

        manager.start_tester_present(type_.clone()).await.unwrap();
        disable_communication(&manager, &access).await;
        assert_eq!(
            tester_present_state(&manager, &type_, "TestECU").await,
            Some(TesterPresentState::Suspended)
        );

        enable_communication(&manager, &access).await;

        assert_eq!(
            tester_present_state(&manager, &type_, "TestECU").await,
            Some(TesterPresentState::Running),
            "on_enabled() must resume a suspended entry once Enabled"
        );

        manager.stop_tester_present(type_).await.unwrap();
    }

    /// `Enabled` is published before the worker calls `on_enabled()`, so a
    /// disable can be claimed in between. `acquire()` then fails with
    /// `Disabling`, and the suspended entries are left alone for the next
    /// activation to resume.
    #[tokio::test]
    async fn on_enabled_keeps_entries_suspended_when_disable_is_claimed_first() {
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(make_gateway(), Arc::clone(&access) as _);
        let type_ = TesterPresentType::Ecu("TestECU".to_owned());

        manager.start_tester_present(type_.clone()).await.unwrap();
        disable_communication(&manager, &access).await;

        access.begin_enabling();
        manager.initialize().await.unwrap();
        access.finish_enabling();
        access.begin_disabling();
        manager.on_enabled().await;

        assert_eq!(
            tester_present_state(&manager, &type_, "TestECU").await,
            Some(TesterPresentState::Suspended),
            "on_enabled() must not resume while a disable is in progress"
        );

        manager.deinitialize().await;
        access.finish_disabling();
        enable_communication(&manager, &access).await;

        assert_eq!(
            tester_present_state(&manager, &type_, "TestECU").await,
            Some(TesterPresentState::Running),
            "the next successful activation must resume the entry"
        );

        manager.stop_tester_present(type_).await.unwrap();
    }

    /// A lock released while communication is disabled must not
    /// get its tester present back once communication is re-enabled. The
    /// suspended entry is the only record of tester-present state, removing it
    /// via `stop_tester_present` must take effect even though communication is
    /// disabled at the time.
    #[tokio::test]
    async fn stopped_while_suspended_is_not_resumed() {
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(make_gateway(), Arc::clone(&access) as _);
        let type_ = TesterPresentType::Ecu("TestECU".to_owned());

        manager.start_tester_present(type_.clone()).await.unwrap();
        disable_communication(&manager, &access).await;

        // The lock expires (or is deleted) while communication is disabled.
        manager.stop_tester_present(type_.clone()).await.unwrap();

        enable_communication(&manager, &access).await;

        assert_eq!(
            tester_present_state(&manager, &type_, "TestECU").await,
            None,
            "a lock released while communication was disabled must not get tester present back"
        );
    }

    /// Same as [`stopped_while_suspended_is_not_resumed`], but the lock is
    /// released while the activation is still `Enabling`, after `initialize`
    /// already ran. The stop must win: `on_enabled` must not bring it back.
    #[tokio::test]
    async fn stop_during_enabling_wins_over_resume() {
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(make_gateway(), Arc::clone(&access) as _);
        let type_ = TesterPresentType::Ecu("TestECU".to_owned());

        manager.start_tester_present(type_.clone()).await.unwrap();
        disable_communication(&manager, &access).await;

        access.begin_enabling();
        manager.initialize().await.unwrap();
        manager.stop_tester_present(type_.clone()).await.unwrap();
        access.finish_enabling();
        manager.on_enabled().await;

        assert_eq!(
            tester_present_state(&manager, &type_, "TestECU").await,
            None,
            "a stop that arrives while communication is Enabling must win over the resume"
        );
    }

    /// An activation can end after `initialize` ran but before it reaches
    /// `Enabled`, when a later lifecycle hook or whole-vehicle detection fails
    /// and the worker deinitializes every hook that already ran. `on_enabled`
    /// is then never called for that activation, but the suspended entry it
    /// would have resumed must survive for the next one.
    #[tokio::test]
    async fn suspended_entry_survives_an_activation_that_never_reaches_enabled() {
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(make_gateway(), Arc::clone(&access) as _);
        let type_ = TesterPresentType::Ecu("TestECU".to_owned());

        manager.start_tester_present(type_.clone()).await.unwrap();
        disable_communication(&manager, &access).await;

        // First activation fails after `initialize`: no `on_enabled`, and
        // every hook that already ran is deinitialized.
        access.begin_enabling();
        manager.initialize().await.unwrap();
        manager.deinitialize().await;
        access.abort_enabling();
        assert_eq!(
            tester_present_state(&manager, &type_, "TestECU").await,
            Some(TesterPresentState::Suspended)
        );

        // Second activation reaches `Enabled`.
        enable_communication(&manager, &access).await;

        assert_eq!(
            tester_present_state(&manager, &type_, "TestECU").await,
            Some(TesterPresentState::Running),
            "tester present must be resumed by the next successful activation"
        );

        manager.stop_tester_present(type_).await.unwrap();
    }

    /// `start_tester_present` must resume an entry that is `Suspended` rather
    /// than leaving it suspended or spawning a duplicate task, so a lock
    /// acquired again after `Enabled` is published but before the worker has
    /// called `on_enabled` still gets working tester present. The later
    /// `on_enabled` must then leave that running task alone.
    #[tokio::test]
    async fn start_on_suspended_resumes_entry() {
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(make_gateway(), Arc::clone(&access) as _);
        let type_ = TesterPresentType::Ecu("TestECU".to_owned());
        let key = TesterPresentTaskId {
            type_: type_.clone(),
            ecu: "TestECU".to_owned(),
        };
        let running_task_id =
            |tasks: &HashMap<TesterPresentTaskId, TesterPresentTask>| match tasks.get(&key) {
                Some(TesterPresentTask::Running(handle)) => handle.id(),
                _ => panic!("expected a running entry"),
            };

        manager.start_tester_present(type_.clone()).await.unwrap();
        disable_communication(&manager, &access).await;

        access.begin_enabling();
        manager.initialize().await.unwrap();
        access.finish_enabling();

        manager.start_tester_present(type_.clone()).await.unwrap();
        let started = running_task_id(&*manager.tester_present_tasks.read().await);

        manager.on_enabled().await;
        let after_on_enabled = running_task_id(&*manager.tester_present_tasks.read().await);

        assert_eq!(
            started, after_on_enabled,
            "on_enabled must not replace a task start_tester_present already resumed"
        );

        manager.stop_tester_present(type_).await.unwrap();
    }

    /// `shutdown()` drains the tester-present map, so an `on_enabled` that
    /// runs afterwards finds nothing suspended and spawns nothing.
    #[tokio::test]
    async fn on_enabled_after_shutdown_does_not_resume() {
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(make_gateway(), Arc::clone(&access) as _);
        let type_ = TesterPresentType::Ecu("TestECU".to_owned());

        manager.start_tester_present(type_).await.unwrap();
        disable_communication(&manager, &access).await;

        cda_interfaces::Shutdown::shutdown(&manager).await;
        access.begin_enabling();
        access.finish_enabling();
        manager.on_enabled().await;

        assert!(
            manager.tester_present_tasks.read().await.is_empty(),
            "on_enabled after shutdown must not spawn tester present"
        );
    }

    /// Like [`make_gateway`], but counts every request it receives.
    fn make_counting_gateway(sends: Arc<std::sync::atomic::AtomicUsize>) -> TestGateway {
        TestGateway::new(move |_, response_tx, _| {
            sends.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let msg = TransportResponse::UdsResponse(ServicePayload {
                data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01],
                source_address: 0x0001,
                target_address: 0x0E00,
                new_session: None,
                new_security: None,
            });
            response_tx.try_send(Ok(Some(msg))).ok();
            Ok(finished_task())
        })
    }

    async fn set_tracked_state(manager: &UdsManager<TestGateway, TestEcuDb>, sid: u8, value: &str) {
        test_ecu(manager)
            .await
            .read()
            .await
            .set_service_state(sid, value.to_owned())
            .await;
    }

    async fn tracked_session(manager: &UdsManager<TestGateway, TestEcuDb>) -> String {
        test_ecu(manager)
            .await
            .read()
            .await
            .session()
            .await
            .unwrap()
    }

    fn is_deferred(tasks: &HashMap<String, ResetTask>) -> bool {
        matches!(tasks.get("TestECU"), Some(ResetTask::Deferred))
    }

    /// A lock that expires while communication is disabled must still reset
    /// the ECU session. Nothing is sent and no activation is requested while
    /// disabled; the reset is sent once communication is enabled again.
    #[tokio::test]
    async fn session_reset_while_disabled_is_sent_once_enabled() {
        let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(
            make_counting_gateway(Arc::clone(&sends)),
            Arc::clone(&access) as _,
        );
        set_tracked_state(&manager, service_ids::SESSION_CONTROL, "extended").await;
        disable_communication(&manager, &access).await;

        let outcome = manager.reset_ecu_session("TestECU").await.unwrap();

        assert_eq!(outcome, ResetOutcome::Deferred);
        assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            access.activate_call_count(),
            0,
            "a deferred reset must not switch communication on"
        );
        assert!(is_deferred(&*manager.session_reset_tasks.read().await));

        enable_communication(&manager, &access).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while tracked_session(&manager).await != "default" {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the deferred session reset must run once communication is enabled");

        assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(manager.session_reset_tasks.read().await.is_empty());
    }

    /// The timed reset scheduled from a session's `mode_expiration` may fire
    /// while communication is disabled. It must be deferred without sending
    /// anything or requesting activation, and sent once communication is
    /// enabled again.
    #[tokio::test]
    async fn timed_session_reset_firing_while_disabled_is_sent_once_enabled() {
        tokio::time::pause();
        let expiration = Duration::from_millis(50);
        let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(
            make_counting_gateway(Arc::clone(&sends)),
            Arc::clone(&access) as _,
        );
        set_tracked_state(&manager, service_ids::SESSION_CONTROL, "default").await;

        manager
            .set_ecu_session(
                "TestECU",
                "extended",
                &(Box::new(()) as DynamicPlugin),
                Some(expiration),
            )
            .await
            .unwrap();
        assert_eq!(tracked_session(&manager).await, "extended");
        let sends_after_set = sends.load(std::sync::atomic::Ordering::SeqCst);

        disable_communication(&manager, &access).await;
        tokio::time::advance(expiration).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while !is_deferred(&*manager.session_reset_tasks.read().await) {
                cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the timed session reset must be deferred while disabled");

        assert_eq!(
            sends.load(std::sync::atomic::Ordering::SeqCst),
            sends_after_set
        );
        assert_eq!(
            access.activate_call_count(),
            0,
            "a deferred reset must not switch communication on"
        );
        assert_eq!(tracked_session(&manager).await, "extended");

        enable_communication(&manager, &access).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while tracked_session(&manager).await != "default" {
                cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the deferred session reset must run once communication is enabled");

        assert_eq!(
            sends.load(std::sync::atomic::Ordering::SeqCst),
            sends_after_set + 1
        );
        assert!(manager.session_reset_tasks.read().await.is_empty());
    }

    /// The security-access reset is deferred the same way while
    /// communication is disabled.
    #[tokio::test]
    async fn security_access_reset_while_disabled_is_deferred() {
        let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(
            make_counting_gateway(Arc::clone(&sends)),
            Arc::clone(&access) as _,
        );
        set_tracked_state(&manager, service_ids::SECURITY_ACCESS, "level_01").await;
        disable_communication(&manager, &access).await;

        let outcome = manager.reset_ecu_security_access("TestECU").await.unwrap();

        assert_eq!(outcome, ResetOutcome::Deferred);
        assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(access.activate_call_count(), 0);
        assert!(is_deferred(&*manager.security_reset_tasks.read().await));
    }

    /// A session set after communication is enabled again, but before
    /// `on_enabled` ran, makes the deferred reset obsolete: it must not
    /// overwrite the new session.
    #[tokio::test]
    async fn session_set_after_enable_discards_deferred_reset() {
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(make_gateway(), Arc::clone(&access) as _);
        set_tracked_state(&manager, service_ids::SESSION_CONTROL, "extended").await;
        disable_communication(&manager, &access).await;
        manager.reset_ecu_session("TestECU").await.unwrap();

        access.begin_enabling();
        manager.initialize().await.unwrap();
        access.finish_enabling();
        manager
            .set_ecu_session(
                "TestECU",
                "programming",
                &(Box::new(()) as DynamicPlugin),
                None,
            )
            .await
            .unwrap();
        manager.on_enabled().await;

        assert!(manager.session_reset_tasks.read().await.is_empty());
        assert_eq!(tracked_session(&manager).await, "programming");
    }

    /// `shutdown()` drops deferred resets along with every other pending
    /// reset, so a later `on_enabled` sends nothing.
    #[tokio::test]
    async fn shutdown_drops_deferred_resets() {
        let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(
            make_counting_gateway(Arc::clone(&sends)),
            Arc::clone(&access) as _,
        );
        set_tracked_state(&manager, service_ids::SESSION_CONTROL, "extended").await;
        disable_communication(&manager, &access).await;
        manager.reset_ecu_session("TestECU").await.unwrap();

        cda_interfaces::Shutdown::shutdown(&manager).await;
        access.begin_enabling();
        access.finish_enabling();
        manager.on_enabled().await;

        assert!(manager.session_reset_tasks.read().await.is_empty());
        assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// `stop_tester_present(Functional(group))` must remove every entry of
    /// that type regardless of current group membership, so an ECU that left
    /// the group between start and stop does not leak a running task.
    #[tokio::test]
    async fn functional_stop_removes_all_keys_of_type() {
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(make_gateway(), Arc::clone(&access) as _);
        let group_type = TesterPresentType::Functional("group".to_owned());

        // Seed entries directly: the manager's `TestEcuDb` does not implement
        // functional-group membership, so this bypasses
        // `ecus_for_functional_group` to isolate `stop_tester_present`'s
        // removal behavior from group resolution.
        {
            let mut tasks = manager.tester_present_tasks.write().await;
            tasks.insert(
                TesterPresentTaskId {
                    type_: group_type.clone(),
                    ecu: "member-still-in-group".to_owned(),
                },
                TesterPresentTask::Suspended,
            );
            tasks.insert(
                TesterPresentTaskId {
                    type_: group_type.clone(),
                    ecu: "member-that-left-the-group".to_owned(),
                },
                TesterPresentTask::Suspended,
            );
        }

        manager
            .stop_tester_present(group_type.clone())
            .await
            .unwrap();

        let tasks = manager.tester_present_tasks.read().await;
        assert!(
            !tasks.keys().any(|id| id.type_ == group_type),
            "stop must remove every entry of the type, including members no longer in the group"
        );
    }

    /// Acquiring a functional lock replaces the physical tester present of a
    /// covered ECU: both entries can be suspended independently, and stopping
    /// the functional entry must not disturb the ECU's own entry.
    #[tokio::test]
    async fn ecu_tp_survives_functional_stop_while_suspended() {
        let access = FakeCommunicationAccess::new(true, true);
        let manager = make_manager_with_ecu_and_access(make_gateway(), Arc::clone(&access) as _);
        let ecu_type = TesterPresentType::Ecu("TestECU".to_owned());
        let group_type = TesterPresentType::Functional("group".to_owned());

        {
            let mut tasks = manager.tester_present_tasks.write().await;
            tasks.insert(
                TesterPresentTaskId {
                    type_: ecu_type.clone(),
                    ecu: "TestECU".to_owned(),
                },
                TesterPresentTask::Suspended,
            );
            tasks.insert(
                TesterPresentTaskId {
                    type_: group_type.clone(),
                    ecu: "TestECU".to_owned(),
                },
                TesterPresentTask::Suspended,
            );
        }

        manager
            .stop_tester_present(group_type.clone())
            .await
            .unwrap();

        let tasks = manager.tester_present_tasks.read().await;
        assert!(
            tasks.contains_key(&TesterPresentTaskId {
                type_: ecu_type,
                ecu: "TestECU".to_owned(),
            }),
            "the ECU's own tester-present entry must survive the functional stop"
        );
        assert!(!tasks.keys().any(|id| id.type_ == group_type));
    }
}

#[cfg(test)]
mod pre_send_authorization_tests {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicU32, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use cda_interfaces::{
        DiagServiceError, DynamicPlugin, EcuStateManager, HashMap, ResetOutcome, ServicePayload,
        TransportResponse, UDS_ID_RESPONSE_BITMASK, UdsSession,
        datatypes::FaultConfig,
        request_authorization::{RequestLockContext, RequestLockProvider, UdsRequestTarget},
        service_ids,
    };
    use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
    use tokio::sync::RwLock;

    use crate::{
        UdsManager,
        test_helpers::{
            RequestSendPolicy, TestEcuDb, TestGateway, build_uds_manager_with_lock_provider,
            finished_task,
        },
    };

    type SentContext = (UdsRequestTarget, ServicePayload, Option<RequestLockContext>);

    struct FixedLock(Option<RequestLockContext>);

    #[async_trait]
    impl RequestLockProvider for FixedLock {
        async fn current_lock(&self, _target: &UdsRequestTarget) -> Option<RequestLockContext> {
            self.0.clone()
        }
    }

    /// Plugin of a caller. The void plugin `()` marks internal traffic and is never checked.
    fn caller_plugin() -> DynamicPlugin {
        Box::new("caller".to_owned())
    }

    fn payload() -> ServicePayload {
        ServicePayload {
            data: vec![service_ids::SESSION_CONTROL, 0x03],
            source_address: 0x0E00,
            target_address: 0x0001,
            new_session: Some("extended".to_owned()),
            new_security: None,
        }
    }

    fn lock() -> RequestLockContext {
        RequestLockContext {
            holder: "holder-sub".to_owned(),
            claims: serde_json::Map::from_iter([("scope".to_owned(), "x".into())]),
            metadata: serde_json::Map::from_iter([("use_case".to_owned(), "sw_update".into())]),
        }
    }

    /// Gateway counting transmissions. It answers positively unless `silent` is set,
    /// in which case every attempt times out.
    fn counting_gateway(silent: bool) -> (TestGateway, Arc<AtomicU32>) {
        let sends = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&sends);
        let gateway = TestGateway::new(move |_, response_tx, _| {
            counter.fetch_add(1, Ordering::SeqCst);
            if silent {
                // Keep the channel open until the caller gives up, so its
                // receive timeout fires.
                return Ok(tokio::spawn(async move { response_tx.closed().await }));
            }
            let message = TransportResponse::UdsResponse(ServicePayload {
                data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x03],
                source_address: 0x0001,
                target_address: 0x0E00,
                new_session: None,
                new_security: None,
            });
            response_tx.try_send(Ok(Some(message))).ok();
            Ok(finished_task())
        });
        (gateway, sends)
    }

    fn manager(
        gateway: TestGateway,
        policy: Arc<RequestSendPolicy>,
        lock: Option<RequestLockContext>,
    ) -> UdsManager<TestGateway, TestEcuDb> {
        let ecu =
            TestEcuDb::with_timeout_default_and_repeat_req_count_app(Duration::from_millis(20), 2)
                .detected()
                .with_request_send_policy(policy);
        let ecus = HashMap::from_iter([("TestECU".to_owned(), RwLock::new(ecu))]);
        build_uds_manager_with_lock_provider(
            gateway,
            ecus,
            FaultConfig::default(),
            enabled_communication_access_for_test(),
            Arc::new(FixedLock(lock)),
        )
        .manager
    }

    async fn send(
        manager: &UdsManager<TestGateway, TestEcuDb>,
        plugin: Option<&DynamicPlugin>,
    ) -> Result<Option<ServicePayload>, DiagServiceError> {
        let data = manager.ecu_data.read().await;
        let ecu = UdsManager::<TestGateway, TestEcuDb>::resolve_ecu(&data, "TestECU")?;
        manager
            .send_authorized_raw_payload(&ecu, payload(), plugin, None)
            .await
    }

    #[tokio::test]
    async fn allowed_request_is_sent_once_with_exact_context() {
        let seen: Arc<Mutex<Vec<SentContext>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let (gateway, sends) = counting_gateway(false);
        let manager = manager(
            gateway,
            Arc::new(move |context| {
                recorder.lock().unwrap().push((
                    context.target.clone(),
                    context.payload.clone(),
                    context.lock.clone(),
                ));
                Ok(())
            }),
            Some(lock()),
        );
        let plugin = caller_plugin();

        send(&manager, Some(&plugin)).await.expect("send allowed");

        assert_eq!(sends.load(Ordering::SeqCst), 1);
        let seen = seen.lock().unwrap();
        let [(target, sent, lock_context)] = seen.as_slice() else {
            panic!(
                "expected exactly one authorization call, got {}",
                seen.len()
            );
        };
        assert_eq!(
            *target,
            UdsRequestTarget::Ecu {
                name: "TestECU".to_owned(),
                additional_fields: Vec::new(),
            }
        );
        assert_eq!(sent.data, payload().data);
        assert_eq!(sent.source_address, 0x0E00);
        assert_eq!(sent.target_address, 0x0001);
        assert_eq!(sent.new_session.as_deref(), Some("extended"));
        assert_eq!(lock_context.as_ref(), Some(&lock()));
    }

    #[tokio::test]
    async fn denied_request_sends_nothing_and_reports_request_not_allowed() {
        let (gateway, sends) = counting_gateway(false);
        let manager = manager(
            gateway,
            Arc::new(|_| Err(DiagServiceError::RequestNotAllowed("denied".to_owned()))),
            None,
        );
        let plugin = caller_plugin();

        let result = send(&manager, Some(&plugin)).await;

        assert!(
            matches!(result, Err(DiagServiceError::RequestNotAllowed(_))),
            "unexpected result: {result:?}"
        );
        assert_eq!(sends.load(Ordering::SeqCst), 0, "no bytes may be sent");
    }

    #[tokio::test]
    async fn every_retry_is_authorized_before_it_is_sent() {
        let checks = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&checks);
        let (gateway, sends) = counting_gateway(true);
        let manager = manager(
            gateway,
            Arc::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            None,
        );
        let plugin = caller_plugin();

        let result = send(&manager, Some(&plugin)).await;

        assert!(
            matches!(result, Err(DiagServiceError::Timeout)),
            "{result:?}"
        );
        // One original transmission plus two application-level repeats.
        assert_eq!(sends.load(Ordering::SeqCst), 3);
        assert_eq!(
            checks.load(Ordering::SeqCst),
            sends.load(Ordering::SeqCst),
            "each transmission needs its own authorization"
        );
    }

    #[tokio::test]
    async fn denial_on_a_retry_prevents_the_next_frame() {
        let checks = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&checks);
        let (gateway, sends) = counting_gateway(true);
        let manager = manager(
            gateway,
            Arc::new(move |_| {
                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(())
                } else {
                    Err(DiagServiceError::RequestNotAllowed("revoked".to_owned()))
                }
            }),
            None,
        );
        let plugin = caller_plugin();

        let result = send(&manager, Some(&plugin)).await;

        assert!(
            matches!(result, Err(DiagServiceError::RequestNotAllowed(_))),
            "{result:?}"
        );
        assert_eq!(
            sends.load(Ordering::SeqCst),
            1,
            "only the first frame is sent"
        );
    }

    #[tokio::test]
    async fn physical_authorization_alone_never_touches_the_gateway() {
        let (gateway, sends) = counting_gateway(false);
        let manager = manager(
            gateway,
            Arc::new(|context| {
                // A flash transfer is authorized with its TransferData probe frame.
                assert_eq!(context.payload.data, [service_ids::TRANSFER_DATA, 1]);
                Err(DiagServiceError::RequestNotAllowed("no 0x36".to_owned()))
            }),
            Some(lock()),
        );
        let plugin = caller_plugin();
        let data = manager.ecu_data.read().await;
        let ecu = data.ecus().get("TestECU").expect("test ECU exists");
        let probe = ServicePayload {
            data: vec![service_ids::TRANSFER_DATA, 1],
            source_address: 0x0E00,
            target_address: 0x0001,
            new_session: None,
            new_security: None,
        };

        let result = manager
            .authorize_physical_send(ecu, "TestECU", &plugin, &probe)
            .await;

        assert!(matches!(
            result,
            Err(DiagServiceError::RequestNotAllowed(_))
        ));
        assert_eq!(sends.load(Ordering::SeqCst), 0);
    }

    /// Resets, including those run by lock cleanup, must always reach the ECU, even if the
    /// pre-send authorization would deny every request.
    #[tokio::test]
    async fn session_reset_is_sent_even_if_authorization_would_deny() {
        let checks = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&checks);
        let sends = Arc::new(AtomicU32::new(0));
        let send_counter = Arc::clone(&sends);
        let gateway = TestGateway::new(move |_, response_tx, _| {
            send_counter.fetch_add(1, Ordering::SeqCst);
            let message = TransportResponse::UdsResponse(ServicePayload {
                data: crate::test_helpers::positive_session_response(),
                source_address: 0x0001,
                target_address: 0x0E00,
                new_session: None,
                new_security: None,
            });
            response_tx.try_send(Ok(Some(message))).ok();
            Ok(finished_task())
        });
        let manager = manager(
            gateway,
            Arc::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Err(DiagServiceError::RequestNotAllowed("denied".to_owned()))
            }),
            None,
        );
        {
            let data = manager.ecu_data.read().await;
            data.ecus()
                .get("TestECU")
                .expect("test ECU exists")
                .read()
                .await
                .set_service_state(service_ids::SESSION_CONTROL, "extended".to_owned())
                .await;
        }

        let outcome = manager
            .reset_ecu_session("TestECU")
            .await
            .expect("reset must not be blocked");

        assert_eq!(outcome, ResetOutcome::Completed);
        assert_eq!(sends.load(Ordering::SeqCst), 1, "the reset frame is sent");
        assert_eq!(
            checks.load(Ordering::SeqCst),
            0,
            "resets must not be subject to the pre-send authorization"
        );
    }

    #[tokio::test]
    async fn internal_traffic_without_plugin_skips_authorization() {
        let checks = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&checks);
        let (gateway, sends) = counting_gateway(false);
        let manager = manager(
            gateway,
            Arc::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Err(DiagServiceError::RequestNotAllowed(
                    "must not run".to_owned(),
                ))
            }),
            None,
        );

        let data = manager.ecu_data.read().await;
        let ecu = UdsManager::<TestGateway, TestEcuDb>::resolve_ecu(&data, "TestECU")
            .expect("test ECU exists");
        manager
            .send_with_raw_payload(&ecu, payload(), None)
            .await
            .expect("internal send is not subject to caller authorization");

        assert_eq!(checks.load(Ordering::SeqCst), 0);
        assert_eq!(sends.load(Ordering::SeqCst), 1);
    }
}
