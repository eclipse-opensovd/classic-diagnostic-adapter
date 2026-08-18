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
    UdsTransport, UdsVariant, VariantDetection, VariantState,
    datatypes::RetryPolicy,
    diagservices::{DiagServiceResponse, UdsPayloadData},
    dlt_ctx, service_ids,
};
use tokio::sync::{RwLock, Semaphore, mpsc};

use crate::{UdsEcuDb, UdsManager, types::UdsParameters};

/// Upper bound on how long `send_with_raw_payload` waits for a *previous*
/// attempt's per-request gateway task to actually finish (per its returned
/// `JoinHandle`) before issuing the next application-layer retry attempt.
///
/// Dropping the previous attempt's response channel only *signals* that task
/// to stop; it does not guarantee the task has released whatever per-ECU
/// resource it holds (e.g. a `DoIP` connection mutex, or - critically for CAN,
/// which has no equivalent per-connection lock - an ISO-TP socket bound to
/// the same CAN ID pair the next attempt is about to open). Awaiting the
/// handle closes that gap. This wait is bounded so a gateway task that never
/// finishes cannot stall retries indefinitely; if the grace period elapses,
/// the next attempt proceeds anyway and a warning is logged.
const RETRY_TEARDOWN_GRACE: Duration = Duration::from_millis(500);

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

        // Inspect the subfunction byte for `suppressPosRspMsgIndicationBit` (bit 7).
        // When set, the ECU is not expected to send a positive response, so the
        // absence of a response must not be treated as a timeout/error (mirrors
        // the same check already applied for functional sends, see
        // `send_functional_to_gateway`).
        let expect_response = !payload.is_suppress_positive_response();

        let response = self
            .send_with_raw_payload(ecu_name, payload.clone(), timeout, expect_response)
            .await;
        let response_after = start.elapsed().saturating_sub(payload_build_after);

        let response = match response {
            Ok(Some(msg)) => {
                self.uds_ecu_db(ecu_name)
                    .expect("ECU name has been already checked")
                    .read()
                    .await
                    .convert_from_uds(&service, &msg, map_to_json, None)
                    .await
            }
            Ok(None) => {
                // Only reachable when `expect_response` was `false`, i.e. the
                // suppress-positive-response bit was set: the ECU legitimately
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

        // Counts application-layer retries per ISO 14229-2:2021 Table 9
        // ("Client error handling"): a transmission failure, a raw receive
        // error, or a plain timeout with no response at all shall each cause
        // the client to repeat the last request, up to `CP_RepeatReqCountApp`
        // times (independent of, and not to be confused with, the NRC
        // 0x21/0x78/0x94 busy-repeat handling below, which has its own,
        // separate time-bounded retry policy).
        let mut app_retry_count: u32 = 0;

        // Handle of the previous attempt's per-request gateway task, if any.
        // Awaited (bounded by `RETRY_TEARDOWN_GRACE`) at the top of the next
        // loop iteration before that attempt is sent, see below.
        let mut previous_task_handle: Option<tokio::task::JoinHandle<()>> = None;

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
            // which has no equivalent lock). Await its handle - bounded by
            // `RETRY_TEARDOWN_GRACE` - before sending the next attempt, so
            // the two per-request tasks don't run concurrently against the
            // same resource.
            if let Some(handle) = previous_task_handle.take() {
                await_stale_gateway_task(handle, ecu_name).await;
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
                Ok(handle) => previous_task_handle = Some(handle),
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

        // See `send_without_variant_guard` for why this bit must be respected.
        let expect_response = !payload.is_suppress_positive_response();

        match self
            .send_with_raw_payload(ecu_name, payload, timeout, expect_response)
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

/// Waits, bounded by [`RETRY_TEARDOWN_GRACE`], for a previous attempt's
/// per-request gateway task to finish before the caller proceeds with the
/// next application-layer retry attempt.
///
/// Dropping the previous attempt's response channel only signals that task to
/// stop; this actually confirms it has finished (and released whatever
/// per-ECU resource it was holding), closing the race between a stale task
/// and the next attempt's fresh one. If the grace period elapses first, a
/// warning is logged and the caller proceeds anyway, so a misbehaving gateway
/// task cannot stall retries indefinitely.
async fn await_stale_gateway_task(handle: tokio::task::JoinHandle<()>, ecu_name: &str) {
    match tokio::time::timeout(RETRY_TEARDOWN_GRACE, handle).await {
        Ok(Ok(())) => {}
        Ok(Err(join_err)) => {
            tracing::debug!(
                ecu_name,
                error = %join_err,
                "Previous attempt's gateway task ended abnormally while tearing down"
            );
        }
        Err(_elapsed) => {
            tracing::warn!(
                ecu_name,
                grace_period = ?RETRY_TEARDOWN_GRACE,
                "Previous attempt's gateway task did not finish within the teardown grace \
                 period before starting the next retry"
            );
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
mod send_tests {
    use std::{
        sync::{Arc, atomic::AtomicBool},
        time::{Duration, Instant},
    };

    use cda_interfaces::{
        DiagServiceError, EcuAddresses, EcuGateway, EcuRuntimeState, EcuStateManager,
        FunctionalTransport, HashMap, HashMapExtensions, NetworkTopology, PendingNrc,
        PhysicalTransport, ServicePayload, TransmissionParameters, TransportResponse,
        UDS_ID_RESPONSE_BITMASK, VariantDetection, datatypes::FaultConfig, service_ids,
    };
    use tokio::sync::{RwLock, mpsc};

    use super::RETRY_TEARDOWN_GRACE;
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

    impl PhysicalTransport for TestGateway {
        fn send(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
            expect_uds_reply: bool,
        ) -> impl Future<Output = Result<tokio::task::JoinHandle<()>, DiagServiceError>> + Send
        {
            // The closure receives `response_sender` by value and fully owns its
            // lifetime, mirroring how the real gateways manage their per-request
            // task's sender:
            //   * to model a gateway that closes the channel after forwarding
            //     its frame(s) (e.g. the CAN gateway breaking after the first
            //     SID-matching response), simply let the sender drop when the
            //     closure returns -> the caller's `recv()` observes `None`.
            //   * to model a gateway task that stays parked with no (further)
            //     response until the caller gives up (e.g. an offline/answer-
            //     suppressing ECU), the closure must keep the sender alive
            //     itself (store a clone), so the caller's `rx_timeout` fires.
            let result = (self.send_fn)(response_sender, expect_uds_reply);
            async move {
                result?;
                // This test double's "task" is already fully done by the time
                // `send` returns (the closure above ran synchronously), so the
                // returned handle resolves essentially instantly. Tests that
                // need to exercise the retry-teardown synchronization itself
                // use `SlowTeardownGateway` instead.
                Ok(tokio::task::spawn(std::future::ready(())))
            }
        }

        fn ecu_online<T: EcuAddresses>(
            &self,
            _ecu_name: &str,
            _ecu_db: &RwLock<T>,
        ) -> impl Future<Output = Result<(), DiagServiceError>> + Send {
            std::future::ready(Ok(()))
        }
    }

    /// Test gateway dedicated to exercising the retry-teardown synchronization
    /// in `send_with_raw_payload`: every `send` call immediately closes its
    /// response channel (as a stale gateway task would once it has forwarded
    /// its last usable message and moved to shutting down), but the *returned
    /// task handle* only resolves after `task_delay`, modelling a per-request
    /// task that is slow to actually finish (e.g. still releasing a
    /// connection lock or socket).
    ///
    /// Every invocation's timestamp is recorded in `send_times`, so tests can
    /// assert on the gap between successive attempts to verify the caller
    /// waited for the previous attempt's handle before issuing the next one.
    #[derive(Clone)]
    struct SlowTeardownGateway {
        task_delay: Duration,
        send_times: Arc<std::sync::Mutex<Vec<Instant>>>,
    }

    impl PhysicalTransport for SlowTeardownGateway {
        fn send(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
            _expect_uds_reply: bool,
        ) -> impl Future<Output = Result<tokio::task::JoinHandle<()>, DiagServiceError>> + Send
        {
            self.send_times.lock().unwrap().push(Instant::now());
            let delay = self.task_delay;
            async move {
                // Simulate the stale task's response-forwarding phase already
                // being over: drop the sender right away so the caller's
                // `recv()` observes the channel closing immediately, well
                // before `delay` elapses.
                drop(response_sender);
                Ok(tokio::task::spawn(async move {
                    cda_interfaces::util::tokio_ext::sleep_for(delay).await;
                }))
            }
        }

        fn ecu_online<T: EcuAddresses>(
            &self,
            _ecu_name: &str,
            _ecu_db: &RwLock<T>,
        ) -> impl Future<Output = Result<(), DiagServiceError>> + Send {
            std::future::ready(Ok(()))
        }
    }

    impl FunctionalTransport for SlowTeardownGateway {
        fn send_functional(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            _expected_ecu_logical_addrs: HashMap<u16, String>,
            _timeout: Duration,
            _expect_positive_response: bool,
        ) -> impl Future<
            Output = Result<
                HashMap<String, Result<ServicePayload, DiagServiceError>>,
                DiagServiceError,
            >,
        > + Send {
            std::future::ready(Ok(HashMap::new()))
        }
    }

    impl NetworkTopology for SlowTeardownGateway {
        fn get_gateway_network_address(
            &self,
            _logical_address: u16,
        ) -> impl Future<Output = Option<String>> + Send {
            std::future::ready(None)
        }
    }

    #[async_trait::async_trait]
    impl cda_interfaces::Shutdown for SlowTeardownGateway {
        async fn shutdown(&self) {}
    }

    impl FunctionalTransport for TestGateway {
        fn send_functional(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            _expected_ecu_logical_addrs: HashMap<u16, String>,
            _timeout: Duration,
            _expect_positive_response: bool,
        ) -> impl Future<
            Output = Result<
                HashMap<String, Result<ServicePayload, DiagServiceError>>,
                DiagServiceError,
            >,
        > + Send {
            std::future::ready(Ok(HashMap::new()))
        }
    }

    impl NetworkTopology for TestGateway {
        fn get_gateway_network_address(
            &self,
            _logical_address: u16,
        ) -> impl Future<Output = Option<String>> + Send {
            std::future::ready(None)
        }
    }

    #[async_trait::async_trait]
    impl cda_interfaces::Shutdown for TestGateway {
        async fn shutdown(&self) {}
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

    fn make_manager_with_timeout_default(
        gateway: TestGateway,
        timeout_default: Duration,
    ) -> UdsManager<TestGateway, TestEcuDb> {
        let ecus = Arc::new(HashMap::from_iter([(
            "TestECU".to_string(),
            RwLock::new(TestEcuDb::with_timeout_default(timeout_default)),
        )]));
        UdsManager::new_for_raw_payload_tests(
            gateway,
            ecus,
            FaultConfig::default(),
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn make_manager_with_timeout_default_and_repeat_req_count_app(
        gateway: TestGateway,
        timeout_default: Duration,
        repeat_req_count_app: u32,
    ) -> UdsManager<TestGateway, TestEcuDb> {
        let ecus = Arc::new(HashMap::from_iter([(
            "TestECU".to_string(),
            RwLock::new(TestEcuDb::with_timeout_default_and_repeat_req_count_app(
                timeout_default,
                repeat_req_count_app,
            )),
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
                    data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01],
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
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

        assert!(result.is_ok());
        let response = result.expect("should be Ok");
        assert!(response.is_some());
        let msg = response.expect("should have message");
        assert_eq!(
            msg.data,
            vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01]
        );
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
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, false)
            .await;

        assert!(result.is_ok());
        assert!(result.expect("should be Ok").is_none());
    }

    /// A request with `suppressPosRspMsgIndicationBit` set (here
    /// `ECUReset 0x81`) drives `expect_response = false`, so
    /// `send_with_raw_payload` completes with `Ok(None)` once the frame is
    /// (n)ack'd - never a `Timeout`/`NoResponse` error - even though the ECU
    /// deliberately sends no response. `send_without_variant_guard` then
    /// converts this `Ok(None)` into a positive, empty decoded response via
    /// `DiagServiceResponse::empty_positive` (unit-tested in cda-core), which
    /// callers render as no-content instead of an error.
    #[tokio::test]
    async fn test_send_with_raw_payload_suppress_positive_response_returns_ok_none() {
        let gateway = TestGateway {
            send_fn: Arc::new(|response_tx, _| {
                // Only an ack (None); the ECU sends no positive response.
                response_tx.try_send(Ok(None)).ok();
                Ok(())
            }),
        };
        let manager = make_manager(gateway);
        // ECUReset (0x11) with SPRMIB bit set on the subfunction byte (0x81).
        let payload = make_test_payload(service_ids::ECU_RESET, &[0x81]);
        assert!(
            payload.is_suppress_positive_response(),
            "test payload must have the suppress-positive-response bit set"
        );
        let expect_response = !payload.is_suppress_positive_response();

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, expect_response)
            .await;

        assert!(result.is_ok(), "expected Ok(None), got {result:?}");
        assert!(
            result.expect("should be Ok").is_none(),
            "suppressed response must yield Ok(None), not a decoded payload"
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_ecu_not_found() {
        let gateway = TestGateway {
            send_fn: Arc::new(|_, _| Ok(())),
        };
        let manager = make_manager_no_ecus(gateway);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

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
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

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
            send_fn: Arc::new(|response_tx, _| {
                // Model a parked gateway task: keep the channel open with no
                // response so the caller's rx_timeout fires (instead of the
                // channel closing early).
                park_sender(response_tx);
                Ok(())
            }),
        };
        let manager = make_manager(gateway);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, Some(Duration::from_millis(50)), true)
            .await;

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
        let gateway = TestGateway {
            send_fn: Arc::new(|response_tx, _| {
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
                Ok(())
            }),
        };
        // No app-layer retries so the first channel-close resolves directly.
        let manager = make_manager_with_timeout_default_and_repeat_req_count_app(
            gateway,
            Duration::from_millis(50),
            0,
        );
        // Request: 22 F1 90 (ReadDataByIdentifier, DID 0xF190).
        let payload = make_test_payload(service_ids::READ_DATA_BY_IDENTIFIER, &[0xF1, 0x90]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

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
        let gateway = TestGateway {
            send_fn: Arc::new(move |response_tx, _| {
                send_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Never send any response - every attempt times out. Park the
                // sender so the channel stays open and the caller's rx_timeout
                // fires for each attempt.
                park_sender(response_tx);
                Ok(())
            }),
        };
        let repeat_req_count_app = 3;
        let manager = make_manager_with_timeout_default_and_repeat_req_count_app(
            gateway,
            Duration::from_millis(20),
            repeat_req_count_app,
        );
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

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
        let gateway = TestGateway {
            send_fn: Arc::new(move |response_tx, _| {
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
                Ok(())
            }),
        };
        let manager = make_manager_with_timeout_default_and_repeat_req_count_app(
            gateway,
            Duration::from_secs(5),
            3,
        );
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

        assert!(result.is_ok(), "Expected eventual success, got {result:?}");
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "Expected 2 failed transmission attempts + 1 successful one"
        );
    }

    /// Regression test for the "immediate retry" bug observed on offline/answer-
    /// suppressing ECUs (positive ACK, then no UDS reply). Previously a single
    /// response channel was shared across all retries, so a stale gateway task
    /// from a prior attempt could push a late response/error into that shared
    /// channel and trip the receive-error branch, firing the next
    /// `CP_RepeatReqCountApp` retry *immediately* instead of only after this
    /// attempt's `rx_timeout` had elapsed (see log.pcapng: retry #1 correctly
    /// waited ~`P6Max`, retry #2 fired ~1ms later).
    ///
    /// With a per-attempt channel, dropping the previous attempt's
    /// `response_rx`/`response_tx` closes the stale task's sender, so a late
    /// error injected into a *prior* attempt's sender cannot reach the current
    /// attempt. Every retry must therefore be gated by the full timeout, so the
    /// total elapsed time is `(1 + repeat_req_count_app) * timeout`.
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
        let gateway = TestGateway {
            send_fn: Arc::new(move |response_tx, _| {
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
                Ok(())
            }),
        };

        let repeat_req_count_app = 2;
        let timeout = Duration::from_millis(50);
        let manager = make_manager_with_timeout_default_and_repeat_req_count_app(
            gateway,
            timeout,
            repeat_req_count_app,
        );
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let start = std::time::Instant::now();
        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;
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
        let gateway = TestGateway {
            send_fn: Arc::new(move |response_tx, _| {
                send_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Always respond with NRC 0x21 (BusyRepeatRequest).
                response_tx
                    .try_send(Ok(Some(TransportResponse::Pending(
                        PendingNrc::BusyRepeatRequest {
                            source_address: 0x0001,
                        },
                    ))))
                    .ok();
                Ok(())
            }),
        };
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
            manager.send_with_raw_payload("TestECU", payload, None, true),
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

    /// Regression test: sends that omit an explicit timeout
    /// must fall back to the ECU's configured `CP_P6Max`-backed
    /// `UdsComParams::timeout_default`, not a hardcoded literal. Previously,
    /// `gather_detection_responses` (in `variant.rs`) hardcoded a 10s timeout
    /// for every `0x22 F100` variant-detection send, ignoring the ECU's
    /// actual configured response timeout entirely. The fix changed that
    /// call site to pass `None` instead, relying on exactly the fallback
    /// (`timeout.unwrap_or(uds_params.timeout_default)`) exercised here.
    ///
    /// This test exercises `send_with_raw_payload` directly rather than
    /// `gather_detection_responses`/`detect_variant` itself, since those
    /// require the full `EcuManager` trait (a much larger surface than the
    /// `UdsEcuDb + VariantDetection` bound used by the existing test double
    /// in this module), which is out of proportion for this scoped fix.
    #[tokio::test]
    async fn test_send_with_raw_payload_uses_configured_timeout_default_when_none() {
        let gateway = TestGateway {
            send_fn: Arc::new(|response_tx, _| {
                // Don't send any response - the call must time out based on
                // the ECU's configured `timeout_default`. Park the sender so
                // the channel stays open until that timeout fires.
                park_sender(response_tx);
                Ok(())
            }),
        };
        let short_timeout = Duration::from_millis(100);
        let manager = make_manager_with_timeout_default(gateway, short_timeout);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let start = std::time::Instant::now();
        // No explicit timeout: must fall back to `uds_params.timeout_default`
        // (this is exactly what `send_without_variant_guard` does when
        // called from `gather_detection_responses` post-fix).
        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;
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
                        data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01],
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
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

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
                            data: vec![
                                service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK,
                                0x01,
                            ],
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
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

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
                        data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01],
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
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

        assert!(result.is_ok());
        let msg = result.expect("should be Ok").expect("should have message");
        assert_eq!(
            msg.data,
            vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01]
        );
    }

    #[tokio::test]
    async fn test_send_with_raw_payload_negative_response() {
        let gateway = TestGateway {
            send_fn: Arc::new(|response_tx, _| {
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
                Ok(())
            }),
        };
        let manager = make_manager(gateway);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

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
                    data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x03],
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
            data: vec![service_ids::SESSION_CONTROL, 0x03],
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
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

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
                Ok(())
            }),
        };
        let manager = make_manager(gateway);
        // ReadDataByIdentifier for DID 0xF190
        let payload = make_test_payload(service_ids::READ_DATA_BY_IDENTIFIER, &[0xF1, 0x90]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

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

    fn make_manager_with_slow_teardown_gateway(
        gateway: SlowTeardownGateway,
        timeout_default: Duration,
        repeat_req_count_app: u32,
    ) -> UdsManager<SlowTeardownGateway, TestEcuDb> {
        let ecus = Arc::new(HashMap::from_iter([(
            "TestECU".to_string(),
            RwLock::new(TestEcuDb::with_timeout_default_and_repeat_req_count_app(
                timeout_default,
                repeat_req_count_app,
            )),
        )]));
        UdsManager::new_for_raw_payload_tests(
            gateway,
            ecus,
            FaultConfig::default(),
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// Regression test for the retry-teardown synchronization fix: the
    /// caller must await a previous attempt's gateway-task handle before
    /// issuing the next attempt, not just drop the response channel and hope
    /// the stale task has already finished.
    ///
    /// `SlowTeardownGateway` closes its response channel immediately (so the
    /// caller's read loop sees a fast "no response" and retries right away),
    /// but its returned task handle only resolves after `task_delay`. If the
    /// caller waited for the handle as designed, the gap between successive
    /// `send()` invocations must be at least `task_delay`; pre-fix, the next
    /// `send()` would fire almost immediately after the channel closed.
    #[tokio::test]
    async fn test_send_with_raw_payload_awaits_previous_task_before_next_retry() {
        let task_delay = Duration::from_millis(100);
        let gateway = SlowTeardownGateway {
            task_delay,
            send_times: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let send_times = Arc::clone(&gateway.send_times);
        // rx_timeout is intentionally larger than task_delay: without the
        // fix, retries fire right after the channel closes (near-instantly),
        // not after task_delay.
        let manager = make_manager_with_slow_teardown_gateway(gateway, Duration::from_secs(5), 2);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);

        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;

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

    /// Regression test for the bounded-wait safety net: if a stale gateway
    /// task never finishes at all, `send_with_raw_payload` must not stall
    /// retries indefinitely - it should proceed once `RETRY_TEARDOWN_GRACE`
    /// elapses.
    #[tokio::test]
    async fn test_send_with_raw_payload_proceeds_after_teardown_grace_when_task_never_finishes() {
        // Far longer than RETRY_TEARDOWN_GRACE (500ms): the task handle will
        // never resolve within the scope of this test.
        // Using 601 seconds, to triggering clippy with the smaller unit lint.
        let task_delay = Duration::from_secs(601);
        let gateway = SlowTeardownGateway {
            task_delay,
            send_times: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let send_times = Arc::clone(&gateway.send_times);
        let manager =
            make_manager_with_slow_teardown_gateway(gateway, Duration::from_millis(50), 1);
        let payload = make_test_payload(service_ids::SESSION_CONTROL, &[0x01]);
        let start = Instant::now();
        let result = manager
            .send_with_raw_payload("TestECU", payload, None, true)
            .await;
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
        // Sanity bound: the whole call must finish quickly, well under
        // task_delay, proving the never-finishing task did not stall it.
        assert!(
            elapsed < Duration::from_secs(5),
            "Expected the call to proceed despite the stale task never finishing, took {elapsed:?}"
        );
    }
}
