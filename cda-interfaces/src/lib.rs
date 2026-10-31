/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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
    fmt::{Display, Formatter},
    time::Duration,
};

use async_trait::async_trait;
use futures::{FutureExt, future::BoxFuture};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod authentication;
mod can_id;
pub use can_id::*;
mod com_param_handling;
pub use com_param_handling::*;
pub mod datatypes;
pub mod diagservices;
mod ecugateway;
pub use ecugateway::{
    EcuGateway, FunctionalTransport, NetworkTopology, PhysicalTransport, RouteStatus,
    TransmissionParameters, TransportProbe,
};
mod ecumanager;
pub use ecumanager::*;
mod ecuuds;
pub use ecuuds::*;
pub mod file_manager;
pub mod health;
pub mod http_protection;
pub mod lock_config;
pub mod lock_priority_api;
mod schema;
pub use schema::*;
pub mod communication_control;
pub mod component_slot;
pub mod config;
pub mod request_authorization;
pub mod runtime_update_api;
pub mod storage_api;
pub mod topology;
mod transport;
pub use transport::TransportType;
pub mod uds;
pub use uds::{
    DEFAULT_SUBFUNCTION_MASK, PendingNrc, SERVICE_IDS_PARAMETER_META_DATA,
    SUPPRESS_POSITIVE_RESPONSE_BIT, TransportResponse, UDS_ID_RESPONSE_BITMASK,
    is_negative_response, is_pending_nrc, is_tester_present_nrc, nrc, pending_nrc_from_raw,
    service_ids, subfunction_ids, uds_response_from_raw,
};

// Deliberately not using new type pattern here, to make sure all crates that take
// std::collection::Hash* still work.
// Together with the foldhash hasher, this is virtually the same as using hashbrown.
pub type Hasher = foldhash::fast::RandomState;
pub type HashMap<K, V> = std::collections::HashMap<K, V, Hasher>;
pub type HashMapEntry<'a, K, V> = std::collections::hash_map::Entry<'a, K, V>;

pub type HashSet<V> = std::collections::HashSet<V, Hasher>;
// Note: hash_set_entry is unstable, hence not defining it.

pub use foldhash::{HashMapExt as HashMapExtensions, HashSetExt as HashSetExtensions};

/// # strings module
/// This module contains a type that allows to store unique strings and use references to them
/// instead of cloning the strings themselves in all places.<br>
/// This is to optimize the memory usage of the diagnostic databases, as they contain a lot of
/// strings which are often not unique.<br>
/// The module additionally contains macros to handle string IDs and references in the diagnostic
/// database.
pub(crate) mod strings;
/// Re-export the STRINGS macros to make it available in the crate scope.
pub use strings::*;
pub mod util;

pub type DynamicPlugin = Box<dyn std::any::Any + Send + Sync>;

/// ECU names for which variant detection should be triggered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantDetectionRequest(Vec<String>);

impl VariantDetectionRequest {
    #[must_use]
    pub fn new(ecus: Vec<String>) -> Self {
        Self(ecus)
    }

    #[must_use]
    pub fn into_ecus(self) -> Vec<String> {
        self.0
    }
}

/// Current detection activity, including work completed between observer polls.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DetectionProgress {
    /// Number of queued or running detections.
    pub pending: usize,
    /// Monotonic activity generation, retained even after detection becomes idle.
    pub generation: u64,
}

/// Tracks queued and running variant detections through owned [`DetectionTicket`]s.
/// The retained generation lets consumers observe even a complete run between polls.
#[derive(Debug, Clone, Default)]
pub struct DetectionTracker {
    progress: std::sync::Arc<tokio::sync::watch::Sender<DetectionProgress>>,
}

impl DetectionTracker {
    /// Creates an idle tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers pending detection work until the returned ticket is dropped.
    #[must_use]
    pub fn begin(&self) -> DetectionTicket {
        self.progress.send_modify(|progress| {
            progress.pending = progress.pending.saturating_add(1);
            progress.generation = progress.generation.saturating_add(1);
        });
        DetectionTicket(self.clone())
    }

    /// Subscribes to pending detections and their retained activity generation.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<DetectionProgress> {
        self.progress.subscribe()
    }

    /// Waits until no detection work is pending or running. Returns `false` if
    /// `timeout` elapsed first.
    pub async fn wait_idle(&self, timeout: Duration) -> bool {
        let mut rx = self.progress.subscribe();
        tokio::time::timeout(timeout, rx.wait_for(|progress| progress.pending == 0))
            .await
            .is_ok_and(|result| result.is_ok())
    }

    fn end(&self) {
        self.progress.send_modify(|progress| {
            progress.pending = progress.pending.saturating_sub(1);
            progress.generation = progress.generation.saturating_add(1);
        });
    }
}

/// Pending detection work registered with a [`DetectionTracker`]; releases its
/// count on drop. Owns exactly one count, so wherever it ends up (received,
/// dropped with an undelivered request, dropped with the channel) the count goes
/// with it.
#[derive(Debug)]
pub struct DetectionTicket(DetectionTracker);

impl Drop for DetectionTicket {
    fn drop(&mut self) {
        self.0.end();
    }
}

/// What travels through the variant-detection channel: the request and the
/// ticket counting it.
pub type QueuedRequest = (VariantDetectionRequest, DetectionTicket);

/// Sends requests to the variant-detection listener.
#[derive(Debug, Clone)]
pub struct VariantDetectionSender {
    sender: tokio::sync::mpsc::Sender<QueuedRequest>,
    tracker: DetectionTracker,
}

impl VariantDetectionSender {
    /// Creates a sender with its own tracker.
    #[must_use]
    pub fn new(sender: tokio::sync::mpsc::Sender<QueuedRequest>) -> Self {
        Self::with_tracker(sender, DetectionTracker::new())
    }

    /// Creates a sender that counts queued requests on `tracker`. Use the same
    /// tracker for the matching [`VariantDetectionReceiver`].
    #[must_use]
    pub fn with_tracker(
        sender: tokio::sync::mpsc::Sender<QueuedRequest>,
        tracker: DetectionTracker,
    ) -> Self {
        Self { sender, tracker }
    }

    /// # Errors
    ///
    /// Returns an error if the variant-detection receiver has been closed.
    pub async fn send(
        &self,
        request: VariantDetectionRequest,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<VariantDetectionRequest>> {
        // Counted only once the slot is reserved: a send cancelled while waiting
        // for capacity must not leave a count behind.
        let Ok(permit) = self.sender.reserve().await else {
            return Err(tokio::sync::mpsc::error::SendError(request));
        };
        self.commit(permit, request);
        Ok(())
    }

    /// The ticket travels with the request, so the count is released wherever the
    /// request ends: received, or dropped with the channel (also if the receiver
    /// went away while this sender waited for capacity).
    fn commit(
        &self,
        permit: tokio::sync::mpsc::Permit<'_, QueuedRequest>,
        request: VariantDetectionRequest,
    ) {
        permit.send((request, self.tracker.begin()));
    }
}

/// Receives requests for the variant-detection listener.
#[derive(Debug)]
pub struct VariantDetectionReceiver {
    receiver: tokio::sync::mpsc::Receiver<QueuedRequest>,
    tracker: DetectionTracker,
}

impl VariantDetectionReceiver {
    /// Creates a receiver for requests counted on `tracker`.
    #[must_use]
    pub fn with_tracker(
        receiver: tokio::sync::mpsc::Receiver<QueuedRequest>,
        tracker: DetectionTracker,
    ) -> Self {
        Self { receiver, tracker }
    }

    /// The tracker counting queued requests and running detections.
    #[must_use]
    pub fn tracker(&self) -> &DetectionTracker {
        &self.tracker
    }

    /// Receives a request together with the ticket counting it. Hold the ticket
    /// until the requested detections are running (and hold tickets of their own).
    pub async fn recv_tracked(&mut self) -> Option<(VariantDetectionRequest, DetectionTicket)> {
        self.receiver.recv().await
    }

    /// # Errors
    ///
    /// Returns an error if no request is currently available or all senders have been dropped.
    pub fn try_recv(
        &mut self,
    ) -> Result<VariantDetectionRequest, tokio::sync::mpsc::error::TryRecvError> {
        self.receiver.try_recv().map(|(request, _ticket)| request)
    }
}

#[derive(Debug, Clone)]
pub enum DiagCommAction {
    Read,
    Write,
    Start,
    RequestResults,
    Stop,
}

#[derive(Debug, Clone)]
pub struct DiagComm {
    pub name: String,
    pub type_: DiagCommType,
    pub lookup_name: Option<String>,
    pub subfunction_id: Option<u8>,
}

impl DiagComm {
    #[must_use]
    pub fn new(name: impl Into<String>, type_: DiagCommType) -> Self {
        let name = name.into();
        Self {
            lookup_name: Some(name.clone()),
            name,
            type_,
            subfunction_id: None,
        }
    }

    #[must_use]
    pub fn action(&self) -> DiagCommAction {
        self.type_.clone().into()
    }
}

impl From<DiagCommType> for DiagCommAction {
    fn from(value: DiagCommType) -> Self {
        match value {
            DiagCommType::Configurations => DiagCommAction::Write,
            DiagCommType::Data => DiagCommAction::Read,
            // Faults is actually Clear or Read, but doesn't matter here
            DiagCommType::Faults | DiagCommType::Modes | DiagCommType::Operations => {
                DiagCommAction::Start
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
/// Enum representing diagnostic communication types according to ASAM SOVD.
///
/// Can be mapped to UDS service prefixes with [`DiagCommType::service_prefixes`]
pub enum DiagCommType {
    /// Service Prefix `0x2E`
    Configurations,
    /// Service Prefixes `0x21` (KWP2000), `0x22` (UDS)
    Data,
    /// Service Prefixes `0x14`, `0x19`
    Faults,
    /// Service Prefixes `0x10`, `0x11`, `0x28`, `0x85`, `0x27`, `0x29`
    Modes,
    /// Service Prefixes `0x2F`, `0x31`, `0x34`, `0x36`, `0x37`
    Operations,
}

impl TryFrom<u8> for DiagCommType {
    type Error = DiagServiceError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            service_ids::WRITE_DATA_BY_IDENTIFIER => Ok(DiagCommType::Configurations),
            service_ids::READ_DATA_BY_LOCAL_IDENTIFIER | service_ids::READ_DATA_BY_IDENTIFIER => {
                Ok(DiagCommType::Data)
            }
            service_ids::CLEAR_DIAGNOSTIC_INFORMATION | service_ids::READ_DTC_INFORMATION => {
                Ok(DiagCommType::Faults)
            }
            service_ids::SESSION_CONTROL
            | service_ids::ECU_RESET
            | service_ids::SECURITY_ACCESS
            | service_ids::COMMUNICATION_CONTROL
            | service_ids::AUTHENTICATION
            | service_ids::CONTROL_DTC_SETTING => Ok(DiagCommType::Modes),
            service_ids::INPUT_OUTPUT_CONTROL_BY_IDENTIFIER
            | service_ids::ROUTINE_CONTROL
            | service_ids::REQUEST_DOWNLOAD
            | service_ids::TRANSFER_DATA
            | service_ids::REQUEST_TRANSFER_EXIT => Ok(DiagCommType::Operations),
            _ => Err(DiagServiceError::InvalidRequest(format!(
                "Invalid DiagCommType value: {value}"
            ))),
        }
    }
}

#[derive(Clone)]
pub enum SecurityAccess {
    RequestSeed(DiagComm),
    SendKey(DiagComm),
}

#[derive(Clone, Debug)]
pub enum TesterPresentMode {
    Start,
    Stop,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum TesterPresentType {
    Functional(String),
    Ecu(String),
}

#[derive(Clone, Debug)]
pub struct TesterPresentControlMessage {
    pub mode: TesterPresentMode,
    pub type_: TesterPresentType,
    pub ecu: String,
    /// If set to `None`, the ECU specific interval will be used.
    pub interval: Option<Duration>,
}

impl TesterPresentType {
    #[must_use]
    pub fn is_functional(&self) -> bool {
        matches!(self, TesterPresentType::Functional(_))
    }
}

impl DiagCommType {
    #[must_use]
    /// This function returns the service prefix for the given `DiagCommType`
    /// according to ASAM_SOVD_BS_V1-0-0
    /// # Service Prefixes Mapping
    ///  - `0x2E` -> `<entity>/configurations`
    ///  - `0x22` -> `<entity>/data`
    ///  - `0x10` -> `<entity>/modes/session`
    ///  - `0x11` -> `<entity>/modes/ecureset`
    ///  - `0x28` -> `<entity>/modes/commctrl`
    ///  - `0x85` -> `<entity>/modes/dtcsetting`
    ///  - `0x27` -> `<entity>/modes/security`
    ///  - `0x29` -> `<entity>/modes/authentication` (deviates from ISO 17978, see ADR-007)
    ///  - `0x14 | 0x19` -> `<entity>/faults`
    ///  - `0x2F | 0x31` -> `<entity>/operations`
    pub fn service_prefixes(&self) -> &'static [u8] {
        use crate::uds::{
            CONFIGURATIONS_PREFIXES, DATA_PREFIXES, FAULTS_PREFIXES, MODES_PREFIXES,
            OPERATIONS_PREFIXES,
        };
        match self {
            DiagCommType::Configurations => &CONFIGURATIONS_PREFIXES,
            DiagCommType::Data => &DATA_PREFIXES,
            DiagCommType::Faults => &FAULTS_PREFIXES,
            DiagCommType::Modes => &MODES_PREFIXES,
            DiagCommType::Operations => &OPERATIONS_PREFIXES,
        }
    }
}

/// Functional group description and lookup configuration.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct FunctionalDescriptionConfig {
    /// Name of the database containing functional group definitions.
    pub description_database: String,
    /// Optional set of functional group names to enable.
    /// When absent, all functional groups are enabled.
    pub enabled_functional_groups: Option<HashSet<String>>,
    /// Position of the protocol identifier in service names.
    pub protocol_position: datatypes::DiagnosticServiceAffixPosition,
}
impl Default for FunctionalDescriptionConfig {
    fn default() -> Self {
        Self {
            description_database: "functional_groups".to_owned(),
            enabled_functional_groups: None,
            protocol_position: datatypes::DiagnosticServiceAffixPosition::Suffix,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DiagServiceError {
    /// Returned in case a resource can not be found
    #[error("Not found: {0:?}")]
    NotFound(String),
    #[error("Request not supported: {0}")]
    RequestNotSupported(String),
    #[error("Communication disabled: {0}")]
    CommunicationDisabled(String),
    /// Communication was not enabled and either activation is not authorized
    /// under the current `init_mode` or activation itself failed. Carries a
    /// configured retry hint, unlike the coarser [`CommunicationDisabled`](Self::CommunicationDisabled).
    #[error("Communication not ready: {message}")]
    CommunicationNotReady {
        message: String,
        retry_after: Duration,
    },
    #[error("Invalid database: {0}")]
    InvalidDatabase(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Parameter conversion error: {0}")]
    ParameterConversionError(String),
    #[error("Unknown operation")]
    UnknownOperation,
    #[error("UDS lookup error: {0}")]
    UdsLookupError(String),
    #[error("Bad payload: {0}")]
    BadPayload(String),
    /// Similar to `BadPayload` but indicates that the data received is insufficient to
    /// process the request.
    /// Used to abort reading data gracefully when the data is incomplete or end of pdu is reached.
    #[error("Payload too short, expected at least {expected} bytes, got {actual} bytes")]
    NotEnoughData { expected: usize, actual: usize },
    #[error("Variant detection error: {0}")]
    VariantDetectionError(String),
    #[error("{0}")]
    InvalidState(String),
    #[error("{0}")]
    InvalidAddress(String),
    #[error("Sending message failed {0}")]
    SendFailed(String),
    #[error("Received Nack, code={0:?}")]
    Nack(u8),
    #[error("Unexpected response. {0:?}")]
    UnexpectedResponse(Option<String>),
    #[error("No response {0}")]
    NoResponse(String),
    #[error("Connection closed {0}")]
    ConnectionClosed(String),
    #[error("Ecu {0} offline")]
    EcuOffline(String),
    #[error("Timeout")]
    Timeout,
    #[error("Access denied: {0}")]
    AccessDenied(String),
    #[error("Request not allowed: {0}")]
    RequestNotAllowed(String),
    /// The request conflicts with the current state, e.g. an ECU is already connected.
    #[error("Conflict: {0}")]
    Conflict(String),
    /// Returned in case a resource can be found but returns an error
    #[error("Resource error: {0}")]
    ResourceError(String),
    #[error("Data parse error: value='{}', details='{}'", .0.value, .0.details)]
    DataError(DataParseError),
    /// Returned in case the provided value for security plugin cannot be used as `SecurityApi`
    #[error("Invalid security plugin provided")]
    InvalidSecurityPlugin,
    #[error(
        "Unable to find a unique value with the given parameters: name='{name}', \
         candidates='{candidates:?}'"
    )]
    AmbiguousParameters {
        name: String,
        candidates: Vec<String>,
    },
    #[error("No value found with the given parameters. Possible values are: {possible_values:?}")]
    InvalidParameter { possible_values: HashSet<String> },
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
}

impl DiagServiceError {
    /// Whether a failed request shows the ECU is unreachable, so its connectivity is demoted.
    ///
    /// `EcuOffline` is excluded: it means the gateway has no connection (yet), which must
    /// keep the state of an `AssumedOnline` ECU while the gateway is still reconnecting.
    #[must_use]
    pub fn demotes_connectivity(&self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::ConnectionClosed(_) | Self::SendFailed(_)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataParseError {
    pub value: String,
    pub details: String,
}

impl std::fmt::Display for DiagComm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DiagService ( name: {}, operation: {:?} )",
            self.name,
            self.action()
        )
    }
}

impl Display for DiagCommAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DiagCommAction::Read => write!(f, "Read"),
            DiagCommAction::Write => write!(f, "Write"),
            DiagCommAction::Start => write!(f, "Start"),
            DiagCommAction::RequestResults => write!(f, "RequestResults"),
            DiagCommAction::Stop => write!(f, "Stop"),
        }
    }
}

/// Type alias for the boxed shared shutdown signal.
/// This provides a concrete named type for use in generic bounds.
pub type ShutdownSignal = futures::future::Shared<BoxFuture<'static, ()>>;

pub fn shutdown_signal<F>(future: F) -> ShutdownSignal
where
    F: Future<Output = ()> + Send + 'static,
{
    future.boxed().shared()
}

/// Capability for gracefully shutting down background tasks/connections, e.g. before a
/// hot-reload replaces the underlying component with a freshly constructed one.
#[async_trait]
pub trait Shutdown: Send + Sync + 'static {
    /// Aborts background tasks and releases connections/resources owned by this instance.
    /// Implementations should be idempotent where practical.
    async fn shutdown(&self);
}

#[cfg(test)]
mod detection_tracker_tests {
    use std::time::Duration;

    use super::{
        DetectionTracker, VariantDetectionReceiver, VariantDetectionRequest, VariantDetectionSender,
    };

    /// A tracker with a sender and a receiver counting on it.
    fn tracked_channel(
        capacity: usize,
    ) -> (
        DetectionTracker,
        VariantDetectionSender,
        VariantDetectionReceiver,
    ) {
        let tracker = DetectionTracker::new();
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        let sender = VariantDetectionSender::with_tracker(tx, tracker.clone());
        let receiver = VariantDetectionReceiver::with_tracker(rx, tracker.clone());
        (tracker, sender, receiver)
    }

    fn pending(tracker: &DetectionTracker) -> usize {
        tracker.subscribe().borrow().pending
    }

    /// [[ test~detection-tracker-queued-requests-and-tickets-keep-tracker-busy, Queued and running detections keep the tracker busy, test ]]
    #[tokio::test]
    async fn queued_requests_and_tickets_keep_tracker_busy() {
        let (tracker, sender, mut receiver) = tracked_channel(4);
        assert_eq!(pending(&tracker), 0);

        sender
            .send(VariantDetectionRequest::new(vec!["ecu".to_owned()]))
            .await
            .unwrap();
        assert_eq!(pending(&tracker), 1, "a queued request counts as pending");

        let (_request, ticket) = receiver.recv_tracked().await.unwrap();
        assert_eq!(pending(&tracker), 1, "the received ticket keeps it pending");
        let running = tracker.begin();
        drop(ticket);
        assert_eq!(pending(&tracker), 1);
        drop(running);
        assert!(tracker.wait_idle(Duration::from_millis(10)).await);
    }

    #[tokio::test]
    async fn cancelled_send_is_not_counted() {
        let (tracker, sender, _receiver) = tracked_channel(1);
        sender
            .send(VariantDetectionRequest::new(Vec::new()))
            .await
            .unwrap();
        // The channel is full: this send waits and is cancelled by the timeout.
        let blocked = tokio::time::timeout(
            Duration::from_millis(20),
            sender.send(VariantDetectionRequest::new(Vec::new())),
        )
        .await;
        assert!(blocked.is_err());
        assert_eq!(pending(&tracker), 1, "only the queued request counts");
    }

    /// [[ test~detection-tracker-idle-after-receiver-drop, Dropping the receiver releases the counts of its queued requests, test ]]
    #[tokio::test]
    async fn dropping_the_receiver_releases_queued_requests() {
        let (tracker, sender, receiver) = tracked_channel(4);
        for _ in 0..2 {
            sender
                .send(VariantDetectionRequest::new(Vec::new()))
                .await
                .unwrap();
        }
        drop(receiver);
        assert_eq!(pending(&tracker), 0);
        assert!(
            sender
                .send(VariantDetectionRequest::new(Vec::new()))
                .await
                .is_err()
        );
        assert_eq!(pending(&tracker), 0, "a failed send is not counted");
    }

    /// [[ test~detection-tracker-undelivered-request-released, A request sent after the receiver went away releases its count with the channel, test ]]
    #[tokio::test]
    async fn send_racing_with_dropping_the_receiver_does_not_leave_a_count() {
        let (tracker, sender, receiver) = tracked_channel(4);

        // A sender that already holds its slot while the receiver goes away.
        let permit = sender.sender.reserve().await.unwrap();
        drop(receiver);
        sender.commit(permit, VariantDetectionRequest::new(Vec::new()));
        assert_eq!(
            pending(&tracker),
            1,
            "the undelivered request is counted until the channel is dropped"
        );

        drop(sender);
        assert!(
            tracker.wait_idle(Duration::from_millis(200)).await,
            "a request that can no longer be received must not keep the tracker busy"
        );
    }
}
