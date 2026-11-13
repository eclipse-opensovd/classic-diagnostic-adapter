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

//! Gate that keeps new vehicle traffic from starting while communication is paused.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use super::access::QUIESCED_MESSAGE;
use crate::DiagServiceError;

/// Closed while a quiesce lease is held; transports refuse new connects and sends.
///
/// Clones share one state, including the retry hint of a refusal. A new gate is
/// open.
#[derive(Clone, Debug, Default)]
pub struct TransportGate(Arc<GateState>);

#[derive(Debug, Default)]
struct GateState {
    closed: AtomicBool,
    retry_after: Duration,
}

impl TransportGate {
    /// Creates an open gate whose refusal carries no retry hint.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an open gate whose refusal carries `retry_after` as its retry
    /// hint.
    #[must_use]
    pub fn with_retry_after(retry_after: Duration) -> Self {
        Self(Arc::new(GateState {
            closed: AtomicBool::new(false),
            retry_after,
        }))
    }

    /// Closes the gate: no new traffic may start.
    pub fn close(&self) {
        self.0.closed.store(true, Ordering::Release);
    }

    /// Opens the gate again.
    pub fn open(&self) {
        self.0.closed.store(false, Ordering::Release);
    }

    /// `true` if traffic may start.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.0.closed.load(Ordering::Acquire)
    }

    /// The error of work refused by the closed gate: communication is paused,
    /// with the gate's retry hint. The one place that builds it, for every
    /// transport.
    #[must_use]
    pub fn quiesced_error(&self) -> DiagServiceError {
        DiagServiceError::CommunicationNotReady {
            message: QUIESCED_MESSAGE.to_owned(),
            retry_after: self.0.retry_after,
        }
    }
}
