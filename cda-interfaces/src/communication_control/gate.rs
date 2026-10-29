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

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Closed while a quiesce lease is held; transports refuse new connects and sends.
///
/// Clones share one state. A new gate is open.
#[derive(Clone, Debug, Default)]
pub struct TransportGate(Arc<AtomicBool>);

impl TransportGate {
    /// Creates an open gate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Closes the gate: no new traffic may start.
    pub fn close(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Opens the gate again.
    pub fn open(&self) {
        self.0.store(false, Ordering::Release);
    }

    /// `true` if traffic may start.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.0.load(Ordering::Acquire)
    }
}
