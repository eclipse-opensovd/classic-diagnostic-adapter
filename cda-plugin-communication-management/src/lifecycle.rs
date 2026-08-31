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

//! Unified communication lifecycle management.
//!
//! This module provides a single authoritative mechanism for:
//! - Synchronous guard-based admission control (fast-path `acquire()`)
//! - Explicit async enable lifecycle operations
//! - Post-enable initializer execution in registration order

pub mod access;
pub mod disable;
pub mod guard;
pub mod state;

pub mod controller;
pub(crate) mod transition;
mod worker;

#[cfg(feature = "test-utils")]
pub use controller::test_utils::{
    communication_disable_for_test, enabled_communication_access_for_test,
};
pub use controller::{
    BuildCommunicationRuntimeError, CommunicationHandle, CommunicationRuntime,
    build_communication_runtime,
};
