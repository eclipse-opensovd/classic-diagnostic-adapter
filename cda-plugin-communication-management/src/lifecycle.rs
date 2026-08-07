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
//! - HTTP protection lifecycle integration

pub mod access;
pub mod disable;
pub mod error;
pub mod guard;
pub mod operation;
pub mod state;

pub mod controller;
mod worker;

// Re-export public items from controller for downstream use
// Re-export test utilities with test-utils feature (not available in lib tests)
// This is re-exported because the fact that this is part of the controller module is an
// implementation detail
#[cfg(feature = "test-utils")]
pub use controller::test_utils::{
    communication_disable_for_test, enabled_communication_access_for_test,
};
pub use controller::{
    BuildCommunicationRuntimeError, CommunicationHandle, CommunicationRuntime,
    build_communication_runtime,
};
