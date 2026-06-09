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

//! Shared test utilities for `diag_kernel` tests.
//!
//! Submodules:
//! - [`ecu_manager_builder`] - constants and factory helpers for [`EcuManager`]
//! - [`db_builder`] - macros for assembling a complete [`DiagnosticDatabase`]
//! - [`mdd_type_builder`] - macros for building individual MDD flatbuffer types

pub(crate) mod db_builder;
pub(crate) mod ecu_manager_builder;
pub(crate) mod mdd_type_builder;
