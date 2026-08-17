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

//! Communication management plugin.
//!
//! Public API is available from the explicit modules that define each type.
//!
//! - [`plugin::CommunicationPlugin`]: authoritative lifecycle facade
//! - [`plugin::CommunicationPluginBuilder`]: plugin factory contract
//! - [`cda_interfaces::communication_control::CommunicationAccess`]: diagnostic-use capability
//! - [`lifecycle::disable::DisableCommunication`]: disable capability
//! - [`cda_interfaces::communication_control::operation`]: lifecycle operation types and outcomes
//! - [`lifecycle::controller::build_communication_runtime`]: startup wiring
//!
//! HTTP-layer protection records live in `cda_interfaces::http_protection`, so
//! owners such as the runtime-update plugin need not depend on this crate.
//!
//! [`plugin::default`] provides [`plugin::default::DefaultCommunicationPlugin`]:
//! the default implementation that applies `[communication] init_mode` policy
//! (`Always`/`OnDemand`/`Disabled`). Other implementations can be
//! substituted via `Setup::with_communication_plugin`.

pub mod lifecycle;
pub mod plugin;
