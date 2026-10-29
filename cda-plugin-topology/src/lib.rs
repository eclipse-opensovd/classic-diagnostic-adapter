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

//! ECU topology plugin.
//!
//! - [`plugin::TopologyPlugin`]: the contract the application talks to
//! - [`plugin::TopologyPluginBuilder`]: plugin factory contract
//! - [`plugin::default::DefaultTopologyPlugin`]: the default implementation,
//!   which persists the detected ECU list in the storage and reuses it on the
//!   next start. Other implementations can be substituted via
//!   `Setup::with_topology_plugin`.
//! - [`plugin::TopologyDatabases`] and [`plugin::TopologySource`]: what the
//!   plugin needs from the loaded databases and the live ECUs
//! - [`persist::TopologyPersistence`]: the communication hook writing the
//!   detected topology
//! - [`reset`]: the topology operations of a `networkreset`
//! - [`restore`]: restoring ECU states at startup
//! - [`store::PersistentEcuTopologyStore`]: the storage-backed store

pub mod persist;
pub mod plugin;
pub mod reset;
pub mod restore;
pub mod store;

use std::time::Duration;

pub use persist::TopologyPersistence;
pub use plugin::{
    DatabaseEcu, TopologyDatabases, TopologyPlugin, TopologyPluginBuilder, TopologyPluginFn,
    TopologyPolicy, TopologySource,
    default::{DefaultTopologyPlugin, DefaultTopologyPluginBuilder},
    topology_plugin_fn,
};
pub use store::PersistentEcuTopologyStore;

/// Upper bound of a `networkreset` waiting for communication to come up, and
/// then again for its rediscovery to settle. Nothing else bounds these waits.
pub const REDISCOVERY_TIMEOUT: Duration = Duration::from_secs(60);
