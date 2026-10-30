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

//! ECU topology persistence: the storage-backed store and the lifecycle hook
//! that writes the detected topology.

pub mod persist;
pub mod store;

pub use persist::{EcuTopologySource, TopologyPersistence};
pub use store::StorageEcuTopologyStore;
