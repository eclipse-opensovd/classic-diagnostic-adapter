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

//! Constants for SOVD online/offline capability description extensions
//! (ISO 17978-3 Table 169).

/// Extension on the [`Operation`](https://spec.openapis.org/oas/v3.1.0#operation-object)
/// object indicating that the operation executes asynchronously.
pub const X_SOVD_ASYNCHRONOUS_EXECUTION: &str = "x-sovd-asynchronous-execution";

/// Extension on the [`PathItem`](https://spec.openapis.org/oas/v3.1.0#path-item-object)
/// object indicating that execution of the operation requires proof of
/// co-location.
pub const X_SOVD_PROXIMITY_PROOF_REQUIRED: &str = "x-sovd-proximity-proof-required";
