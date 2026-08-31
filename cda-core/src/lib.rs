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

mod diag_kernel;

pub use diag_kernel::{
    diagservices::*,
    ecumanager::{EcuManager, EcuManagerConfig},
    security::{LOOKUP_REQUEST_SEED_SERVICE_HOOK, lookup_request_seed_service},
};

// Declares the vendor-override registry and `validate_vendor_overrides()` for
// this crate. Required once at the crate root because this crate defines
// vendor-overridable functions.
override_macros::declare_vendor_override_registry!();
