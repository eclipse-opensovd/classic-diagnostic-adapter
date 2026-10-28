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

//! `functions/functionalgroups/{fg}/operations`: the result types of the
//! operations of a functional group, see
//! [`Operation`](crate::client::components::operations::Operation).

use cda_sovd::VendorErrorCode;
use sovd_interfaces::functions::functional_groups::operations::{FgAsyncGetByIdResponse, service};

/// The result of a synchronous execution of an operation of a functional
/// group.
pub(crate) type FunctionalGroupSyncExecution = service::Response<VendorErrorCode>;

/// An execution of an operation of a functional group.
pub(crate) type FunctionalGroupExecution = FgAsyncGetByIdResponse<VendorErrorCode>;
