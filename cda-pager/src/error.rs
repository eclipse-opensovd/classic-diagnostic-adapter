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

/// Errors raised while setting up or using the pager.
#[derive(Debug, thiserror::Error)]
pub enum PagerError {
    #[error("Invalid pager configuration: {0}")]
    InvalidConfig(String),
    #[error("Pager I/O error: {0}")]
    Io(String),
    #[error("Pager system call failed: {0}")]
    Syscall(String),
    #[error("The userfaultfd pager is only supported on Linux")]
    Unsupported,
    #[error("The pager was already initialized")]
    AlreadyInitialized,
}
