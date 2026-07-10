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
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigSanityError {
    #[error("Failed to parse value: {0}")]
    ParsingError(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid value for '{field}': {reason}")]
    InvalidValue { field: String, reason: String },
}

pub trait ConfigSanity {
    /// Checks the configuration for common mistakes and returns an error message if found.
    /// # Errors
    /// Returns `Err(String)` if a sanity check fails, with a descriptive error message.
    fn validate_sanity(&self) -> Result<(), ConfigSanityError>;
}
