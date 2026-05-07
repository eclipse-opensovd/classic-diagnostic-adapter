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

//! SSL/TLS module - safe wrappers around `mbedtls_ssl_config` and `mbedtls_ssl_context`.

mod config;
mod context;

pub use config::{MaxFragLen, SslConfig, SslConfigBuilder, SslVerifyMode, TlsVersion};
pub use context::{HandshakeError, MidHandshakeSslStream, SslStream};
