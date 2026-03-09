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

//! Error types for mbedtls operations.
//!
//! Wraps mbedtls integer error codes into a proper Rust `Error` type.

use std::fmt;

/// An error returned by an mbedtls function.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MbedtlsError {
    code: i32,
}

impl MbedtlsError {
    /// Create from a raw mbedtls error code (always negative).
    ///
    /// For non release builds this includes a check if the code is negative
    /// as expected. This is just a helper for noticing if something changes
    /// within mbedtls unexpectedly. As the code internally is also an i32
    /// a positive error code will just cause irregularities when displaying
    /// the error but not break anything.
    #[must_use]
    pub fn from_raw(code: i32) -> Self {
        debug_assert!(code < 0, "mbedtls errors are negative");
        Self { code }
    }

    /// The raw mbedtls error code.
    #[must_use]
    pub fn code(&self) -> i32 {
        self.code
    }

    /// Returns `true` if the error indicates the operation would block
    /// and the caller should retry after the underlying I/O is ready for reading.
    #[must_use]
    pub fn is_want_read(&self) -> bool {
        self.code == mbedtls_sys::MBEDTLS_ERR_SSL_WANT_READ
    }

    /// Returns `true` if the error indicates the operation would block
    /// and the caller should retry after the underlying I/O is ready for writing.
    #[must_use]
    pub fn is_want_write(&self) -> bool {
        self.code == mbedtls_sys::MBEDTLS_ERR_SSL_WANT_WRITE
    }

    /// Returns `true` if the peer sent a close-notify alert.
    #[must_use]
    pub fn is_peer_close_notify(&self) -> bool {
        self.code == mbedtls_sys::MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
    }

    /// Descriptive name for well-known error codes.
    fn name(self) -> Option<&'static str> {
        // Cast the constants (u32 in bindgen, but represent negative i32 via wrapping)
        let c = self.code;
        Some(match c {
            c if c == mbedtls_sys::MBEDTLS_ERR_SSL_WANT_READ => "SSL_WANT_READ",
            c if c == mbedtls_sys::MBEDTLS_ERR_SSL_WANT_WRITE => "SSL_WANT_WRITE",
            c if c == mbedtls_sys::MBEDTLS_ERR_SSL_TIMEOUT => "SSL_TIMEOUT",
            c if c == mbedtls_sys::MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => "SSL_PEER_CLOSE_NOTIFY",
            c if c == mbedtls_sys::MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE => "SSL_FATAL_ALERT_MESSAGE",
            c if c == mbedtls_sys::MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE => "SSL_HANDSHAKE_FAILURE",
            c if c == mbedtls_sys::MBEDTLS_ERR_SSL_BAD_CERTIFICATE => "SSL_BAD_CERTIFICATE",
            c if c == mbedtls_sys::MBEDTLS_ERR_SSL_INTERNAL_ERROR => "SSL_INTERNAL_ERROR",
            c if c == mbedtls_sys::MBEDTLS_ERR_SSL_BAD_CONFIG => "SSL_BAD_CONFIG",
            c if c == mbedtls_sys::MBEDTLS_ERR_SSL_CONN_EOF => "SSL_CONN_EOF",
            c if c == mbedtls_sys::MBEDTLS_ERR_X509_CERT_VERIFY_FAILED => "X509_CERT_VERIFY_FAILED",
            c if c == mbedtls_sys::MBEDTLS_ERR_X509_INVALID_FORMAT => "X509_INVALID_FORMAT",
            c if c == mbedtls_sys::MBEDTLS_ERR_PK_KEY_INVALID_FORMAT => "PK_KEY_INVALID_FORMAT",
            c if c == mbedtls_sys::MBEDTLS_ERR_PK_PASSWORD_REQUIRED => "PK_PASSWORD_REQUIRED",
            _ => return None,
        })
    }
}

impl fmt::Debug for MbedtlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for MbedtlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // mbedtls uses negative integers for errors,
        // to display them as positive hexadecimal values, we negate the code and
        // add the '-' sign into the string
        #[allow(clippy::arithmetic_side_effects)]
        #[allow(clippy::cast_sign_loss)]
        match self.name() {
            Some(name) => write!(f, "mbedtls error: {name} (-0x{:04X})", (-self.code) as u32),
            None => write!(f, "mbedtls error: -0x{:04X}", (-self.code) as u32),
        }
    }
}

impl std::error::Error for MbedtlsError {}

impl From<MbedtlsError> for std::io::Error {
    fn from(e: MbedtlsError) -> Self {
        let kind = if e.is_want_read() || e.is_want_write() {
            std::io::ErrorKind::WouldBlock
        } else if e.is_peer_close_notify() {
            std::io::ErrorKind::ConnectionAborted
        } else {
            std::io::ErrorKind::Other
        };
        std::io::Error::new(kind, e)
    }
}

/// Convert a raw mbedtls return code into a `Result`.
/// Zero or positive values are success; negative values are errors.
pub(crate) fn result_from_raw(
    ret: std::os::raw::c_int,
) -> Result<std::os::raw::c_int, MbedtlsError> {
    if ret < 0 {
        Err(MbedtlsError::from_raw(ret))
    } else {
        Ok(ret)
    }
}
