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

//! Safe wrappers for mbedtls X.509 certificates and private keys.

use std::{ffi::CString, io, ptr};

use mbedtls_sys as ffi;

use crate::error::{MbedtlsError, result_from_raw};

/// A parsed X.509 certificate chain.
///
/// Wraps `mbedtls_x509_crt`. Drop cleans up via `mbedtls_x509_crt_free`.
pub struct X509Certificate {
    inner: ffi::mbedtls_x509_crt,
}

// Safety: mbedtls_x509_crt is a self-contained data structure.
// It is safe to send across threads once fully initialized.
unsafe impl Send for X509Certificate {}

impl X509Certificate {
    /// Parse a PEM- or DER-encoded certificate (chain).
    ///
    /// For PEM, the buffer must include the null terminator (the length must
    /// account for it). Multiple PEM blocks in a single buffer will be parsed
    /// into a chain.
    ///
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying mbedtls function
    ///   returns an error, such as if the input is invalid.
    pub fn from_pem(pem: &[u8]) -> Result<Self, MbedtlsError> {
        // mbedtls_x509_crt_parse expects the terminating NUL for PEM
        if pem.last().is_none_or(|v| *v != 0) {
            return Err(MbedtlsError::from_raw(
                mbedtls_sys::MBEDTLS_ERR_SSL_BAD_CONFIG,
            ));
        }
        let mut crt = Self::new_uninit();
        let ret =
            unsafe { ffi::mbedtls_x509_crt_parse(&raw mut crt.inner, pem.as_ptr(), pem.len()) };
        result_from_raw(ret)?;
        Ok(crt)
    }

    /// Parse a single DER-encoded certificate.
    ///
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying mbedtls function
    ///   returns an error, such as if the input is invalid.
    pub fn from_der(der: &[u8]) -> Result<Self, MbedtlsError> {
        let mut crt = Self::new_uninit();
        let ret =
            unsafe { ffi::mbedtls_x509_crt_parse_der(&raw mut crt.inner, der.as_ptr(), der.len()) };
        result_from_raw(ret)?;
        Ok(crt)
    }

    /// Load certificate(s) from a file (PEM or DER).
    ///
    /// # Errors
    /// * `io::Error` wrapping an `MbedtlsError` with the error code if the underlying
    ///   mbedtls function returns an error, such as if the file is not found.
    /// * `io::Error` if the path contains interior NUL bytes.
    pub fn from_file(path: &str) -> Result<Self, io::Error> {
        let c_path = CString::new(path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("path contains interior NUL: {e}"),
            )
        })?;
        let mut crt = Self::new_uninit();
        let ret = unsafe { ffi::mbedtls_x509_crt_parse_file(&raw mut crt.inner, c_path.as_ptr()) };
        result_from_raw(ret)?;
        Ok(crt)
    }

    /// Append more certificates (PEM or DER) to this chain.
    ///
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying mbedtls function
    ///   returns an error, such as if the input is invalid.
    pub fn append_pem(&mut self, pem: &[u8]) -> Result<(), MbedtlsError> {
        let ret =
            unsafe { ffi::mbedtls_x509_crt_parse(&raw mut self.inner, pem.as_ptr(), pem.len()) };
        result_from_raw(ret)?;
        Ok(())
    }

    fn new_uninit() -> Self {
        unsafe {
            let mut crt: ffi::mbedtls_x509_crt = std::mem::zeroed();
            ffi::mbedtls_x509_crt_init(&raw mut crt);
            Self { inner: crt }
        }
    }

    /// Raw pointer - used internally by `SslConfig`.
    pub(crate) fn as_mut_ptr(&mut self) -> *mut ffi::mbedtls_x509_crt {
        &raw mut self.inner
    }
}

impl Drop for X509Certificate {
    fn drop(&mut self) {
        unsafe { ffi::mbedtls_x509_crt_free(&raw mut self.inner) }
    }
}

impl std::fmt::Debug for X509Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X509Certificate")
            .field("version", &self.inner.version)
            .finish_non_exhaustive()
    }
}
/// A parsed private (or public) key.
///
/// Wraps `mbedtls_pk_context`. Drop cleans up via `mbedtls_pk_free`.
pub struct PrivateKey {
    inner: ffi::mbedtls_pk_context,
}

// Safety: mbedtls_pk_context is a self-contained data structure.
// It is safe to send across threads once fully initialized.
unsafe impl Send for PrivateKey {}

impl PrivateKey {
    /// Parse a PEM- or DER-encoded private key.
    ///
    /// For PEM the buffer must include the trailing NUL byte in its length.
    /// `password` may be empty for unencrypted keys.
    ///
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying mbedtls function
    ///   returns an error, such as if the key is invalid or the password is incorrect.
    pub fn from_pem(pem: &[u8], password: &[u8]) -> Result<Self, MbedtlsError> {
        let mut pk = Self::new_uninit();
        let pwd_ptr = if password.is_empty() {
            ptr::null()
        } else {
            password.as_ptr()
        };
        let pwd_len = password.len();
        let ret = unsafe {
            ffi::mbedtls_pk_parse_key(&raw mut pk.inner, pem.as_ptr(), pem.len(), pwd_ptr, pwd_len)
        };
        result_from_raw(ret)?;
        Ok(pk)
    }

    /// Load a private key from a file.
    ///
    /// # Errors
    /// * `io::Error` if the path or password contain interior NUL bytes
    /// * `io::Error` wrapping an `MbedtlsError` if the underlying mbedtls
    ///   function returns an error, such as if the file is not found or
    ///   the key is invalid.
    pub fn from_file(path: &str, password: Option<&str>) -> Result<Self, io::Error> {
        let c_path = CString::new(path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("path contains interior NUL: {e}"),
            )
        })?;
        let c_pwd = password
            .map(|p| {
                CString::new(p).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("password contains interior NUL: {e}"),
                    )
                })
            })
            .transpose()?;
        let pwd_ptr = c_pwd.as_ref().map_or(ptr::null(), |c| c.as_ptr());
        let mut pk = Self::new_uninit();
        let ret =
            unsafe { ffi::mbedtls_pk_parse_keyfile(&raw mut pk.inner, c_path.as_ptr(), pwd_ptr) };
        result_from_raw(ret)?;
        Ok(pk)
    }

    fn new_uninit() -> Self {
        unsafe {
            let mut pk: ffi::mbedtls_pk_context = std::mem::zeroed();
            ffi::mbedtls_pk_init(&raw mut pk);
            Self { inner: pk }
        }
    }

    /// Raw pointer - used internally by `SslConfig`.
    pub(crate) fn as_mut_ptr(&mut self) -> *mut ffi::mbedtls_pk_context {
        &raw mut self.inner
    }

    /// Key size in bits.
    #[must_use]
    pub fn bit_len(&self) -> usize {
        unsafe { ffi::mbedtls_pk_get_bitlen(&raw const self.inner) }
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        unsafe { ffi::mbedtls_pk_free(&raw mut self.inner) }
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("bits", &self.bit_len())
            .finish_non_exhaustive()
    }
}
