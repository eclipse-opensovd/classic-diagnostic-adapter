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

//! Safe wrapper around `mbedtls_ssl_config`.

use std::{ffi::CString, io, sync::Arc};

use mbedtls_sys as ffi;

use crate::{
    error::{MbedtlsError, result_from_raw},
    x509::{PrivateKey, X509Certificate},
};

const ZERO_TERMINATOR: u8 = 0;

/// Certificate-verification mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslVerifyMode {
    /// No verification (insecure for clients).
    None,
    /// Verify if a certificate is presented, but continue if absent.
    Optional,
    /// Peer *must* present a valid certificate (default for clients).
    Required,
}

impl SslVerifyMode {
    fn to_raw(self) -> i32 {
        // these constants are between 0 and 2, so cast is fine
        #[allow(clippy::cast_possible_wrap)]
        match self {
            Self::None => ffi::MBEDTLS_SSL_VERIFY_NONE as i32,
            Self::Optional => ffi::MBEDTLS_SSL_VERIFY_OPTIONAL as i32,
            Self::Required => ffi::MBEDTLS_SSL_VERIFY_REQUIRED as i32,
        }
    }
}

/// Maximum fragment length extension values.
///
/// Used with [`SslConfigBuilder::max_fragment_length`] to negotiate smaller
/// record sizes (useful for constrained devices).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxFragLen {
    /// Do not use the max-fragment-length extension (default).
    None,
    Len512,
    Len1024,
    Len2048,
    Len4096,
}

impl MaxFragLen {
    fn to_raw(self) -> u8 {
        // these constants are between 0 and 4 as defined in the RFC
        // so the cast is fine
        #[allow(clippy::cast_possible_truncation)]
        match self {
            Self::None => ffi::MBEDTLS_SSL_MAX_FRAG_LEN_NONE as u8,
            Self::Len512 => ffi::MBEDTLS_SSL_MAX_FRAG_LEN_512 as u8,
            Self::Len1024 => ffi::MBEDTLS_SSL_MAX_FRAG_LEN_1024 as u8,
            Self::Len2048 => ffi::MBEDTLS_SSL_MAX_FRAG_LEN_2048 as u8,
            Self::Len4096 => ffi::MBEDTLS_SSL_MAX_FRAG_LEN_4096 as u8,
        }
    }
}

/// Shared, immutable TLS configuration.
///
/// Mirrors the `openssl::ssl::SslConnector` / `SslAcceptor` pattern: build
/// once, then hand an `Arc<SslConfig>` to every connection.
///
/// # Ownership
///
/// `SslConfig` takes **ownership** of the certificate chain and private key
/// that are passed in, keeping them alive for the lifetime of the config.
pub struct SslConfig {
    inner: ffi::mbedtls_ssl_config,
    // Prevent the owned objects from being dropped while the config references them.
    _ca_chain: Option<Box<X509Certificate>>,
    _own_cert: Option<Box<X509Certificate>>,
    _own_key: Option<Box<PrivateKey>>,
    _alpn_cstrings: Option<Vec<CString>>,
    _alpn_ptrs: Option<Vec<*const std::os::raw::c_char>>,
    _ciphersuites: Option<Vec<i32>>,
    _groups: Option<Vec<u16>>,
    _sig_algs: Option<Vec<u16>>,
}

// Safety: after building, the config is read-only and all referenced data is
// owned. mbedtls_ssl_config is safe to share across threads.
unsafe impl Send for SslConfig {}
unsafe impl Sync for SslConfig {}

/// Builder for [`SslConfig`].
pub struct SslConfigBuilder {
    inner: ffi::mbedtls_ssl_config,
    ca_chain: Option<Box<X509Certificate>>,
    own_cert: Option<Box<X509Certificate>>,
    own_key: Option<Box<PrivateKey>>,
    alpn_cstrings: Option<Vec<CString>>,
    alpn_ptrs: Option<Vec<*const std::os::raw::c_char>>,
    ciphersuites: Option<Vec<i32>>,
    groups: Option<Vec<u16>>,
    sig_algs: Option<Vec<u16>>,
    is_built: bool,
}

impl SslConfigBuilder {
    /// Create a TLS **client** configuration with sane defaults.
    ///
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying mbedtls function
    ///   returns an error when initializing the ssl context with the set
    ///   config.
    pub fn new_client() -> Result<Self, MbedtlsError> {
        // these constants are all 0, so cast is fine
        #[allow(clippy::cast_possible_wrap)]
        Self::new(
            ffi::MBEDTLS_SSL_IS_CLIENT as i32,
            ffi::MBEDTLS_SSL_TRANSPORT_STREAM as i32,
            ffi::MBEDTLS_SSL_PRESET_DEFAULT as i32,
        )
    }

    /// Create a TLS **server** configuration with sane defaults.
    ///
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying mbedtls function
    ///   returns an error when initializing the ssl context with the set
    ///   config.
    pub fn new_server() -> Result<Self, MbedtlsError> {
        // these constants are either 1 or 0, so cast is fine
        #[allow(clippy::cast_possible_wrap)]
        Self::new(
            ffi::MBEDTLS_SSL_IS_SERVER as i32,
            ffi::MBEDTLS_SSL_TRANSPORT_STREAM as i32,
            ffi::MBEDTLS_SSL_PRESET_DEFAULT as i32,
        )
    }

    fn new(endpoint: i32, transport: i32, preset: i32) -> Result<Self, MbedtlsError> {
        unsafe {
            let mut conf: ffi::mbedtls_ssl_config = std::mem::zeroed();
            ffi::mbedtls_ssl_config_init(&raw mut conf);
            result_from_raw(ffi::mbedtls_ssl_config_defaults(
                &raw mut conf,
                endpoint,
                transport,
                preset,
            ))?;
            Ok(Self {
                inner: conf,
                ca_chain: None,
                own_cert: None,
                own_key: None,
                alpn_cstrings: None,
                alpn_ptrs: None,
                ciphersuites: None,
                groups: None,
                sig_algs: None,
                is_built: false,
            })
        }
    }

    /// Set the trusted CA chain for peer-certificate verification.
    ///
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying mbedtls function
    ///   returns an error.
    #[must_use]
    pub fn ca_chain(mut self, ca: X509Certificate) -> Self {
        let mut ca = Box::new(ca);
        unsafe {
            ffi::mbedtls_ssl_conf_ca_chain(
                &raw mut self.inner,
                ca.as_mut_ptr(),
                std::ptr::null_mut(), // no CRL
            );
        }
        self.ca_chain = Some(ca);
        self
    }

    /// Set the server's own certificate and private key.
    ///
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying mbedtls function
    ///   returns an error.
    pub fn own_cert(mut self, cert: X509Certificate, key: PrivateKey) -> Result<Self, io::Error> {
        let mut cert = Box::new(cert);
        let mut key = Box::new(key);
        let ret = unsafe {
            ffi::mbedtls_ssl_conf_own_cert(&raw mut self.inner, cert.as_mut_ptr(), key.as_mut_ptr())
        };
        result_from_raw(ret)?;
        self.own_cert = Some(cert);
        self.own_key = Some(key);
        Ok(self)
    }

    /// Set the certificate verification mode.
    #[must_use]
    pub fn verify_mode(mut self, mode: SslVerifyMode) -> Self {
        unsafe {
            ffi::mbedtls_ssl_conf_authmode(&raw mut self.inner, mode.to_raw());
        }
        self
    }

    /// Restrict the minimum TLS version.
    #[must_use]
    pub fn min_tls_version(mut self, version: TlsVersion) -> Self {
        self.inner.private_min_tls_version = version.to_raw();
        self
    }

    /// Restrict the maximum TLS version.
    #[must_use]
    pub fn max_tls_version(mut self, version: TlsVersion) -> Self {
        self.inner.private_max_tls_version = version.to_raw();
        self
    }

    /// Set the list of allowed ciphersuites.
    ///
    /// Pass IANA ciphersuite identifiers. Use the `ffi::MBEDTLS_TLS_*` and
    /// `ffi::MBEDTLS_TLS1_3_*` constants. The list must be ordered by
    /// preference (most preferred first).
    ///
    /// # Example
    /// ```ignore
    /// use mbedtls_rs::ffi;
    /// builder.ciphersuites(&[
    ///     ffi::MBEDTLS_TLS1_3_AES_256_GCM_SHA384 as i32,
    ///     ffi::MBEDTLS_TLS1_3_AES_128_GCM_SHA256 as i32,
    ///     ffi::MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 as i32,
    /// ])
    /// ```
    ///
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying mbedtls function
    ///   returns an error.
    #[must_use]
    pub fn ciphersuites(mut self, ciphersuites: &[i32]) -> Self {
        let mut cs: Vec<i32> = ciphersuites.to_vec();
        cs.push(i32::from(ZERO_TERMINATOR));
        unsafe {
            ffi::mbedtls_ssl_conf_ciphersuites(&raw mut self.inner, cs.as_ptr());
        }
        self.ciphersuites = Some(cs);
        self
    }

    /// Set the list of allowed groups (curves / finite fields) for key exchange.
    ///
    /// Pass IANA `NamedGroup` identifiers. Use `ffi::MBEDTLS_SSL_IANA_TLS_GROUP_*`
    /// constants. The list must be ordered by preference.
    ///
    /// # Example
    /// ```ignore
    /// use mbedtls_rs::ffi;
    /// builder.groups(&[
    ///     ffi::MBEDTLS_SSL_IANA_TLS_GROUP_X25519 as u16,
    ///     ffi::MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1 as u16,
    ///     ffi::MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1 as u16,
    /// ])
    /// ```
    ///
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying mbedtls function
    ///   returns an error.
    #[must_use]
    pub fn groups(mut self, groups: &[u16]) -> Self {
        let mut g: Vec<u16> = groups.to_vec();
        g.push(u16::from(ZERO_TERMINATOR));
        unsafe {
            ffi::mbedtls_ssl_conf_groups(&raw mut self.inner, g.as_ptr());
        }
        self.groups = Some(g);
        self
    }

    /// Set the list of allowed signature algorithms (TLS 1.2 + 1.3).
    ///
    /// Pass IANA `SignatureScheme` identifiers. For TLS 1.3, use
    /// `ffi::MBEDTLS_TLS1_3_SIG_*` constants. The list must be ordered by
    /// preference.
    ///
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying mbedtls function
    ///   returns an error.
    #[must_use]
    pub fn sig_algs(mut self, sig_algs: &[u16]) -> Self {
        let mut sa: Vec<u16> = sig_algs.to_vec();
        // MBEDTLS_TLS1_3_SIG_NONE is 0 so the cast is safe
        #[allow(clippy::cast_possible_truncation)]
        sa.push(ffi::MBEDTLS_TLS1_3_SIG_NONE as u16); // add the expected zero terminator
        unsafe {
            ffi::mbedtls_ssl_conf_sig_algs(&raw mut self.inner, sa.as_ptr());
        }
        self.sig_algs = Some(sa);
        self
    }

    /// Set the maximum fragment length extension.
    ///
    /// Negotiates a smaller maximum record payload size with the peer.
    ///
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying mbedtls function
    ///   returns an error.
    pub fn max_fragment_length(mut self, mfl: MaxFragLen) -> Result<Self, io::Error> {
        let ret = unsafe { ffi::mbedtls_ssl_conf_max_frag_len(&raw mut self.inner, mfl.to_raw()) };
        result_from_raw(ret)?;
        Ok(self)
    }

    /// Set the list of supported ALPN protocols (e.g. `["h2", "http/1.1"]`).
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying mbedtls function
    ///   returns an error.
    pub fn alpn_protocols(mut self, protocols: &[&str]) -> Result<Self, io::Error> {
        let cstrings: Vec<CString> = protocols
            .iter()
            .map(|p| {
                CString::new(*p).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("protocol {p} contains interior NUL: {e}"),
                    )
                })
            })
            .collect::<Result<_, _>>()?;
        let mut ptrs: Vec<*const std::os::raw::c_char> =
            cstrings.iter().map(|c| c.as_ptr()).collect();
        ptrs.push(std::ptr::null()); // null-terminated array

        let ret =
            unsafe { ffi::mbedtls_ssl_conf_alpn_protocols(&raw mut self.inner, ptrs.as_ptr()) };
        result_from_raw(ret)?;
        self.alpn_cstrings = Some(cstrings);
        self.alpn_ptrs = Some(ptrs);
        Ok(self)
    }

    // ---- build ----

    /// Freeze the configuration and return a shareable `Arc<SslConfig>`.
    #[must_use]
    pub fn build(mut self) -> Arc<SslConfig> {
        self.is_built = true;
        Arc::new(SslConfig {
            inner: std::mem::take(&mut self.inner),
            _ca_chain: std::mem::take(&mut self.ca_chain),
            _own_cert: std::mem::take(&mut self.own_cert),
            _own_key: std::mem::take(&mut self.own_key),
            _alpn_cstrings: std::mem::take(&mut self.alpn_cstrings),
            _alpn_ptrs: std::mem::take(&mut self.alpn_ptrs),
            _ciphersuites: std::mem::take(&mut self.ciphersuites),
            _groups: std::mem::take(&mut self.groups),
            _sig_algs: std::mem::take(&mut self.sig_algs),
        })
    }
}

/// TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl TlsVersion {
    fn to_raw(self) -> ffi::mbedtls_ssl_protocol_version {
        match self {
            Self::Tls12 => ffi::mbedtls_ssl_protocol_version_MBEDTLS_SSL_VERSION_TLS1_2,
            Self::Tls13 => ffi::mbedtls_ssl_protocol_version_MBEDTLS_SSL_VERSION_TLS1_3,
        }
    }
}

impl SslConfig {
    /// Raw const pointer - used by `SslStream` to set up a context.
    pub(crate) fn as_ptr(&self) -> *const ffi::mbedtls_ssl_config {
        &raw const self.inner
    }
}

impl Drop for SslConfig {
    fn drop(&mut self) {
        unsafe { ffi::mbedtls_ssl_config_free(&raw mut self.inner) }
    }
}

impl Drop for SslConfigBuilder {
    fn drop(&mut self) {
        // drop only if the config wasnt built, otherwise ownership was transferred to SslConfig
        // and it will be dropped there
        if !self.is_built {
            unsafe { ffi::mbedtls_ssl_config_free(&raw mut self.inner) }
        }
    }
}

impl std::fmt::Debug for SslConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SslConfig").finish_non_exhaustive()
    }
}
