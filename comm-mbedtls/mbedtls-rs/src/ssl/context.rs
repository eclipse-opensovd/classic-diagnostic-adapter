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

//! Synchronous TLS stream wrapping a `Read + Write` transport.
//!
//! This follows the same pattern as `openssl::ssl::SslStream`:
//!
//! 1. Create an `SslStream` from an `SslConfig` + transport.
//! 2. Perform the TLS handshake (can be non-blocking -> `MidHandshakeSslStream`).
//! 3. Read/write cleartext through the `SslStream`.

use std::{
    ffi::CStr,
    io::{self, Read, Write},
    os::raw::{c_int, c_uchar, c_void},
    pin::Pin,
    sync::Arc,
};

use mbedtls_sys as ffi;

use crate::{error::MbedtlsError, ssl::SslConfig};

// ---------------------------------------------------------------------------
// BIO callbacks - bridge mbedtls I/O to Rust Read/Write
// ---------------------------------------------------------------------------

/// The BIO context we stash behind `p_bio`. It holds a pointer to the Rust
/// stream plus an optional I/O error to shuttle back to the caller.
struct BioContext<S> {
    stream: S,
    /// Last I/O error, if the BIO callback encountered one.
    last_error: Option<io::Error>,
}

/// `f_send` callback: called by mbedtls when it wants to write ciphertext.
unsafe extern "C" fn bio_send<S: Write>(
    ctx: *mut c_void,
    buf: *const c_uchar,
    len: usize,
) -> c_int {
    let bio = unsafe { &mut *ctx.cast::<BioContext<S>>() };
    let slice = unsafe { std::slice::from_raw_parts(buf, len) };
    match bio.stream.write(slice) {
        Ok(0) => ffi::MBEDTLS_ERR_SSL_CONN_EOF as c_int,
        Ok(n) => c_int::try_from(n).unwrap_or(ffi::MBEDTLS_ERR_SSL_INTERNAL_ERROR as c_int),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
            ffi::MBEDTLS_ERR_SSL_WANT_WRITE as c_int
        }
        Err(e) => {
            bio.last_error = Some(e);
            ffi::MBEDTLS_ERR_SSL_INTERNAL_ERROR as c_int
        }
    }
}

/// `f_recv` callback: called by mbedtls when it wants to read ciphertext.
unsafe extern "C" fn bio_recv<S: Read>(ctx: *mut c_void, buf: *mut c_uchar, len: usize) -> c_int {
    let bio = unsafe { &mut *ctx.cast::<BioContext<S>>() };
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    match bio.stream.read(slice) {
        Ok(0) => ffi::MBEDTLS_ERR_SSL_CONN_EOF as c_int,
        Ok(n) => c_int::try_from(n).unwrap_or(ffi::MBEDTLS_ERR_SSL_INTERNAL_ERROR as c_int),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
            ffi::MBEDTLS_ERR_SSL_WANT_READ as c_int
        }
        Err(e) => {
            bio.last_error = Some(e);
            ffi::MBEDTLS_ERR_SSL_INTERNAL_ERROR as c_int
        }
    }
}

// ---------------------------------------------------------------------------
// SslStream
// ---------------------------------------------------------------------------

/// A TLS-encrypted stream over a transport `S`.
///
/// Created via [`SslStream::connect`] (client) or [`SslStream::accept`] (server).
/// Once the handshake succeeds, implements [`Read`] and [`Write`] for cleartext
/// I/O.
pub struct SslStream<S> {
    ssl: ffi::mbedtls_ssl_context,
    /// Pinned so the BIO pointer stays valid.
    bio: Pin<Box<BioContext<S>>>,
    /// Keep the config alive.
    _config: Arc<SslConfig>,
}

// Safety: S: Send => SslStream<S>: Send. The mbedtls context is not
// accessed from multiple threads simultaneously.
unsafe impl<S: Send> Send for SslStream<S> {}

impl<S: Read + Write> SslStream<S> {
    // ---- construction helpers ----

    /// Begin a TLS **client** handshake over `stream`.
    ///
    /// If `hostname` is set `mbedtls_ssl_set_hostname` is called which enables SNI.
    /// # Errors
    /// * `HandshakeError::Failure` if `psa_crypto_init` fails
    /// * `HandshakeError::Failure` if setting any mbedtls config parameters fails.
    /// * `HandshakeError::WouldBlock` if the handshake cannot complete because the
    ///   underlying transport would block.
    /// * `HandshakeError::Failure` if a fatal I/O or TLS error occurred during the
    ///   handshake
    /// * `HandshakeError::Failure` if `hostname` contains an interior NUL byte.
    pub fn connect(
        config: Arc<SslConfig>,
        stream: S,
        hostname: Option<&str>,
    ) -> HandshakeResult<S> {
        let mut ssl = Self::new_inner(config, stream)?;
        if let Some(hostname) = hostname {
            let c_host = std::ffi::CString::new(hostname).map_err(|e| {
                HandshakeError::Failure(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("hostname contains interior NUL: {e}"),
                ))
            })?;
            let ret = unsafe { ffi::mbedtls_ssl_set_hostname(&raw mut ssl.ssl, c_host.as_ptr()) };
            mbedtls_result(ret).map_err(|e| HandshakeError::Failure(e.into()))?;
        }
        ssl.complete_handshake()
    }

    /// Begin a TLS **server** handshake over `stream`.
    /// # Errors
    /// * `HandshakeError::Failure` if `psa_crypto_init` fails
    /// * `HandshakeError::Failure` if setting any mbedtls config parameters fails.
    /// * `HandshakeError::WouldBlock` if the handshake cannot complete because the
    ///   underlying transport would block.
    /// * `HandshakeError::Failure` if a fatal I/O or TLS error occurred during
    ///   the handshake
    pub fn accept(config: Arc<SslConfig>, stream: S) -> HandshakeResult<S> {
        let ssl = Self::new_inner(config, stream)?;
        ssl.complete_handshake()
    }

    fn new_inner(
        config: Arc<SslConfig>,
        stream: S,
    ) -> std::result::Result<Self, HandshakeError<S>> {
        unsafe {
            // Initialise PSA crypto (idempotent).
            let psa_ret = ffi::psa_crypto_init();
            if psa_ret != 0 {
                return Err(HandshakeError::Failure(io::Error::other(format!(
                    "psa_crypto_init failed: {psa_ret}"
                ))));
            }

            let mut ssl: ffi::mbedtls_ssl_context = std::mem::zeroed();
            ffi::mbedtls_ssl_init(&raw mut ssl);

            let ret = ffi::mbedtls_ssl_setup(&raw mut ssl, config.as_ptr());
            mbedtls_result(ret).map_err(|e| {
                ffi::mbedtls_ssl_free(&raw mut ssl);
                HandshakeError::Failure(e.into())
            })?;

            let bio = Box::pin(BioContext {
                stream,
                last_error: None,
            });

            // need to cast away the const modifier and change to c_void,
            // as the c api takes a non const void pointer.
            let bio_ptr: *mut c_void = (&raw const *bio).cast_mut().cast::<c_void>();

            ffi::mbedtls_ssl_set_bio(
                &raw mut ssl,
                bio_ptr,
                Some(bio_send::<S>),
                Some(bio_recv::<S>),
                None,
            );

            Ok(SslStream {
                ssl,
                bio,
                _config: config,
            })
        }
    }

    fn complete_handshake(mut self) -> HandshakeResult<S> {
        match self.do_handshake() {
            Ok(()) => Ok(self),
            Err(ref e) if e.is_want_read() || e.is_want_write() => Err(HandshakeError::WouldBlock(
                Box::new(MidHandshakeSslStream(self)),
            )),
            Err(e) => {
                // Propagate any underlying I/O error.
                let io_err = self.take_bio_error().unwrap_or_else(|| e.into());
                Err(HandshakeError::Failure(io_err))
            }
        }
    }

    fn do_handshake(&mut self) -> Result<(), MbedtlsError> {
        let ret = unsafe { ffi::mbedtls_ssl_handshake(&raw mut self.ssl) };
        mbedtls_result(ret)
    }

    fn take_bio_error(&mut self) -> Option<io::Error> {
        // Safety: we have &mut self, so exclusive access.
        unsafe {
            let bio = Pin::get_unchecked_mut(self.bio.as_mut());
            bio.last_error.take()
        }
    }

    // ---- inspection ----

    /// The negotiated ALPN protocol, if any.
    #[must_use]
    pub fn alpn_protocol(&self) -> Option<&str> {
        unsafe {
            let ptr = ffi::mbedtls_ssl_get_alpn_protocol(&raw const self.ssl);
            if ptr.is_null() {
                None
            } else {
                CStr::from_ptr(ptr).to_str().ok()
            }
        }
    }

    /// The negotiated TLS version string (e.g. `"TLSv1.3"`).
    #[must_use]
    pub fn version_str(&self) -> &str {
        unsafe {
            let ptr = ffi::mbedtls_ssl_get_version(&raw const self.ssl);
            if ptr.is_null() {
                "unknown"
            } else {
                CStr::from_ptr(ptr).to_str().unwrap_or("unknown")
            }
        }
    }

    /// The negotiated ciphersuite name.
    #[must_use]
    pub fn ciphersuite(&self) -> &str {
        unsafe {
            let ptr = ffi::mbedtls_ssl_get_ciphersuite(&raw const self.ssl);
            if ptr.is_null() {
                "unknown"
            } else {
                CStr::from_ptr(ptr).to_str().unwrap_or("unknown")
            }
        }
    }

    /// Access the underlying transport.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.bio.stream
    }

    /// Mutable access to the underlying transport.
    ///
    /// # Safety
    ///
    /// Do not read from or write to the transport directly while TLS records
    /// are in flight - this will corrupt the TLS session.
    pub fn get_mut(&mut self) -> &mut S {
        unsafe { &mut Pin::get_unchecked_mut(self.bio.as_mut()).stream }
    }

    /// Send a TLS `close_notify` alert to the peer.
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying transport returns an
    ///   error on `mbedtls_ssl_close_notify`
    pub fn shutdown(&mut self) -> Result<(), MbedtlsError> {
        let ret = unsafe { ffi::mbedtls_ssl_close_notify(&raw mut self.ssl) };
        mbedtls_result(ret)
    }
}

impl<S: Read + Write> Read for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = unsafe { ffi::mbedtls_ssl_read(&raw mut self.ssl, buf.as_mut_ptr(), buf.len()) };
        match ret {
            #[allow(clippy::cast_sign_loss)] // ret is checked if it is positive
            n if n > 0 => Ok(n as usize),
            0 => Ok(0), // EOF / peer closed
            n => {
                let err = MbedtlsError::from_raw(n);
                if err.is_peer_close_notify() {
                    Ok(0) // graceful close
                } else {
                    Err(self.take_bio_error().unwrap_or_else(|| err.into()))
                }
            }
        }
    }
}

impl<S: Read + Write> Write for SslStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ret = unsafe { ffi::mbedtls_ssl_write(&raw mut self.ssl, buf.as_ptr(), buf.len()) };
        if ret >= 0 {
            #[allow(clippy::cast_sign_loss)] // ret is check if it is not negative
            Ok(ret as usize)
        } else {
            let err = MbedtlsError::from_raw(ret);
            Err(self.take_bio_error().unwrap_or_else(|| err.into()))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // mbedtls writes are flushed per-record, but flush the underlying stream.
        unsafe { Pin::get_unchecked_mut(self.bio.as_mut()).stream.flush() }
    }
}

impl<S> Drop for SslStream<S> {
    fn drop(&mut self) {
        unsafe { ffi::mbedtls_ssl_free(&raw mut self.ssl) }
    }
}

impl<S: std::fmt::Debug> std::fmt::Debug for SslStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SslStream").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Handshake helpers
// ---------------------------------------------------------------------------

/// The result of an attempted TLS handshake.
pub type HandshakeResult<S> = std::result::Result<SslStream<S>, HandshakeError<S>>;

/// Error during the TLS handshake.
pub enum HandshakeError<S> {
    /// The handshake could not complete because the underlying transport
    /// returned `WouldBlock`. The caller should poll the transport and then
    /// call [`MidHandshakeSslStream::handshake`] again.
    /// `MidHandshakeSslStream` is boxed as it can be large
    WouldBlock(Box<MidHandshakeSslStream<S>>),

    /// A fatal I/O or TLS error occurred.
    Failure(io::Error),
}

impl<S: std::fmt::Debug> std::fmt::Debug for HandshakeError<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WouldBlock(_) => f.write_str("HandshakeError::WouldBlock(..)"),
            Self::Failure(e) => write!(f, "HandshakeError::Failure({e})"),
        }
    }
}

impl<S: std::fmt::Debug> std::fmt::Display for HandshakeError<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WouldBlock(_) => f.write_str("TLS handshake would block"),
            Self::Failure(e) => write!(f, "TLS handshake failed: {e}"),
        }
    }
}

impl<S: std::fmt::Debug> std::error::Error for HandshakeError<S> {}

/// A TLS stream whose handshake has not yet completed.
///
/// Can take the stream from [`HandshakeError::WouldBlock`] and call [`handshake`]
/// again once the transport is ready.
///
/// [`handshake`]: MidHandshakeSslStream::handshake
pub struct MidHandshakeSslStream<S>(SslStream<S>);

impl<S: Read + Write> MidHandshakeSslStream<S> {
    /// Resume the TLS handshake.
    /// # Errors
    /// * `HandshakeError::WouldBlock` if the handshake cannot complete
    ///   because the underlying transport would block. The caller should
    ///   poll the transport and call `handshake` again.
    /// * `HandshakeError::Failure` if a fatal I/O or TLS error occurred.
    pub fn handshake(self) -> HandshakeResult<S> {
        self.0.complete_handshake()
    }

    /// Access the underlying transport (e.g. to register for readiness).
    #[must_use]
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }
}

/// Turns mbedtls return code into a `Result<(), MbedtlsError`
/// # Errors
/// `MbedtlsError` if `code != 0`
fn mbedtls_result(code: i32) -> Result<(), MbedtlsError> {
    match code {
        0 => Ok(()),
        err => Err(MbedtlsError::from_raw(err)),
    }
}
