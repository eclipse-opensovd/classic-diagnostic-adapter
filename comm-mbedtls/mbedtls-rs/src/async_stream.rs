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

//! Async TLS stream for use with Tokio.
//!
//! Follows the same approach as `tokio-openssl`: wraps the synchronous
//! `SslStream` and drives I/O through an intermediate memory BIO, shuttling
//! bytes between `AsyncRead`/`AsyncWrite` and mbedtls.
//!
//! # Usage
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use tokio::net::TcpStream;
//! use mbedtls_rs::ssl::{SslConfig, SslConfigBuilder, SslVerifyMode};
//! use mbedtls_rs::async_stream::TlsStream;
//!
//! # async fn example() -> std::io::Result<()> {
//! let config = SslConfigBuilder::new_client()
//!     .unwrap()
//!     .verify_mode(SslVerifyMode::Required)
//!     .build();
//!
//! let tcp = TcpStream::connect("example.com:443").await?;
//! let mut tls = TlsStream::connect(config, tcp, Some("example.com")).await?;
//!
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! tls.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n").await?;
//! let mut buf = vec![0u8; 4096];
//! let n = tls.read(&mut buf).await?;
//! # Ok(())
//! # }
//! ```

use std::{
    io,
    os::raw::{c_int, c_uchar, c_void},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use mbedtls_sys as ffi;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{error::MbedtlsError, ssl::SslConfig};

// ---------------------------------------------------------------------------
// Internal memory BIO
// ---------------------------------------------------------------------------

/// A pair of in-memory byte buffers that bridge async I/O <-> mbedtls.
///
/// * **`incoming`** - bytes read from the network go here; mbedtls reads from it.
/// * **`outgoing`** - mbedtls writes ciphertext here; we drain it to the network.
struct MemBio {
    incoming: Vec<u8>,
    incoming_cursor: usize,
    outgoing: Vec<u8>,
}

impl MemBio {
    fn new() -> Self {
        Self {
            incoming: Vec::with_capacity(16 * 1024),
            incoming_cursor: 0,
            outgoing: Vec::with_capacity(16 * 1024),
        }
    }

    /// Feed network data into the incoming buffer.
    fn feed_incoming(&mut self, data: &[u8]) {
        // Compact first.
        if self.incoming_cursor > 0 {
            self.incoming.drain(..self.incoming_cursor);
            self.incoming_cursor = 0;
        }
        self.incoming.extend_from_slice(data);
    }

    /// How many incoming bytes are available for mbedtls to read.
    fn incoming_available(&self) -> usize {
        self.incoming.len().saturating_sub(self.incoming_cursor)
    }

    /// Read from incoming into `buf` (called by the `bio_recv` callback).
    fn read_incoming(&mut self, buf: &mut [u8]) -> usize {
        let avail = self.incoming_available();
        if avail == 0 {
            return 0;
        }
        let n = avail.min(buf.len());
        let new_cursor = self.incoming_cursor.saturating_add(n);
        // fine as `incoming_available` ensures avail is always < incoming.len - cursor
        // and n is always the lesser of buf.len and avail
        #[allow(clippy::indexing_slicing)]
        buf[..n].copy_from_slice(&self.incoming[self.incoming_cursor..new_cursor]);
        self.incoming_cursor = self.incoming_cursor.saturating_add(n);
        n
    }

    /// Take all pending outgoing ciphertext.
    fn take_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outgoing)
    }

    fn has_outgoing(&self) -> bool {
        !self.outgoing.is_empty()
    }
}

// ---------------------------------------------------------------------------
// BIO callbacks for the memory-buffered approach
// ---------------------------------------------------------------------------

unsafe extern "C" fn membio_send(ctx: *mut c_void, buf: *const c_uchar, len: usize) -> c_int {
    let bio = unsafe { &mut *ctx.cast::<MemBio>() };
    let slice = unsafe { std::slice::from_raw_parts(buf, len) };
    bio.outgoing.extend_from_slice(slice);
    c_int::try_from(len).unwrap_or(ffi::MBEDTLS_ERR_SSL_INTERNAL_ERROR as c_int)
}

unsafe extern "C" fn membio_recv(ctx: *mut c_void, buf: *mut c_uchar, len: usize) -> c_int {
    let bio = unsafe { &mut *ctx.cast::<MemBio>() };
    let n = bio.read_incoming(unsafe { std::slice::from_raw_parts_mut(buf, len) });
    if n == 0 {
        ffi::MBEDTLS_ERR_SSL_WANT_READ as c_int
    } else {
        c_int::try_from(n).unwrap_or(ffi::MBEDTLS_ERR_SSL_INTERNAL_ERROR as c_int)
    }
}

/// An async TLS stream over a Tokio `AsyncRead + AsyncWrite` transport.
pub struct TlsStream<S> {
    ssl: ffi::mbedtls_ssl_context,
    bio: Pin<Box<MemBio>>,
    inner: S,
    _config: Arc<SslConfig>,
    handshake_completed: bool,
}

// Safety: S: Send -> TlsStream<S>: Send.
unsafe impl<S: Send> Send for TlsStream<S> {}

impl<S> TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Perform a TLS **client** handshake asynchronously.
    /// If `hostname` is provided `mbedtls_ssl_set_hostname` is called. This enables Server Name
    /// Indication (SNI)
    ///
    /// # Errors
    /// * `IoError` with `psa_crypto_init` return code, if an error occurs while initializing
    ///   the PSA crypto subsystem
    /// * `IoError` from the underlying `MbedtlsError` if setting any of the config for mbedtls
    ///   fails
    /// * `IoError` if the handshake fails
    /// * `IoError` with kind `InvalidInput` if the specified hostname contains an interior
    ///   NUL byte
    pub async fn connect(
        config: Arc<SslConfig>,
        inner: S,
        hostname: Option<&str>,
    ) -> io::Result<Self> {
        let mut stream = Self::new_inner(config, inner)?;
        if let Some(hostname) = hostname {
            let c_host = std::ffi::CString::new(hostname)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let ret =
                unsafe { ffi::mbedtls_ssl_set_hostname(&raw mut stream.ssl, c_host.as_ptr()) };
            if ret != 0 {
                return Err(MbedtlsError::from_raw(ret).into());
            }
        }
        stream.async_handshake().await?;
        Ok(stream)
    }

    /// Perform a TLS **server** handshake asynchronously.
    /// # Errors
    /// * Any errors from `async_handshake` are propagated.
    /// * If the initialization of `psa_crypto` fails returns an error containing the return code
    pub async fn accept(config: Arc<SslConfig>, inner: S) -> io::Result<Self> {
        let mut stream = Self::new_inner(config, inner)?;
        stream.async_handshake().await?;
        Ok(stream)
    }

    fn new_inner(config: Arc<SslConfig>, inner: S) -> io::Result<Self> {
        unsafe {
            let psa_ret = ffi::psa_crypto_init();
            if psa_ret != 0 {
                return Err(io::Error::other(format!(
                    "psa_crypto_init failed: {psa_ret}"
                )));
            }

            let mut ssl: ffi::mbedtls_ssl_context = std::mem::zeroed();
            ffi::mbedtls_ssl_init(&raw mut ssl);

            let ret = ffi::mbedtls_ssl_setup(&raw mut ssl, config.as_ptr());
            if ret != 0 {
                ffi::mbedtls_ssl_free(&raw mut ssl);
                return Err(MbedtlsError::from_raw(ret).into());
            }

            let bio = Box::pin(MemBio::new());
            let bio_ptr = (&raw const *bio).cast_mut().cast::<c_void>();

            ffi::mbedtls_ssl_set_bio(
                &raw mut ssl,
                bio_ptr,
                Some(membio_send),
                Some(membio_recv),
                None,
            );

            Ok(Self {
                ssl,
                bio,
                inner,
                _config: config,
                handshake_completed: false,
            })
        }
    }

    /// Drive the TLS handshake to completion asynchronously.
    async fn async_handshake(&mut self) -> io::Result<()> {
        use tokio::io::AsyncReadExt;

        // Due to the internal read buffer size that is allocated by this future exceeding the
        // recommended maximum feature size that are safe to put on stack, the feature is
        // wrapped in Box::pin to put it on the heap.
        // (see https://rust-lang.github.io/rust-clippy/master/index.html#large_futures)
        Box::pin(async {
            loop {
                let ret = unsafe { ffi::mbedtls_ssl_handshake(&raw mut self.ssl) };

                // Flush any outgoing ciphertext first.
                self.flush_outgoing().await?;

                if ret == 0 {
                    self.handshake_completed = true;
                    return Ok(());
                }

                let err = MbedtlsError::from_raw(ret);
                if err.is_want_read() {
                    // Need more data from the network.
                    // The buffer allocation is the reason we are putting the future on the heap
                    // (see the comment above)
                    let mut buf = [0u8; ffi::MBEDTLS_SSL_IN_CONTENT_LEN as usize];
                    let n = self.inner.read(&mut buf).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "connection closed during TLS handshake",
                        ));
                    }
                    // the n returned from `AsyncReadExt::read` is at most the buffer length
                    #[allow(clippy::indexing_slicing)]
                    self.bio_mut().feed_incoming(&buf[..n]);
                } else if err.is_want_write() {
                    // mbedtls wants us to flush - already done above.
                } else {
                    return Err(err.into());
                }
            }
        })
        .await
    }

    /// Flush outgoing ciphertext to the underlying async transport.
    async fn flush_outgoing(&mut self) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let data = self.bio_mut().take_outgoing();
        if !data.is_empty() {
            self.inner.write_all(&data).await?;
            self.inner.flush().await?;
        }
        Ok(())
    }

    fn bio_mut(&mut self) -> &mut MemBio {
        unsafe { Pin::get_unchecked_mut(self.bio.as_mut()) }
    }

    // ---- public inspection ----

    /// The negotiated ALPN protocol, if any.
    pub fn alpn_protocol(&self) -> Option<&str> {
        unsafe {
            let ptr = ffi::mbedtls_ssl_get_alpn_protocol(&raw const self.ssl);
            if ptr.is_null() {
                None
            } else {
                std::ffi::CStr::from_ptr(ptr).to_str().ok()
            }
        }
    }

    /// Access the underlying transport.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Mutable access to the underlying transport.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Send a TLS `close_notify` and flush.
    /// # Errors
    /// * `MbedtlsError` with the error code if the underlying transport returns an error on
    ///   `ssl_close_nofify`
    /// * Any errors from `flush_outgoing` are propagated
    pub async fn shutdown(&mut self) -> io::Result<()> {
        let ret = unsafe { ffi::mbedtls_ssl_close_notify(&raw mut self.ssl) };
        self.flush_outgoing().await?;
        if ret == 0 || MbedtlsError::from_raw(ret).is_peer_close_notify() {
            Ok(())
        } else {
            Err(MbedtlsError::from_raw(ret).into())
        }
    }

    /// Check if the `bio` has any pending outgoing data.
    /// If yes try to write the data.
    ///
    /// # Errors
    /// `io::Error` in case the `inner.poll_write` returned an error.
    fn check_write_flush<T>(&mut self, cx: &mut Context<'_>) -> Option<Poll<io::Result<T>>> {
        let bio = self.bio_mut();
        if !bio.has_outgoing() {
            return None;
        }

        let data = self.bio_mut().take_outgoing();
        let mut offset = 0;
        while offset < data.len() {
            let inner = Pin::new(&mut self.inner);
            #[allow(clippy::indexing_slicing)] // checked by loop condition
            match inner.poll_write(cx, &data[offset..]) {
                Poll::Ready(Ok(n)) => offset = offset.saturating_add(n),
                Poll::Ready(Err(e)) => return Some(Poll::Ready(Err(e))),
                Poll::Pending => {
                    // in case of pending store the remainder back in the outgoing buffer for
                    // the next flush attempt.
                    #[allow(clippy::indexing_slicing)] // checked by loop condition
                    self.bio_mut().outgoing.extend_from_slice(&data[offset..]);
                    return Some(Poll::Pending);
                }
            }
        }
        None
    }
}

impl<S> AsyncRead for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First, try to read from any buffered incoming data.
        // Feed data from the async transport into the memory BIO.
        let mut network_buf = [0u8; ffi::MBEDTLS_SSL_IN_CONTENT_LEN as usize];
        loop {
            let inner = Pin::new(&mut self.inner);
            let mut read_buf = ReadBuf::new(&mut network_buf);
            match inner.poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        // EOF on transport.
                        break;
                    }
                    // fine as n is the length of the filled buffer part
                    #[allow(clippy::indexing_slicing)]
                    self.bio_mut().feed_incoming(&network_buf[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }

        // mbedtls decrypt.
        let out = buf.initialize_unfilled();
        let ret = unsafe { ffi::mbedtls_ssl_read(&raw mut self.ssl, out.as_mut_ptr(), out.len()) };

        // Flush any outgoing data produced (e.g. renegotiation, alerts).
        if let Some(poll) = self.check_write_flush::<()>(cx) {
            match poll {
                Poll::Pending => (), // pending will be handled in the next flush attempt
                Poll::Ready(r) => {
                    if let Err(e) = r {
                        return Poll::Ready(Err(e)); // propagate error
                    }
                }
            }
        }

        match ret {
            n if n > 0 => {
                #[allow(clippy::cast_sign_loss)] // fine, as we check if n > 0
                buf.advance(n as usize);
                Poll::Ready(Ok(()))
            }
            0 => Poll::Ready(Ok(())), // EOF
            n => {
                let err = MbedtlsError::from_raw(n);
                if err.is_want_read() {
                    Poll::Pending
                } else if err.is_peer_close_notify() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(err.into()))
                }
            }
        }
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let ret = unsafe { ffi::mbedtls_ssl_write(&raw mut self.ssl, buf.as_ptr(), buf.len()) };

        if let Some(poll) = self.check_write_flush(cx) {
            return poll;
        }

        match ret {
            #[allow(clippy::cast_sign_loss)] // this is fine, as we check if n > 0
            n if n > 0 => Poll::Ready(Ok(n as usize)),
            0 => Poll::Ready(Ok(0)),
            n => {
                let err = MbedtlsError::from_raw(n);
                if err.is_want_write() {
                    Poll::Pending
                } else {
                    Poll::Ready(Err(err.into()))
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(poll) = self.check_write_flush(cx) {
            return poll;
        }

        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let ret = unsafe { ffi::mbedtls_ssl_close_notify(&raw mut self.ssl) };

        // Flush the close_notify record.
        if let Some(poll) = self.check_write_flush(cx) {
            return poll;
        }

        if ret == 0 || ret == ffi::MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY as c_int {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        } else {
            let err = MbedtlsError::from_raw(ret);
            if err.is_want_write() || err.is_want_read() {
                Poll::Pending
            } else {
                Poll::Ready(Err(err.into()))
            }
        }
    }
}

impl<S> Drop for TlsStream<S> {
    fn drop(&mut self) {
        unsafe { ffi::mbedtls_ssl_free(&raw mut self.ssl) }
    }
}

impl<S: std::fmt::Debug> std::fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsStream")
            .field("handshake_completed", &self.handshake_completed)
            .finish_non_exhaustive()
    }
}
