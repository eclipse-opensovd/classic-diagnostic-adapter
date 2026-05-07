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

//! # rust-mbedtls
//!
//! Rust wrapper around bindings for **mbedtls 4.0.0**, with tokio `AsyncIo`support.
//!
//! # Examples
//! ## 1. `tokio::io` TLS Client
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use tokio::net::TcpStream;
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use mbedtls_rs::ssl::{SslConfigBuilder, SslVerifyMode};
//! use mbedtls_rs::async_stream::TlsStream;
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     // 1. Build a shared TLS config (reuse across connections)
//!     let config = SslConfigBuilder::new_client()
//!         .expect("config init failed")
//!         .verify_mode(SslVerifyMode::None) // see §4 for proper CA verification
//!         .build();
//!
//!     // 2. Connect TCP, then upgrade to TLS
//!     let tcp = TcpStream::connect("example.com:443").await?;
//!     let mut tls = TlsStream::connect(config, tcp, Some("example.com")).await?;
//!
//!     // 3. Read/write cleartext
//!     tls.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n").await?;
//!
//!     let mut response = Vec::new();
//!     tls.read_to_end(&mut response).await?;
//!     println!("{}", String::from_utf8_lossy(&response));
//!
//!     // 4. Graceful shutdown
//!     tls.shutdown().await?;
//!     Ok(())
//! }
//! ```
//!
//! ## 2. `std::io` TLS Client
//!
//! ```rust,no_run
//! use std::net::TcpStream;
//! use std::io::{Read, Write};
//! use std::sync::Arc;
//! use mbedtls_rs::ssl::{SslConfigBuilder, SslStream, SslVerifyMode};
//!
//! fn main() -> std::io::Result<()> {
//!     let config = SslConfigBuilder::new_client()
//!         .expect("config init failed")
//!         .verify_mode(SslVerifyMode::None)
//!         .build();
//!
//!     let tcp = TcpStream::connect("example.com:443")?;
//!     let mut tls = SslStream::connect(config, tcp, Some("example.com"))
//!         .map_err(|e| match e {
//!             mbedtls_rs::ssl::HandshakeError::Failure(e) => e,
//!             _ => std::io::Error::new(std::io::ErrorKind::Other, "handshake would block"),
//!         })?;
//!
//!     tls.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")?;
//!
//!     let mut response = Vec::new();
//!     tls.read_to_end(&mut response)?;
//!     println!("{}", String::from_utf8_lossy(&response));
//!
//!     let _ = tls.shutdown();
//!     Ok(())
//! }
//! ```
//!
//! ## 3. `tokio::io` TLS Server
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use tokio::net::TcpListener;
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use mbedtls_rs::ssl::{SslConfigBuilder, SslVerifyMode};
//! use mbedtls_rs::x509::{X509Certificate, PrivateKey};
//! use mbedtls_rs::async_stream::TlsStream;
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     // Load server certificate and private key
//!     let cert = X509Certificate::from_file("/path/to/server.crt")
//!         .expect("failed to load cert");
//!     let key = PrivateKey::from_file("/path/to/server.key", None)
//!         .expect("failed to load key");
//!
//!     // Build server config
//!     let config = SslConfigBuilder::new_server()
//!         .expect("config init failed")
//!         .own_cert(cert, key)
//!         .expect("failed to set own cert")
//!         .verify_mode(SslVerifyMode::None) // no client cert required
//!         .build();
//!
//!     let listener = TcpListener::bind("0.0.0.0:4433").await?;
//!
//!     loop {
//!         let (tcp, _addr) = listener.accept().await?;
//!         let config = config.clone(); // Arc::clone - cheap
//!
//!         tokio::spawn(async move {
//!             let mut tls = TlsStream::accept(config, tcp).await.unwrap();
//!
//!             let mut buf = vec![0u8; 4096];
//!             let n = tls.read(&mut buf).await.unwrap();
//!             println!("Received: {}", String::from_utf8_lossy(&buf[..n]));
//!
//!             tls.write_all(b"HTTP/1.0 200 OK\r\n\r\nHello from mbedtls!\n").await.unwrap();
//!             let _ = tls.shutdown().await;
//!         });
//!     }
//! }
//! ```
//!

pub use mbedtls_sys as ffi;
pub mod ed25519;
pub mod error;
pub mod ssl;
pub mod x509;

#[cfg(feature = "tokio")]
pub mod async_stream;
