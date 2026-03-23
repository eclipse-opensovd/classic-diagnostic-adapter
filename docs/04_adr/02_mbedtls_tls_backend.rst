.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

ADR-002: mbedTLS as Alternative TLS Backend for DoIP
====================================================

Status
------

**Experimental**

Date: 2026-03-23

Context
-------

The Classic Diagnostic Adapter (CDA) uses TLS-secured DoIP (Diagnostics over IP) connections to communicate with ECUs. The default TLS backend is OpenSSL via the ``openssl`` and ``tokio-openssl`` Rust crates.

OpenSSL does not implement the ``record_size_limit`` TLS extension (RFC 8449). Some ECUs require this extension and close the connection when the peer sends records exceeding the limit they were trying to negotiate.
Since OpenSSL neither advertises nor honours the extension, a stable connection with such ECUs cannot be guaranteed. See `openssl/openssl#27916 <https://github.com/openssl/openssl/pull/27916>`_ and `auroralabs-loci/openssl#342 <https://github.com/auroralabs-loci/openssl/pull/342>`_ for the upstream status.

mbedTLS 4.0.0 supports ``record_size_limit``, but only for TLS 1.3. Since DoIP connections commonly use TLS 1.2, a patch is needed to extend this support.
Additionally, mbedTLS 4.0.0 has no Ed25519 (PureEdDSA) signature support, which is required by some ECUs. A additional patch adds this capability via a custom PSA accelerator driver.

Upstreaming the changes for Ed25519 at the current time is not feasible as the patch in this repository only covers the necessary parts required for ECU communication and would most likely need to be extended to be acceptable for upstream inclusion.
The mbedTLS maintainers have planned Ed25519 support in their roadmap, but with no concrete date for now. Once the upstream supports it natively the patch can simply be dropped.

Decision
--------

Add **mbedTLS 4.0.0** as an optional, feature-gated TLS backend in the ``comm-mbedtls`` module. The module is structured as two Rust crates:

- **mbedtls-sys** -- downloads, patches, and compiles mbedTLS from source; generates FFI bindings via ``bindgen``.
- **mbedtls-rs** -- safe Rust wrapper exposing synchronous and asynchronous (Tokio) TLS streams, X.509 certificate handling, and TLS configuration via a builder API.

Two patches are applied to upstream mbedTLS 4.0.0 at build time (see ``comm-mbedtls/mbedtls-sys/patches/README.md`` for details):

- **record-size-limit-tls12.patch** -- extends the existing TLS 1.3 ``record_size_limit`` implementation to TLS 1.2 (RFC 8449).
- **ed25519-psa-driver.patch** -- adds Ed25519 support to mbedTLS across the PSA crypto, PK, X.509, and TLS 1.2 layers, which upstream mbedTLS 4.0.0 does not provide. The actual Ed25519 cryptographic operations are performed in Rust (``ed25519-dalek``) and called from C via a PSA accelerator driver FFI bridge.

Backend Selection
^^^^^^^^^^^^^^^^^

The TLS backend is selected at **compile time** via Cargo feature flags:

.. list-table::
   :header-rows: 1
   :widths: 15 15 60

   * - Feature
     - Default
     - Effect
   * - ``openssl``
     - yes
     - Use OpenSSL
   * - ``mbedtls``
     - no
     - Use mbedTLS (experimental)

If both features are enabled, OpenSSL takes precedence. The selection is enforced through ``#[cfg]`` guards in ``cda-comm-doip``; there is no runtime dispatch or shared TLS provider trait. Both backends produce streams implementing Tokio's ``AsyncRead + AsyncWrite``, which is sufficient for the generic ``DoIPConnection<T>`` transport layer.

Consequences
------------

Positive
^^^^^^^^

- ECUs requiring ``record_size_limit`` extension can be supported without any potentially unstable workarounds (such as limiting the max transfer size to a size smaller than reported by the extension).
- mbedTLS is statically linked with no system-level dependency, simplifying cross-compilation and embedded deployment.
- The module is self-contained and designed to be extractable into its own repository once deemed stable.

Risks and Tradeoffs
^^^^^^^^^^^^^^^^^^^

- **Experimental status.** The mbedTLS backend has not undergone a dedicated security review.
- **Custom patches.** Two patches against upstream mbedTLS must be maintained. Future mbedTLS releases may incorporate these features natively, at which point the patches can be dropped.
- **Build complexity.** The ``mbedtls-sys`` build script downloads a source tarball at build time (unless ``MBEDTLS_DIR`` is set), applies patches, and invokes CMake. Offline builds require pre-fetching the source.
- **Additional licenses.** For building mbedtls-sys from source, ureq and bzip2 are added as build dependencies. Those bring in additional licenses which were explictly allowed for those crates. This can lead to additional maintanance effort when updating dependencies.

Future Direction
^^^^^^^^^^^^^^^^

- Promote to production-ready after potentially a security review and broader ECU testing.
- Extract ``comm-mbedtls`` into a standalone crate/repository.
- Unify TLS configuration so cipher suites, curves, and signature algorithms are driven by the CDA config file rather than compile-time constants.
- Drop patches if/when upstream mbedTLS gains native Ed25519 and TLS 1.2 ``record_size_limit`` support, or when OpenSSL adds ``record_size_limit``.

References
----------

- `RFC 8449 -- Record Size Limit Extension for TLS <https://www.rfc-editor.org/rfc/rfc8449>`_
- `RFC 8032 -- Edwards-Curve Digital Signature Algorithm (EdDSA) <https://www.rfc-editor.org/rfc/rfc8032>`_
- `mbedTLS record_size_limit PR (TLS 1.3) <https://github.com/Mbed-TLS/mbedtls/pull/7455>`_
- `OpenSSL record_size_limit PR <https://github.com/openssl/openssl/pull/27916>`_
- `PR #242 -- TLS: add mbedtls option <https://github.com/eclipse-opensovd/classic-diagnostic-adapter/pull/242>`_
- ``comm-mbedtls/mbedtls-sys/patches/README.md`` -- detailed patch documentation
