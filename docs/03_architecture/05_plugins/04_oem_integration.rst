.. SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0
..
.. SPDX-License-Identifier: Apache-2.0

OEM Library Integration
-----------------------

.. arch:: OEM Library Integration Contract
    :id: arch~oem-library-integration
    :status: draft

    ``opensovd-cda`` (library name ``opensovd_cda_lib``) can be embedded by an OEM
    application that adds vendor-specific behaviour without forking the CDA. This
    section defines what that contract covers and what it deliberately does not.

    **Supported surface**

    Everything ``opensovd_cda_lib`` exposes is part of the contract:

    * ``AppArgs`` / ``Command`` - the CLI surface, so an OEM binary accepts the
      same flags as ``opensovd-cda`` without redeclaring them.
    * ``config`` - ``Configuration`` and ``load_config_with_fallback``, including
      the ``[oem]`` section reserved for vendor settings and passed through
      verbatim to extensions.
    * ``setup_tracing``, ``shutdown_signal``, ``cda_version`` - the remaining
      pieces of a ``main``.
    * ``Setup`` and its builder methods, handed to ``run_with_ext`` /
      ``run_with_ext_from_config``.
    * ``extensions`` - the capabilities an extension hook receives.
    * ``update`` and ``update_security`` - composing a runtime-update plugin from
      a custom storage backend, policy, or database format.
    * ``AppError``.

    Construction of the live vehicle - databases, transports, gateway, UDS
    manager - is **not** public. Those signatures name concrete transport types
    (``DoipDiagGateway``, ``CanDiagGateway``, ``DiagnosticTransportRouter``,
    ``UdsManager``) and change whenever the transport stack does, so an
    integration built on them broke on every such refactor. ``extensions``
    exposes the same capabilities as traits that survive those changes.

    **Worked examples**

    ``examples/`` holds one runnable binary per extension point, each customising
    exactly one thing and leaving the rest stock:

    .. list-table::
        :header-rows: 1

        * - Example
          - Extension point
        * - ``examples/oem-routes``
          - Custom SOVD routes: both service addressing modes, DTCs, and locks
        * - ``examples/oem-health``
          - Reporting a vendor service through CDA's ``/health``
        * - ``examples/oem-security``
          - ``SecurityPlugin`` / ``SecurityPluginLoader``
        * - ``examples/oem-communication``
          - ``CommunicationPlugin`` - when the vehicle network may be brought up
        * - ``examples/oem-storage``
          - ``Storage`` backend for runtime-update files
        * - ``examples/oem-update-policy``
          - ``RuntimeUpdateSecurityPlugin`` and ``RuntimeFileInspector``

    They are workspace members but not default members, so a plain ``cargo build``
    skips them; CI builds them explicitly. Their purpose is to fail the build when
    a change breaks one of the extension points above, before an external
    integration finds out.

    **Extension point: custom SOVD routes**

    Register routes through ``Setup::with_extension``. The hook runs *after*
    vehicle data is loaded and the standard vehicle routes are mounted, so handlers
    can issue diagnostic requests immediately:

    .. code-block:: rust

        use aide::axum::ApiRouter;
        use axum::routing::put;
        use opensovd_cda_lib::{AppError, Setup, extensions::ExtensionContext};

        async fn register(context: ExtensionContext) -> Result<(), AppError> {
            let diagnostics = context.diagnostics();
            let routes = ApiRouter::new().route("/thing", put(my_handler));
            context.routes().register_oem("/vehicle/v15/x-acme", routes).await?;
            Ok(())
        }

        let setup = Setup::<MySecurityData, MySecurityLoader>::new()
            .with_extension(register);

    OEM route namespaces must start with ``/vehicle/v15/x-``; anything else is
    rejected with ``ExtensionError::ReservedNamespace`` so vendor routes can never
    shadow standard SOVD paths.

    **Extension point: diagnostics**

    ``ExtensionContext::diagnostics()`` returns an ``Arc<dyn DiagnosticServices>``,
    whose ``uds()`` hands back ``Arc<dyn UdsEcu<Response = DiagnosticResponse>>`` --
    the same interface CDA's own SOVD handlers hold. A plugin therefore has the
    possibilities of an internal service: both service addressing modes
    (``send_by_sid`` by request prefix, ``send_by_sid_and_name`` by SID plus
    database short name), sessions, security access, tester present, flash
    transfer, DTCs, database queries, functional groups and variant state.

    It is deliberately expressed as ``dyn UdsEcu`` rather than a curated facade:
    what broke integrations was naming concrete transport types
    (``UdsManager<DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>>>, _>``),
    not using UDS traits. Hold the ``DiagnosticServices`` handle in handler state
    and call ``uds()`` per request - it re-reads the live component generation,
    so it follows a runtime database update; an ``Arc<Uds>`` cached at startup
    would keep answering from components that were shut down.

    **Extension point: locks**

    ``ExtensionContext::locks()`` returns an ``Arc<dyn LockAccess>`` with
    ``require_ecu_lock`` and ``require_functional_group_lock``. A route that
    changes state must use it, or it races the standard component routes, which
    enforce exactly these rules. Broadcasting to a functional group needs the
    functional-group lock; an ECU lock does not cover the other members. The
    caller's identity comes from the security plugin, so a replacement plugin
    governs who the lock is compared against.

    ``Setup::with_preload`` is the lower-level alternative. It runs *before* database
    load and receives the raw ``DynamicRouter``, so it can mount routes that must be
    reachable while the (potentially slow) load runs - but it has no diagnostic
    capability and hands out the router directly, so prefer ``with_extension``
    unless routes genuinely must be up before the databases are.

    **Security is not an extension point at the route layer**

    Handlers extract the per-request security plugin with ``Secured`` and pass that
    instance on. The security plugin is the authority for access decisions; a handler
    must not re-derive an access decision from claims it read itself, because a
    downstream plugin may apply additional checks that such a shortcut would skip.

    **Dependency requirements**

    The extension surface speaks in ``aide``, ``axum`` and ``schemars`` types, so an OEM crate
    declares those dependencies itself and must resolve them to the same versions CDA
    uses. The workspace pins ``aide`` to a fork via ``[patch.crates-io]``, since the
    OpenAPI generation CDA needs is not available upstream; an OEM workspace replicates
    that block so both dependency graphs agree. Resolving a second, unpatched ``aide``
    produces ``ApiRouter`` types that will not unify.

    All CDA workspace crates are ``publish = false``, so dependencies are git or path
    dependencies:

    .. code-block:: toml

        [dependencies]
        opensovd-cda = { git = "https://github.com/eclipse-opensovd/classic-diagnostic-adapter.git", rev = "..." }
        aide = { version = "0.16.0-alpha.1", features = ["axum"] }
        axum = { version = "0.8", default-features = false }

        [patch.crates-io]
        aide = { git = "https://github.com/alexmohr/aide.git", rev = "56355cb" }
        doip-codec = { git = "https://github.com/theswiftfox/doip-codec.git", rev = "0dba319" }
        doip-definitions = { git = "https://github.com/theswiftfox/doip-definitions.git", rev = "bdeab8c" }
        flatbuffers = { git = "https://github.com/alexmohr/flatbuffers.git", rev = "0ba3307d" }

    **Allocator**

    ``opensovd_cda_lib`` sets mimalloc as the ``#[global_allocator]`` for the whole
    process. This is intentional: the allocator is part of CDA's performance profile
    and applies to every process built on the library. An embedding application
    therefore does not define its own ``#[global_allocator]``.
