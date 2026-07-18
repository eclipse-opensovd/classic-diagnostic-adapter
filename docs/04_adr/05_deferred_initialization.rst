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

ADR-005: Deferred ECU Communication Initialization
====================================================

Status
------

**Accepted**

| Date: 2026-07-10

Context
-------

The Classic Diagnostic Adapter (CDA) starts DoIP gateway creation and ECU
discovery during startup, before the HTTP server is operational. This creates
friction for use cases where:

1. **Fast startup is required** - the diagnostic tester must be reachable (health
   endpoints, version info) before vehicle communication begins.
2. **Authorization-gated initialization** - ECU communication should only start
   after an explicit precondition is met (e.g., security unlock, session
   establishment, plugin-controlled activation).
3. **Plugin-driven control** - a custom plugin needs to decide *when* to initiate
   vehicle communication based on application-specific logic.
4. **Full communication silence** - in certain deployment scenarios, no network
   activity (including socket binding) may occur until explicitly requested.

A naive approach of deferring the entire DoIP/UDS stack construction introduces
unnecessary complexity: stub routes requiring hot-swap replacement, a monolithic
actor coupling DoIP lifecycle with route management and plugin callbacks, and
duplicated Tower middleware for structurally identical guards.

Decision
--------

Deferred initialization is implemented with proper separation of concerns:

- **MDD databases are always loaded at startup** - SOVD routes are registered
  with real handlers from the start. No stubs, no route replacement.
- **DoIP communication is fully silent** until triggered - the UDP socket is
  bound at startup to reserve the port, but no network traffic occurs (no VIR
  broadcasts, no TCP connections, no routing activation) until explicitly triggered.
- **A common ``RequestGuard`` trait** unifies the deferred init guard and the
  update guard behind a single generic Tower middleware.
- **A ``CommunicationControl`` trait** provides a cross-crate interface for
  managing the DoIP lifecycle.
- **A ``DoipCommActor``** in ``cda-comm-doip`` owns the DoIP state machine.
- **Guard implementations live in their respective plugin crates**, not in
  ``cda-sovd`` or ``cda-main``.

The mode is controlled by the ``CommunicationSettings`` struct (a top-level
section of the CDA configuration): ``init_mode``, ``post_update_mode``, and
``deferred_retry_after_seconds``. Defaults preserve existing behavior.

Architecture
^^^^^^^^^^^^

.. code-block:: text

   +-----------------------------------------------------------------+
   | cda-interfaces                                                   |
   |                                                                  |
   |  trait CommunicationControl: Send + Sync {                       |
   |      async fn enable() -> Result<(), CommControlError>;          |
   |      async fn disable() -> Result<(), CommControlError>;         |
   |      fn state() -> CommState;                                    |
   |      fn active(&self) -> Arc<AtomicBool>;                        |
   |  }                                                               |
   |                                                                  |
   |  enum CommState { Disabled, Initializing, Active, Failed }      |
   |                                                                  |
   |  trait InitializationPlugin (3 required methods)                  |
   |    on_ready(comm: Arc<dyn CommunicationControl>)                  |
   |    can_initialize(context: &InitializationContext) -> bool        |
   |    on_initialized(result: &InitResult)                            |
   +-----------------------------------------------------------------+
                              | implements
   +--------------------------v--------------------------------------+
   | cda-comm-doip                                                    |
   |                                                                  |
   |  DoipCommActor (kameo)                                           |
   |    State machine: Disabled -> Initializing -> Active | Failed     |
   |    On "Enable": bind sockets -> VIR -> TCP -> routing activation   |
   |                 -> variant detection -> Active                     |
   |    On "Disable": tear down connections -> Disabled               |
   |    Exposes Arc<AtomicBool> for fast-path reads                   |
   |                                                                  |
   |  DoipCommHandle (impl CommunicationControl)                      |
   +-----------------------------------------------------------------+
            ^                              ^
            | enable()                     | disable() / enable()
   +-----------------------+    +-----------------------------------+
   | cda-plugin-deferred-  |    | cda-plugin-runtime-update          |
   | init                  |    |                                     |
   |                       |    |  After update completes:            |
   |  DeferredInitGuard    |    |   Enabled  -> replace_gateway()    |
   |  (impl RequestGuard)  |    |   Deferred -> replace_gateway_     |
   |                       |    |              deferred()             |
   |  On trigger:          |    |   Last     -> restore pre-update   |
   |   plugin.can_init     |    |              state                  |
   |   -> comm.enable()     |    |                                     |
   |   -> on_initialized   |    |  Uses UpdateGuardState from        |
   |   -> 503 until Active  |    |  cda-interfaces (via spawn_update_ |
   +-----------------------+    |  guard()) - implements             |
                               |  RequestGuard for update-in-       |
                               |  progress 409 handling              |
                               +-------------------------------------+
            ^                              ^
            |                              |
   +---------------------------------------------------------------+
   | cda-sovd                                                       |
   |                                                                |
   |  trait RequestGuard: Send + Sync + Clone + 'static {           |
   |      fn is_active(&self) -> bool;                              |
   |      fn evaluate(path, method) -> BoxFuture<GuardDecision>;    |
   |  }                                                             |
   |                                                                |
   |  GuardLayer<G: RequestGuard>  (generic Tower Layer/Service)    |
   |  install_guard<G>(dynamic_router, guard)                       |
   |                                                                |
   |  GuardLayer<DeferredInitGuard>  - installed first (inner)      |
   |  GuardLayer<UpdateGuardState>   - installed second (outer)     |
   +----------------------------------------------------------------+

**Common request guard middleware** (``cda-sovd/src/sovd/request_guard.rs``)

A generic ``GuardLayer<G: RequestGuard>`` Tower middleware provides a unified
mechanism for both the deferred init guard and the update guard. The
``RequestGuard`` trait uses a two-tier design:

- ``is_active() -> bool`` - a cheap fast-path check (single atomic load). When
  the guard is not active, all requests pass through with zero overhead.
- ``evaluate(path, method) -> GuardDecision`` - async evaluation that decides
  whether to pass or deny (with configurable HTTP status, error code, and
  optional ``Retry-After`` header).

Both guards are installed as ``DynamicRouter`` finalizers, covering all routes
globally including OEM plugin routes added after startup.

**DoIP communication state machine** (``cda-comm-doip/src/comm_actor.rs``)

A ``kameo`` actor, ``DoipCommActor``, manages the DoIP communication lifecycle
as a state machine:

- ``Disabled`` - no network resources allocated, zero traffic on the wire.
- ``Initializing`` - performing bind -> VIR broadcast -> TCP connect -> routing
  activation -> variant detection.
- ``Active`` - fully operational, diagnostic messages can flow.
- ``Failed`` - initialization failed, may retry on next trigger.

The actor is accessed via a ``DoipCommHandle`` that implements the
``CommunicationControl`` trait defined in ``cda-interfaces``. This handle
exposes an ``Arc<AtomicBool>`` flag (true when Active) for use by the HTTP
guard's fast-path.

**Deferred init guard** (``cda-plugin-deferred-init/src/guard.rs``)

Implements ``RequestGuard``. On evaluation:

1. If the request path does not require DoIP communication -> ``Pass``.
2. Consult ``InitializationPlugin::can_initialize(context)`` - if denied -> ``Deny``.
3. Spawn an async task calling ``CommunicationControl::enable()`` (fire-and-forget).
4. After ``enable()`` completes, call ``InitializationPlugin::on_initialized(result)``
   with ``InitResult::Ok`` on success or ``InitResult::Failed(DeferredInitError::InitFailed(...))``
   on failure.
5. Return HTTP 503 with ``Retry-After`` header immediately.

Subsequent requests find the atomic flag flipped to ``true`` once
initialization succeeds, bypassing evaluation entirely.

**Update guard** (``cda-interfaces/src/guard.rs``)

``UpdateGuardState`` implements ``RequestGuard``. When an update is
in progress, all non-exempt routes receive HTTP 409 (Conflict). Exempt routes
(e.g., GET on the executions endpoint) pass through.

**Startup sequence (Deferred mode)**

1. Load MDD databases - parse ODX files, build ECU metadata.
2. Register real SOVD routes - all endpoints functional from startup.
3. Create ``DoipCommActor`` in ``Disabled`` state.
4. Create and install ``DeferredInitGuard`` via ``install_guard()``.
5. Create and install update guard.
6. Call ``InitializationPlugin::on_ready()`` - plugin may trigger immediately.
7. Server starts accepting HTTP requests.

**HTTP response for pending state**

Per SOVD ISO DIS 17978-3 Table 15, HTTP 503 is defined as "Method Unavailable
- the method is temporarily unavailable" and explicitly supports a
``Retry-After`` header (configurable, default 30 seconds). The error body uses
``error_code: precondition-not-fulfilled`` (SOVD Table 18).

**Post-update behavior**

The ``PostUpdateCommunicationMode`` enum governs DoIP behavior after a runtime
database reload. This is implemented in the reloader (``cda-plugin-runtime-update``):

- ``Enabled`` - reloader calls ``replace_gateway()`` which disables the old DoIP
  connection, installs the new gateway, and re-enables communication immediately.
- ``Deferred`` - reloader calls ``replace_gateway_deferred()`` which installs the
  new gateway in disabled state; the guard re-activates and ``on_ready()`` is called
  again so the plugin can re-arm its trigger.
- ``Last`` - reloader calls ``replace_gateway()`` if communication was active before
  the update, or ``replace_gateway_deferred()`` if it was deferred.

Rationale
---------

Unified Guard Middleware over Bespoke Implementations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Having two independent Tower middleware implementations for the deferred init
guard and the update guard would share ~80 lines of identical boilerplate. A
common ``RequestGuard`` trait with a generic ``GuardLayer<G>`` eliminates this
duplication while making it trivial to add future guards with the same pattern.

Communication State Machine over Deferred Construction
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Deferring the *entire* DoIP/UDS stack construction would require stub routes,
route replacement, and a complex actor in ``cda-main`` that owns rebuild inputs,
live components, route handles, and plugin callbacks. Instead, the chosen design:

- Loads MDD at startup (cheap, no network I/O) - eliminating stubs.
- Manages DoIP lifecycle as a proper state machine in the DoIP crate - each
  crate owns its own domain.
- Keeps the actor focused on clear state transitions rather than coupling
  unrelated concerns.

Guards in Plugin Crates over Central ``cda-sovd``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Moving guard implementations to their respective plugin crates
(``cda-plugin-deferred-init``, ``cda-plugin-runtime-update``) follows the
principle that policy logic lives with the code that understands it. The
generic middleware infrastructure remains in ``cda-sovd``.

``CommunicationControl`` Trait over Direct Actor Coupling
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Defining ``CommunicationControl`` in ``cda-interfaces`` allows both the
deferred init plugin and the runtime update plugin to control DoIP
communication without depending on ``cda-comm-doip`` directly. This enables
alternative implementations (e.g., for testing or alternative transports).

Path-Based Filtering
^^^^^^^^^^^^^^^^^^^^

Path prefix matching (``/vehicle/v15/components/``,
``/vehicle/v15/functions/functionalgroups/``) is explicit, auditable, and
independent of route registration order. The trailing slash distinguishes
individual ECU endpoints (requiring DoIP) from listing endpoints (which read
from in-memory MDD metadata only).

``OnDemandInitPlugin`` as Default
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When ``communication_init = Deferred`` and no custom plugin is provided, the
system defaults to ``OnDemandInitPlugin``, which triggers initialization on the
first diagnostic request by returning ``true`` from ``can_initialize`` for any
``InitializationContext``.

503 over 409 for Pending State
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

HTTP 503 (Service Unavailable) with ``Retry-After`` is the correct SOVD
semantic for temporarily unavailable methods. HTTP 409 (Conflict) is reserved
for the update guard where a request conflicts with an in-progress operation.

Consequences
------------

Positive
^^^^^^^^

- CDA starts and becomes HTTP-reachable (health, version, listing endpoints)
  before any DoIP communication occurs.
- **Communication silence** - UDP port reserved at startup (port lock, zero
  traffic), no broadcasts, connections, or routing activation until explicitly
  triggered.
- **No stub routes or route replacement** - real routes from startup, eliminating
  an entire class of complexity.
- Plugin developers control when ECU communication begins, both reactively
  (``can_initialize``) and proactively (via ``CommunicationControl``).
- The unified ``RequestGuard`` pattern makes adding future guards trivial.
- Each crate owns its domain: DoIP lifecycle in ``cda-comm-doip``, deferred
  policy in ``cda-plugin-deferred-init``, update logic in
  ``cda-plugin-runtime-update``, generic middleware in ``cda-sovd``.
- Post-update behavior is expressed via clear state transitions
  (``disable``/``enable``) rather than actor message choreography.
- The default (``Enabled``) preserves all existing behavior; no migration needed.

Negative
^^^^^^^^

- Clients making diagnostic requests in deferred mode receive 503 and must
  implement retry logic (mitigated by the ``Retry-After`` header).
- The first successful diagnostic request after on-demand trigger has higher
  latency (full DoIP initialization including variant detection).
- Cross-crate actor communication adds a level of indirection compared to a
  monolithic approach (mitigated by the atomic fast-path flag).
- ``kameo`` is now a dependency of ``cda-comm-doip`` and
  ``cda-plugin-runtime-update`` in addition to ``cda-main``.

Alternatives Considered
-----------------------

Monolithic Deferred Actor
^^^^^^^^^^^^^^^^^^^^^^^^^^

Deferring the entire DoIP/UDS stack construction in a single actor in
``cda-main`` that owns stub routes, performs route hot-swapping, and manages
rebuild inputs from multiple crates. Rejected because it couples too many
concerns, introduces unnecessary complexity (stub implementations, route
replacement), and places DoIP lifecycle logic outside the DoIP crate.

Always-Immediate Mode
^^^^^^^^^^^^^^^^^^^^^

Starting DoIP communication unconditionally at startup. Rejected because it
does not support authorization-gated, plugin-controlled, or
communication-silent use cases.

Lazy DoIP Connection per Request
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Creating a new DoIP gateway per request was considered. Rejected because DoIP
gateway creation involves network I/O and a single shared gateway with proper
lifecycle management is more efficient.

References
----------

- SOVD ISO DIS 17978-3 §5.8.2 Table 15 - HTTP 503 "Method Unavailable"
- SOVD ISO DIS 17978-3 §5.8.3 Table 16 - ``vendor_code`` conditional on ``vendor-specific``
- SOVD ISO DIS 17978-3 §5.8.4 Table 18 - ``precondition-not-fulfilled`` error code
- ``cda-sovd/src/sovd/request_guard.rs`` - ``RequestGuard`` trait, ``GuardLayer<G>``
- ``cda-interfaces/src/communication_control.rs`` - ``CommunicationControl``, ``CommState``
- ``cda-comm-doip/src/comm_actor.rs`` - ``DoipCommActor``, ``DoipCommHandle``
- ``cda-plugin-deferred-init/src/guard.rs`` - ``DeferredInitGuard``
- ``cda-interfaces/src/guard.rs`` - ``UpdateGuardState``, ``RequestGuard``, ``spawn_update_guard()``
- ``cda-interfaces/src/deferred_init_api/mod.rs`` - ``InitializationPlugin``
- ``cda-database/src/lib.rs`` - ``CommunicationSettings``, ``CommunicationInitMode``, ``PostUpdateCommunicationMode``
