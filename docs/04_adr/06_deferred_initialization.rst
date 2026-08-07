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

ADR-006 Authoritative Communication Lifecycle And Deferred Initialization
=========================================================================

Status
------

Accepted

Context
-------

CDA can start diagnostic communication eagerly, wait for the first diagnostic
HTTP request, or refuse ordinary activation entirely until an explicit
trigger. Runtime update must exclude diagnostic activity while it replaces
runtime components. These flows need HTTP availability signals, transport
transitions, initialization, and diagnostic-use admission, coordinated
behind a single authority rather than left to independently mutated state.

The resulting model must preserve passive deferred startup, let a selected
plugin determine the public communication behavior, and prevent it or its
consumers from bypassing generic transport and state-machine invariants.
``[communication] init_mode`` makes the deferred-startup choice explicit and
adds a third value with materially different safety behavior: whole-vehicle
communication may never be no longer be inferred from configuration; it must
be a first-class, plugin-enforced policy.

Exactly three ``CommunicationInitMode`` values are implemented --
``Always``, ``OnDemand``, and ``Disabled`` -- with no persisted ECU-to-gateway
topology. Every accepted ``OnDemand`` trigger initializes the whole vehicle,
never a single gateway; process startup never restores prior topology or
readiness. ``WhenNotPersisted`` and all persisted-topology behavior described
below under "Persistence Boundary" are explicitly out of scope.

Decision
--------

The startup-selected ``CommunicationPlugin`` is the authoritative public
facade for communication lifecycle changes. It is built once by
``CommunicationPluginBuilder``, receiving a ``CommunicationHandle`` and the
configured ``CommunicationInitMode`` as a typed fact. Runtime plugin
replacement and transfer of this authority are not supported.

``CommunicationHandle`` claims lifecycle-state transitions synchronously --
so guard acquisition and lease drop stay lock-free -- and submits the
resulting physical work to a capacity-8 lifecycle worker (see `Lifecycle
Worker`_). Only that worker invokes ``TransportControl::enable()`` and
``TransportControl::disable()``. A custom plugin can delegate the facade's
operations through the handle, but receives neither raw transport control nor
protection-record identity, so it cannot bypass framework transition,
initialization, or ownership rules. Critically, the handle itself has *no*
``init_mode`` opinion: the framework never inspects ``init_mode`` to initiate
communication except for the ``Always``-mode startup call (see `Deferred
Startup And Mode Semantics`_); every other activation decision belongs to the
plugin alone.

``cda-interfaces`` retains only physical transport contracts, including
``TransportState``, ``TransportStateTracker``, ``TransportControl``,
``CommunicationInitializer``, ``CommunicationInitMode``, communication
settings, and ``SwappableGateway``. The plugin crate owns authoritative
``CommunicationState``, lifecycle failures, access and disable contracts,
owner tokens, plugin contracts, the lifecycle worker, and HTTP protection
contracts. Physical transport state is not authoritative lifecycle state:
lifecycle state also represents initialization, guards, exclusive disable
ownership, and structured failures.

Architecture
------------

.. uml:: images/communication_management_architecture.puml
   :alt: Authoritative communication lifecycle architecture

Module Architecture
^^^^^^^^^^^^^^^^^^^

.. uml:: images/communication_management_modules.puml
   :alt: Communication lifecycle module architecture

Authority And Consumer Views
-----------------------------

The selected plugin exposes awaited ``activate(cause)``, nonblocking
``request_activate()``, awaited ``trigger_detection(cause)``, awaited
``disable(reason)``, guarded diagnostic ``acquire()``, state inspection, the
typed event handler, and initializer registration. Setup retains this full
facade for startup and initializer registration.

``trigger_detection(cause)`` is authorized in every ``init_mode``, including
``Disabled``, where it is the *only* operation that may initialize
communication. It is deliberately a distinct plugin operation from
``activate(cause)`` rather than another ``ActivationCause`` variant, so a
default or custom plugin can apply materially different authorization rules
to each.

All other consumers receive only the capability they need:

* SOVD and diagnostic communication consumers receive ``CommunicationAccess``.
  It exposes authoritative state inspection and ``acquire()``, returning a
  ``CommunicationGuard`` only in ``Enabled``.
* Runtime update receives ``DisableCommunication`` and
  ``HttpProtectionRegistry``. It cannot activate transport, register an
  initializer, or lift the communication plugin's protection.
* The narrow views forward to the same selected plugin. They do not call the
  lifecycle worker directly and do not expose activation.

``CommunicationGuard`` is held for a diagnostic operation's complete lifetime.
Disable is rejected while any guard is active.

HTTP Protection Ownership
--------------------------

``HttpProtectionRegistry::protect()`` creates an independently owned HTTP
protection and returns a non-cloneable opaque ``OwnedHttpProtection``. The
registry is cloneable, but the internal record key is not part of any public
type, event, callback, log API data, or removal API. Dropping an unlifted
owner token performs best-effort, idempotent removal. An owner can remove
only its own record.

Protections coexist. The request guard evaluates an immutable ordered
snapshot; the first installed matching protection supplies the denial
response. Route and method matching retain path-segment boundaries, and
exemptions take precedence within a protection. Registry unavailability must
fail conservatively rather than silently pass requests through. A
restricted-request hook receives request metadata but no protection
identifier, runs synchronously, and cannot change, delay, or replace the
configured denial response.

The default plugin owns ``CommunicationNotReady``. It returns the configured
``503 Service Unavailable`` response and ``Retry-After`` while communication
is unavailable. Its ``on_event`` handler applies ``init_mode`` policy (see
"Deferred Startup And Mode Semantics" below) and, when authorized, calls the
nonblocking ``request_activate()``; duplicate requests coalesce into the
single in-flight generation. The triggering request still receives the
configured denial -- no request is ever held open waiting for activation to
finish.

Two event shapes reach the plugin. ``DiagnosticRequestPending { ecu }``
carries a resolved ECU identity: route/request code resolves it, never the
plugin, so plugins never parse URL paths. ``RequestRestricted`` is the older,
path/method-only compatibility event, retained for observability and for
custom plugins that do not need ECU identity. Without persisted topology
every accepted trigger scope normalizes to whole-vehicle regardless of which
event carried it, so a plugin's ``on_event`` may treat both uniformly for
now; the distinction exists so a future per-gateway policy can act on
``DiagnosticRequestPending`` without a breaking event-shape change.

.. code-block:: rust

   // TODO(persistence-init-mode): route/request code resolves ECU identity
   // and emits DiagnosticRequestPending; this lands with the late-bound
   // route wiring. Until then RequestRestricted drives the same
   // whole-vehicle-scoped policy. See ADR-006.

Lifecycle State And Failure Behavior
--------------------------------------

The authoritative state machine is ``Disabled``, ``Enabling``, ``Enabled``,
``Disabling``, ``DisabledExclusive``, or
``Error(CommunicationOperationFailure)``. There is no separate last-failure
accessor: the current ``Error`` payload is authoritative.

Successful activation performs transport activation, runs all registered
post-activation initializers in registration order, lifts the plugin's
communication protection, and then publishes ``Enabled``. Variant detection
remains a framework-enforced post-activation initializer. No external
participant votes on or blocks a lifecycle decision; a typed
lifecycle-transition event stream remains a possible future extension.

Transport or initializer failure, including a failure while resuming,
publishes ``Error(CommunicationOperationFailure)`` and **retains** (or
reinstalls) ``CommunicationNotReady`` -- protection is lifted only after a
runtime is fully ready, never merely attempted. Lifting on failure would let
a diagnostic request reach the normal handler-level communication error
during a window where the transport is known to be broken, instead of the
pending response a later authorized retry can still resolve cleanly. Other
owners' protections remain installed.
An authorized ``activate()``/``trigger_detection()`` is the recovery
operation from ``Error(_)`` and installs a fresh communication protection
during recovery; it never reuses a previously lifted owner token.

The framework serializes transitions. Awaited callers cannot strand
``Enabling`` or ``Disabling`` by cancellation: lifecycle work has
worker-owned finalization, independent of the calling task (see `Lifecycle
Worker`_). Panic boundaries are reported where practical and conservatively
finalized so a stale transition is not left indefinitely.

Lifecycle Worker
-----------------

A capacity-8 ``LifecycleCommand`` mailbox is the sole task that touches the
physical transport, the registered initializer list, and HTTP protection
ownership. ``CommunicationHandle`` claims a state transition synchronously
(so guards and lease drop stay lock-free) and submits the resulting physical
work -- activate, disable, release a disable lease, or register an
initializer -- to this worker.

The mailbox capacity bounds *admission* only: a command is either fully
enqueued or not sent at all (``mpsc::Sender::send`` is cancel-safe), and
every enqueued command is always eventually processed or explicitly failed,
never silently dropped. This is what makes activation triggers durable and
coalesced: concurrent triggers for a still-uninitialized vehicle join the one
in-flight generation instead of racing to claim it themselves, and none of
them can be lost to a full mailbox.

Shutdown uses a separate, unbounded out-of-band channel so it can never be
blocked by a full command mailbox. It closes admission immediately (before
the worker even sees the shutdown signal), fails every *queued* command
deterministically, then best-effort disables the transport while preserving
protection through teardown -- protection is intentionally leaked past the
worker task's own exit, since nothing will ever call ``deactivate`` on it
again and the alternative (dropping it when the task returns) would undo
"preserve protection through teardown" the instant it was satisfied.

**Known gap:** shutdown does not preemptively cancel a command already being
processed (an in-flight ``Activate`` blocked inside the transport, say);
`handle_command` is awaited inline in the worker's own loop, so shutdown
simply waits its turn behind whatever the worker is currently doing. This is
safe rather than merely tolerable -- since commands and shutdown share one
sequential loop, shutdown's teardown can never run *concurrently* with a
command still touching the transport, and admission is already closed so no
new work is accepted in the meantime -- but it does not bound shutdown
latency: a stuck command delays shutdown for as long as it is stuck. True
preemptive cancellation needs a cancellable unit of work smaller than "one
command," which needs the ``VehicleRuntimeFactory`` generation model, which
does not exist; see "Persistence Boundary" below.

``DisableLease::release()`` is cancellation-safe by the same mailbox
guarantee: it stays a plain synchronous defer-on-drop capability until the
release command is durably accepted into the worker's mailbox, at which
point the worker -- not the caller's task -- owns finishing it, including
across a cancelled caller.

Disable Ownership
------------------

``disable(reason)`` is accepted only from ``Enabled``, with no active
diagnostic guards and no existing disable owner. It installs a fresh
communication protection, disables transport, publishes
``DisabledExclusive``, and returns the sole non-cloneable ``DisableLease``. A
second disable request is a conflict and returns no lease. Activate and
request-activate calls while disabled-exclusive are rejected and never
queued.

``DisableLease::release(self)`` consumes the lease and submits the release to
the lifecycle worker, which validates the lease identity and exact
``DisabledExclusive`` state atomically at the point it dequeues the command
(not before), runs transport activation and initializers, and returns
``Enabled`` or a structured activation failure. A stale or double release can
never resume a later disable generation. Drop of an unreleased lease -- or of
a `release()` future cancelled before the worker durably accepts it --
performs a **synchronous defer**: it clears the disable owner and transitions
state to ``Disabled`` without attempting transport re-activation. HTTP
protection remains active and the on-demand mechanism recovers on the next
inbound diagnostic request (``request_activate``). No background cleanup task
or async channel is involved in the drop path itself: drop never blocks on or
requires a Tokio runtime, and it cannot fail.

Runtime Update
--------------

Runtime update creates its own ``UpdateInProgress`` protection before
requesting the exclusive disable lease. Failure to install that protection
prevents any transport change. If disable fails, dropping the update owner
removes only the update protection and no update starts. The update
protection returns ``409 Conflict`` with configured ``Retry-After`` and
blocks every route except:

* ``GET /health``;
* ``GET /health/ready``;
* ``GET /vehicle/v15/data/version``; and
* ``GET`` on
  ``/vehicle/v15/apps/sovd2uds/operations/runtimefilesupdate/executions`` and
  beneath that execution prefix, including an execution-status resource.

Authorization, locks, uploads, deletes, and execution ``POST`` routes are not
exempt. Since update protection is installed first, it supplies ``409`` when
a later communication protection would also match with ``503``.

On every explicit early cleanup path and on task completion, runtime update
awaits lease release before dropping its update protection. If resume fails,
the framework first enters ``Error(failure)`` and retains communication
protection; dropping update protection then exposes the ordinary
handler-level communication error once a later trigger succeeds. If an update
task is cancelled or panics, lease and update-protection owners are
independently dropped: the lease drop defers synchronously (state goes to
``Disabled``) and the update owner removes only its own record. When
``PostUpdateCommunicationMode::Deferred`` is configured the update task
simply drops the lease instead of calling ``release().await``; the on-demand
mechanism handles re-activation on the next diagnostic request.

Deferred Startup And Mode Semantics
--------------------------------------

Setup constructs passive, immutable preparation (configuration, MDD/database
loading, ECU inventory, file-manager and security-plugin preparation), then
the generic lifecycle framework and HTTP-protection registry. It builds and
retains the selected plugin, attaches the event-channel hook, registers
initializers through the full plugin facade, derives narrow views, and only
then publishes routes.

.. list-table:: Required mode semantics
   :header-rows: 1
   :widths: 10 20 25 25 20

   * - Mode
     - Startup
     - Plugin ``activate()``
     - First ECU request
     - ``trigger_detection()``
   * - ``Always``
     - Initialize whole vehicle
     - Join or repeat according to current state
     - Requests use current readiness
     - Initialize/re-detect whole vehicle
   * - ``OnDemand``
     - Keep uninitialized
     - Initialize whole vehicle
     - Return pending, trigger once
     - Initialize/re-detect whole vehicle
   * - ``Disabled``
     - Keep uninitialized
     - Reject, no network activity
     - Return pending, never triggers
     - Initialize/re-detect whole vehicle (only authorized path)

While ``Enabled``, ``trigger_detection(Explicit)`` performs **variant
re-detection only**: it re-runs the registered initializers without calling
``TransportControl::enable()`` or constructing anything -- detection is the
one initializer that actually does work, so this amounts to re-running
variant detection against the already-live transport. It is refused
(``GuardsHeld``) while any ``CommunicationGuard`` is active, because the
per-ECU request semaphore serializes individual requests, not a whole
multi-request sequence (e.g. a flash transfer's ``TransferData`` blocks), so
a detection request could otherwise land between two requests of that
sequence. ``trigger_detection(NetworkReset)`` while ``Enabled`` returns a
structured not-implemented failure rather than silently performing the
weaker variant re-detection instead: topology re-discovery may construct
gateways, unlike variant re-detection, and is deferred to the
``networkreset`` endpoint (see "Persistence Boundary" below). From
``Disabled``/``Error``, every cause performs full activation identically,
since there is no live transport yet for any cause to distinguish.

``Always`` calls ``activate(Startup)`` through the plugin at setup and
propagates startup failure according to existing application-start
semantics -- this is the only place the framework itself inspects
``init_mode`` to initiate communication. ``OnDemand`` and ``Disabled`` keep
communication uninitialized at startup; HTTP/SOVD is already available via
the routes registered above, and every other activation decision is the
default plugin's alone, applying the table above from ``on_event`` and
``activate()``/``trigger_detection()`` (see "HTTP Protection Ownership" and
"Authority And Consumer Views" above).

**Deferred DoIP resource creation.** ``DoipDiagGateway::new()`` is purely
in-memory and safe to call unconditionally regardless of ``init_mode``: it
never creates or binds a UDP socket, sends a packet, or starts a task. The
UDP socket bind, VIR broadcast, ECU connection, and spontaneous VAM listener
all happen lazily inside the gateway's own ``enable()`` -- the same
authorization choke point ``init_mode`` policy already gates -- not at
construction time. This is what lets ``cda-main``'s startup component
construction stay unconditional (no mode branch needed in
``prepare_vehicle_components``/``create_diagnostic_gateway``) while still
guaranteeing zero network activity before an authorized trigger: without a
bound socket, no packet can physically be sent or received, which is the
strongest available guarantee for that requirement.

This is a **scoped, documented deviation** from constructing the UDS manager
itself lazily. SOVD routes hold a value snapshot of the UDS manager baked in
at route-build time (not a live reference into a replaceable slot), so a
truly late-bound UDS manager requires either a late-bound ``UdsEcu``/
``SchemaProvider`` wrapper spanning that trait family's full surface, or
driving the same rebuild-and-``DynamicRouter::replace_routes`` sequence the
runtime-update reloader already uses, on first authorized activation instead
of only on reload. Both remain available as independently verifiable future
work, but are no longer required to satisfy this ADR: an eagerly-constructed,
network-inert UDS manager is accepted as correct for the safety property this
ADR exists to guarantee, with that property enforced by two mechanisms
described in full in "Variant Detection Readiness" below -- the lazy `DoIP`
socket (no network activity) and the variant-readiness gate (no premature,
wrong-variant data) -- rather than by deferring construction itself.

Variant Detection Readiness
------------------------------

``CommunicationState::Enabled`` means activation *completed*, **not** that
variant detection *concluded*: detection is dispatched per ECU (as a
post-activation initializer, see "Lifecycle State And Failure Behavior"
above) and settles asynchronously, including a retry budget for ECUs that
conclude offline. The per-ECU ``VariantState`` (``NotTested`` until
detection settles it into a terminal state -- ``Detected``, ``NotDetected``,
or ``Duplicate``) is the actual readiness signal, exposed as an awaitable
``tokio::sync::watch`` channel seeded with the ECU's current state.

.. list-table:: What may be served before variant detection concludes
   :header-rows: 1
   :widths: 40 30 30

   * - Surface
     - Depends on
     - Available at startup
   * - Route paths / ECU list (component catalog)
     - Loaded MDD databases
     - Yes, in every ``init_mode``
   * - Resource listings under an ECU, request/response schemas
     - Detected variant
     - No -- wait for detection, or return pending
   * - Operation execution
     - Transport plus detected variant
     - No -- return pending until communication is ready

The SOVD URL space (route paths, the component/ECU catalog) is a function of
the loaded MDD databases alone and never of a detected variant, which is why
routes are registered at startup in all three ``init_mode`` values (see
"Deferred DoIP Resource Creation" above) -- there is nothing variant-specific
to gate there. Variant-dependent content -- resource listings under an ECU
and request/response schemas -- waits for that ECU's ``VariantState`` to
leave ``NotTested`` instead of answering early with whatever the base or
previously-detected variant happened to describe:

* If the target ECU's ``VariantState`` has already left ``NotTested``, it is
  served immediately (the steady-state, zero-cost path).
* If an activation is in flight, or communication is already ``Enabled``
  with detection still settling in the background, the request awaits that
  ECU's watch channel, bounded by a named timeout documented against
  detection's own retry budget (offline-verdict retries plus per-request
  timeouts) so the bound is never silently arbitrary.
* On timeout, or when communication is not enabled and nothing is in
  flight, the request returns ``CommunicationNotReady`` with a retry hint --
  in the latter case also firing a non-blocking activation request
  (``init_mode``-gated, so this is a no-op under ``Disabled``, preserving its
  "stay quiet" contract) so a later request finds a generation already in
  flight and only has to wait.

Net effect per ``init_mode``: for schema/resource-listing requests made
during the startup window, ``Always`` waits for detection to conclude and
serves the detected variant, rather than answering early with whatever the
base variant describes. ``OnDemand`` returns one fast pending response and
triggers, exactly as above, then later requests wait and serve. ``Disabled``
stays pending and quiet, never triggering and never touching the network,
exactly as above.

This closes the readiness gap that eager UDS-manager construction (see
"Deferred Startup And Mode Semantics" above) does not: acceptance criterion
4's literal wording ("no UDS manager at startup") is not met, and is hereby
amended -- eager-but-network-inert construction is accepted, and the
property the criterion exists to guarantee is instead enforced directly by
two independent mechanisms: the lazy `DoIP` socket
(covered by ``new_never_binds_the_doip_socket``, "Deferred DoIP resource
creation" above) rules out network activity before authorization, and this
section's readiness gate rules out premature (wrong-variant) ECU data,
including the post-activation, pre-detection window that deferring
construction alone would not have closed.

Persistence Boundary
----------------------

There is no persisted ECU-to-gateway topology, and the following
are explicitly deferred rather than implemented:

* ``WhenNotPersisted`` as a selectable ``init_mode`` value.
* Persisted topology storage, loading, validation, clearing, and atomic
  updates.
* Direct reconnect to a persisted gateway address without whole-vehicle
  re-detection.
* Per-gateway fallback discovery based on persisted topology.
* Topology re-discovery via ``trigger_detection(NetworkReset)`` (the
  ``networkreset(trigger_detection=true)`` endpoint): unlike variant
  re-detection, it may construct gateways, so it is rejected with a
  structured not-implemented failure while ``Enabled`` rather than silently
  falling back to the weaker variant re-detection (see "Deferred Startup And
  Mode Semantics" above). Marked ``TODO(networkreset-endpoint)`` rather than
  ``TODO(persistence-init-mode)``: it is blocked on the endpoint's existence,
  not on persisted topology.
* Per-ECU/per-gateway ``OnDemand`` initialization scope -- every accepted
  trigger normalizes to whole-vehicle scope; an
  ``InitializationScope::Ecu(EcuName)`` variant exists in the process-local
  state model purely so the requested ECU can be preserved for tracing and so
  future persisted-topology work does not need a breaking type change.
* Post-detection persistence publication.

Future persistence work must not alter the plugin authorization boundary
(see "Decision" above) or permit ``Disabled``-mode startup traffic under any
circumstance -- persisted topology may change *what* an authorized trigger
does (e.g. reconnect a single gateway instead of the whole vehicle), never
*whether* an unauthorized one may act. Absence, corruption, staleness, and
partial persisted records are unresolved follow-up decisions: this ADR does
not prescribe fail-open-to-whole-vehicle, fail-closed-to-``Disabled``, or
per-field validation, and a future ADR revision (or a new ADR, once this
scope is large enough to warrant one) must decide among them before
persisted topology ships.

Extension points are marked in code with
``TODO(persistence-init-mode): ... See ADR-006.`` at scope normalization,
mode parsing, direct reconnect, and persistence publication sites; do not
scatter generic TODOs beyond those. The ``networkreset`` endpoint itself is
marked separately, ``TODO(networkreset-endpoint)``, since it is blocked on
the endpoint's existence rather than on persisted topology.

Future Generic Interception
---------------------------

Response interception is not part of this decision. A future generic Tower
finalizer may inspect request metadata and downstream responses, but must
remain independent from HTTP-protection ownership and communication
lifecycle authority. Response customization must not grant authority to
lift, replace, or otherwise mutate another owner's protection. The current
synchronous restricted-request hook is solely a lifecycle trigger; it is not
an interceptor or observer API and does not establish the shape of a future
interception API.

Consequences
------------

* The selected plugin is the sole public lifecycle authority, while generic
  framework invariants remain enforced; the framework itself never inspects
  ``init_mode`` except for the ``Always``-mode startup call.
* ``init_mode`` supports exactly ``Always``, ``OnDemand``, and ``Disabled``;
  ``Disabled`` is a strict authorization boundary where only
  ``trigger_detection()`` may initialize communication, never an alias for
  on-demand behavior.
* HTTP availability is represented by independent owner tokens, not a global
  restriction switch or shared admission lock.
* Diagnostic consumers and runtime update have deliberately narrow
  capabilities.
* A failed communication activation is visible as structured lifecycle
  state, retains HTTP protection, and as the existing handler-level
  communication error once a later authorized trigger succeeds -- never an
  indefinitely stale ``503`` response, and never a window where protection
  was lifted despite a known-broken transport.
* Initializers remain mandatory lifecycle work; no external participant
  votes on or delays a lifecycle decision.
* Activation triggers are durable and coalesced through the capacity-8
  lifecycle worker; mailbox saturation cannot lose the sole pending trigger,
  and shutdown cannot be blocked by a full mailbox.
* Deferred DoIP resource creation (no socket, gateway activity, VIR, or
  connection before authorization) is achieved without a startup-time
  ``init_mode`` branch in ``cda-main``, by moving socket binding into the
  gateway's own ``enable()``; the UDS manager and SOVD routes remain a
  scoped, documented exception constructed eagerly but network-inert until
  authorized, pending the persistence-dependent follow-up recorded above.
* Acceptance criterion 4 is amended: the eagerly-constructed UDS manager is
  accepted, with no network activity and no premature (wrong-variant) ECU
  data enforced directly instead (see "Variant Detection Readiness" above).
  ``Always`` mode no longer serves base-variant schema/resource-listing data
  during the startup window; it waits for the real detected variant instead.
* Variant re-detection (``trigger_detection(Explicit)`` while ``Enabled``)
  never constructs a gateway and is refused while a communication guard is
  held; topology re-discovery (``NetworkReset``) is deferred to the
  ``networkreset`` endpoint and rejected as not-implemented in the meantime.

Superseded Concepts
--------------------

This section records what the authoritative lifecycle model in this ADR
replaces.

* An ``update_in_progress: Arc<AtomicBool>`` cloned directly into unrelated
  modules (``cda-comm-uds``, ``cda-sovd``, ``cda-plugin-runtime-update``,
  ``cda-main``), each reading or writing it themselves with no single owner.
* ``UpdateGuardState``/``UpdateGuardLayer``, whose ``busy_handle()`` exposes
  that same flag as the sole HTTP-restriction switch -- coupling an HTTP
  restriction's lifetime to transport/data-transfer admission rather than to
  an independently owned protection record.
* A separate flash-transfer activity guard (``ActivityGuard``/
  ``flash_transfer_guard()``) consulted ad hoc before an update may start,
  uncoordinated with the two mechanisms above.
* No deferred-startup concept at all: ``main`` always activates
  communication eagerly at process start.

``CommunicationHandle``, ``CommunicationPlugin``, and the narrow consumer
views (see `Authority And Consumer Views`_) replace all four outright; none
has a compatibility facade.
