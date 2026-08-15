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

.. note::

   This ADR records *decisions and their rationale*. Mechanics - exact
   signatures, state cells, channel shapes, failure payloads - live in the
   rustdoc of ``cda-plugin-communication-management`` and are not repeated
   here, so that they have exactly one place to drift from.

Context
-------

CDA can start diagnostic communication eagerly, wait for the first diagnostic
HTTP request, or refuse ordinary activation entirely until an explicit
trigger. Runtime update must exclude diagnostic activity while it replaces
runtime components. These flows need HTTP availability signals, transport
transitions, initialization, and diagnostic-use admission, coordinated behind
a single authority rather than left to independently mutated state.

The resulting model must preserve passive deferred startup, let a selected
plugin determine the public communication behavior, and prevent it or its
consumers from bypassing generic transport and state-machine invariants.
``[communication] init_mode`` makes the deferred-startup choice explicit and
adds a third value with materially different safety behavior: whole-vehicle
communication may no longer be inferred from configuration; it must be a
first-class, plugin-enforced policy.

Decision
--------

The startup-selected ``CommunicationPlugin`` is the authoritative public
facade for communication lifecycle changes. It is built once by
``CommunicationPluginBuilder``, receiving a ``CommunicationHandle`` and the
configured ``CommunicationInitMode`` as a typed fact. Runtime plugin
replacement and transfer of this authority are not supported.

``CommunicationHandle`` claims lifecycle-state transitions synchronously - so
guard acquisition and lease drop need no ``.await`` - and submits the
resulting physical work to a bounded lifecycle worker. Only that worker
invokes ``TransportControl::enable()``/``disable()``. A custom plugin can
delegate the facade's operations through the handle, but receives neither raw
transport control nor protection-record identity, so it cannot bypass
framework transition, initialization, or ownership rules.

Critically, the handle has *no* ``init_mode`` opinion. The framework never
inspects ``init_mode`` to initiate communication except for the
``Always``-mode startup call; every other activation decision belongs to the
plugin alone.

``cda-interfaces`` retains only the contracts a transport or hook
implementation must satisfy, plus the configuration types that select
behavior (``TransportControl``, ``CommunicationLifecycle``,
``CommunicationVariantDetection``, ``TransportState``,
``TransportStateTracker``, ``ComponentSlot``/``ReplaceComponent``, and the
``[communication]`` settings). The plugin crate owns authoritative ``CommunicationState``,
lifecycle failures, access and disable contracts, owner tokens, plugin
contracts, the lifecycle worker, and HTTP protection contracts. Physical
transport state is not authoritative lifecycle state: lifecycle state also
represents initialization, guards, exclusive disable ownership, and structured
failures.

Architecture
------------

.. uml:: images/communication_management_architecture.puml
   :alt: Authoritative communication lifecycle architecture

.. uml:: images/communication_management_modules.puml
   :alt: Communication lifecycle module architecture

Authority And Consumer Views
-----------------------------

The plugin facade exposes activation, detection, disable, guarded
``acquire()``, state and detection-policy inspection, and hook registration.
Setup retains it for startup and registration; every other consumer receives
only a narrow view:

* SOVD and diagnostic consumers get ``CommunicationAccess``: state
  inspection, ``acquire()``, and the nonblocking ``request_activate()``.
* Runtime update gets ``DisableCommunication`` plus ``HttpProtectionRegistry``
  for its own protection, and ``CommunicationAccess`` to request the
  configured post-update state.

Neither view can activate directly, register a hook or detector, run
``trigger_detection()``, or lift another owner's protection.

That narrowing **is** type-level, including for runtime update. The gateway
and UDS manager each live behind a ``ComponentSlot``, owned exclusively by
setup, which mints two disjoint views: ``read()`` for consumers that operate
the live component, and ``replacer()`` for installing a replacement (shutting
down the one displaced) with no read access at all.

Runtime update holds **neither**. Its ``UpdatePluginContext`` carries no slot
view of any kind, so it has no method reaching ``TransportControl::enable()``
or any ``UdsEcu`` operation. Replacement happens one level out: after an apply
the plugin calls ``RuntimeReloaderPlugin``, which builds a new generation via
``VehicleComponentFactory`` and installs it via ``VehicleComponentPublisher``;
only that publisher, owned by ``cda-main``, holds the ``replacer()`` views. See
``cda_interfaces::component_slot`` for the mechanism.

The guarantee covers the *live* gateway and UDS manager reachable through
these slots; a plugin constructing and driving its own transport or UDS client
outside them is not constrained by this boundary, same as any other
in-process type.

``ComponentSlot`` uses a reader-writer lock rather than a single mutex:
``read()`` (including ``enable()``/``disable()``/``state()`` on the internal
transport view) takes a read guard, and only ``replace()`` takes the write
guard, held just for the swap. A single mutex would have reintroduced the
barrier that the router's and each gateway's own operation lock exist to
avoid one layer down - status reads (``TransportStateTracker::state``) must
stay available while an ``enable()`` is in flight.

There is no event channel, ``on_event`` handler, or typed request-pending
event. A consumer that finds communication not ready calls
``request_activate()`` itself and immediately answers not-ready; no request is
ever held open waiting for activation. Duplicate requests coalesce into the
single in-flight generation.

Lifecycle State And Transitions
--------------------------------

The authoritative state machine is ``Disabled``, ``Enabling``, ``Enabled``,
``Disabling``, ``DisabledExclusive``, or ``Error(_)``. There is no separate
last-failure accessor: the current ``Error`` payload is authoritative.

``Enabling`` carries activation-shaped operations only - ``Enable``,
``EnableAndDetect``, ``Resume`` - and therefore always means a transport is
being brought up. Explicit re-detection is not among them and moves the state
machine nowhere; see ``redetect()`` below.

**Every (state, operation) cell is decided by one pure, exhaustively matched
function**, ``lifecycle::transition::decide``. All three claim sites consult
it and apply its verdict; none decides anything itself, and a new state or
operation cannot compile until every new cell has been decided explicitly.
The matrix only ever asks what the *state* permits - authority
(``init_mode`` policy, lease ownership) stays with the caller, as the
authority model above requires.

Underneath, the handle exposes two activation primitives, differing only in
which stages they run: ``enable()`` (transport + hooks) and ``activate()``
(transport + hooks + detection, subject to ``VariantDetectionMode``).

``redetect()`` is deliberately **not** a third one, and **not a transition**.
It runs the detection stage against a runtime that is already ``Enabled``,
touching neither the transport nor the hooks, so it is an operation that runs
*inside* a state rather than between two. The runtime stays ``Enabled`` for its
whole duration and the sweep is tracked by its own in-flight slot rather than by
``Enabling``.

Two properties depend on that, and both are load-bearing. Communication remains
available throughout a sweep: guard admission reads the state, and the state
says the transport is up - which it is. And a failed sweep has somewhere honest
to land: it reports the failure to its caller and leaves the runtime
``Enabled``, rather than being forced through the activation-outcome path whose
only failure exit is ``Error(_)`` - a state every consumer reads as "the
transport is not up", which for a re-detection is false.

``redetect()`` is strict, and this is a safety property rather than a
convenience: from ``Disabled``, ``Error``, and ``Enabling(_)`` alike it is
refused and **never** widened into an activation. All three are states with no
live transport, and a detection request is a request to *re-read* what is
already reachable; treating it as a bring-up would let a caller holding only
detection authority put packets on the vehicle network, which under
``init_mode = Disabled`` is exactly what the mode forbids. Communication is
brought up first, by whoever holds that authority. ``Error(_)`` is no
exception: recovery is an activation, and only ``activate()`` performs one.

A successful activation runs three ordered stages - transport, then every
registered ``CommunicationLifecycle`` hook in registration order, then the
registered detector - before publishing ``Enabled``. No external participant
votes on or blocks a lifecycle decision.

**Variant detection is deliberately not a lifecycle hook.** A hook is coupled
to the transport, runs on every enable, and has a matching ``deinitialize()``;
detection is optional, repeatable against a live transport, and has no
teardown counterpart. Keeping them apart is what lets ``enable()`` bring the
transport up without detecting, and lets ``redetect()`` run without
re-entering any hook's ``initialize()`` - which would otherwise break that
trait's paired contract, since a re-detection has no ``deinitialize()`` in
between. Only one detector exists; detection is whole-vehicle by definition,
so a second registration replaces the first.

Any *activation* failure publishes ``Error(_)``, which therefore always means
the transport is down or its state is unknown - the invariant the matrix and
the readiness gate both rely on when they treat ``Error`` as somewhere to
recover *from*. A failed re-detection is not an activation failure and does not
publish it: nothing was brought up or torn down, so the runtime stays
``Enabled``, the failure is reported to the caller through its return value,
and the effective ``VariantDetectionMode`` drops to ``Never``, because with the
sweep finished and failed nothing is going to settle any ECU's variant, and the
readiness gate has to be able to say so rather than advertise a detection that
is not coming. Diagnostic requests continue to
obtain their not-ready response from the handler-level readiness gate; the
lifecycle worker neither owns nor mutates HTTP protection records.

Awaited callers cannot strand ``Enabling``/``Disabling`` by cancellation:
lifecycle work is finalized independently of the calling task. Panic
boundaries are reported where practical and conservatively finalized.

HTTP Protection Ownership
--------------------------

``HttpProtectionRegistry::protect()`` returns a non-cloneable opaque
``OwnedHttpProtection``. The registry is cloneable, but the record key is not
part of any public type, event, callback, log, or removal API. Dropping an
owner token performs best-effort idempotent removal of only its own record.

Protections coexist. The request guard evaluates an immutable ordered
snapshot; the first installed matching protection supplies the denial. Route
and method matching retain path-segment boundaries, and exemptions take
precedence within a protection. A poisoned lock is recovered and records are
still evaluated, rather than read as an empty registry that would pass every
request through.

The diagnostic handler layer handles the "communication not ready" signal
directly: when communication is unavailable, it returns
``CommunicationNotReady`` (``503`` with ``Retry-After``), triggering
asynchronous activation when ``init_mode`` permits. The runtime-update plugin
installs its own protection using the shared registry, returning ``409
Conflict`` with exempt routes for health and lock-state endpoints.

Lifecycle Worker
-----------------

A bounded ``LifecycleCommand`` mailbox feeds the sole task that touches the
physical transport and the initializer list.

Its capacity bounds *admission* only: a command is either fully enqueued or
not sent at all, and every enqueued command is eventually processed or
explicitly failed, never silently dropped. That is what makes activation
triggers durable and coalesced - concurrent triggers for an uninitialized
vehicle join the one in-flight generation, and none can be lost to a full
mailbox. ``DisableLease::release()`` is cancellation-safe by the same
guarantee: it stays a synchronous defer-on-drop capability until the release
command is durably accepted, after which the worker owns finishing it.

**Shutdown uses a separate, unbounded out-of-band channel** so it can never be
blocked by a full command mailbox. It closes admission immediately, fails
queued commands deterministically, then best-effort disables the transport.
It does *not* preemptively cancel a command already executing - safe, because
commands and shutdown share one sequential loop, so teardown can never run
concurrently with a command still touching the transport, but it does not
bound shutdown latency. Preemptive cancellation needs a cancellable unit
smaller than one command; tracked separately.

*Why not an actor framework* (``kameo`` is already a workspace dependency):
a framework mailbox carries the stop signal as just another message - FIFO
behind queued commands, and itself blockable on a full mailbox - which is
precisely what the out-of-band lane exists to avoid. A working sender must
also exist *before* the task is spawned, since the plugin builder is handed a
functional handle during construction. Decisively, this worker must never be
restarted: it owns the physical transport, so a supervisor restarting it would
silently re-enable the vehicle network behind the plugin's ``init_mode``
decision. Worth revisiting only for a framework offering a control channel
separate from the message mailbox.

Disable Ownership
------------------

``disable(reason)`` is accepted from ``Enabled`` **and** from ``Disabled``,
with no active guards and no existing owner. The lease is exclusive ownership
of the runtime, not an operation on the transport: a consumer that needs
everything else held still while it works - runtime update, swapping
databases - needs no transport at all, and refusing it while communication is
deferred would force a deferred deployment to bring the whole vehicle network
up purely to become eligible. ``Error(_)`` is a conflict: its transport state
is unknown, so no resume shape could be chosen honestly.

Both halves of what a release means - whether the transport comes back at
all, and whether it detects when it does - are decided in the single locked
read that *grants* the lease and travel together on its ``DisableOwner``.
Neither the releaser nor the passage of time gets a say, and a later disable
generation cannot inherit an earlier one's shape.

* Granted from ``Enabled``: hooks are deinitialized and the transport taken
  down. ``release()`` restores both, in the detection shape the displaced
  runtime had *when the lease was granted*.
* Granted from ``Disabled``: neither transport nor hooks are touched - there
  is nothing up to take down, and deinitializing hooks that never saw an
  ``initialize()`` would break the paired contract. ``release()`` returns to
  plain ``Disabled``.

**A release never enables a runtime the releaser did not find enabled.** This
is what keeps the lease from becoming a back-door activation path: runtime
update holds ``DisableCommunication`` and no lifecycle authority, so if
releasing could activate, it could start vehicle communication ``init_mode``
never authorized.

Recording what the runtime *was doing* rather than what its enable *asked for*
is deliberate: the two differ only when an activation meant to detect but
found no detector registered, and there the effective mode is the honest
answer - consumers were already told nothing would settle a variant, so a
release must not quietly settle one behind that answer.

Dropping an unreleased lease - or a ``release()`` future cancelled before the
worker accepts it - performs a **synchronous defer**: it clears ownership and
transitions to ``Disabled`` without attempting re-activation. Drop never
blocks, never requires a Tokio runtime, and cannot fail.

``CommunicationGuard`` is held for a diagnostic operation's complete lifetime,
and disable is rejected while any guard is active.

Runtime Update
--------------

Runtime update creates its own ``UpdateInProgress`` protection *before*
requesting the lease. Registry installation is infallible; poisoned locks are
recovered rather than treated as an unavailable registry. The protection
returns ``409 Conflict`` and blocks every route except: ``GET
/health`` (covering ``/health/ready``); ``GET /vehicle/v15/data/version``;
``GET``/``POST`` on ``/vehicle/v15/authorize``; ``GET``/``POST``/``PUT`` on
``/vehicle/v15/locks`` (create, list, and extend, **not** delete); and
``GET`` on the ``runtimefilesupdate/executions`` prefix. Uploads, deletes,
and execution ``POST`` routes are not exempt.

On every cleanup path and on completion, the lease is released **before** the
update protection is dropped. Dropping first would open a window in which
neither the ``409`` nor a restored transport is in place, and requests
arriving mid-resume would fall through to a handler-level error instead of the
response a caller is expected to retry against. If an update task is cancelled
or panics, both owners drop independently: the lease defers synchronously and
the update owner removes only its own record.

``PostUpdateCommunicationMode`` names the intended state *after* the update,
not what the update displaced. ``Deferred`` drops the lease. ``Enabled``
releases it and *then* requests activation - a second step, because releasing
only restores what the lease took away, and an update may legitimately start
from a deferred runtime, so a release alone would leave ``Enabled``
unhonoured exactly when it matters. The request goes through
``CommunicationAccess`` rather than the lease, keeping ``init_mode`` the final
authority: ``Always``/``OnDemand`` honour it, ``Disabled`` treats it as a
no-op. A post-update preference must not override an authorization boundary.

There is deliberately no third "restore whatever it was before" value: the
lease already restores what it displaced, so such a value would only mean
declining to ask afterwards - which is ``Deferred``.

An update therefore runs to completion on an ``OnDemand``/``Disabled``
deployment without the vehicle network ever coming up, which is the point of
updating before touching the vehicle.

Deferred Startup And Mode Semantics
------------------------------------

Setup constructs passive, immutable preparation (configuration, database
loading, ECU inventory, file-manager and security-plugin preparation), then
the lifecycle framework and protection registry. It builds and retains the
plugin, registers hooks and the detector, derives narrow views, and only then
publishes routes.

.. list-table:: Required mode semantics
   :header-rows: 1
   :widths: 12 22 26 24 26

   * - Mode
     - Startup
     - Plugin ``activate()``
     - First ECU request
     - ``trigger_detection()``
   * - ``Always``
     - Initialize whole vehicle
     - Join or repeat according to current state
     - Requests use current readiness
     - Re-detect while ``Enabled``; refused otherwise
   * - ``OnDemand``
     - Keep uninitialized
     - Initialize whole vehicle
     - Return pending, trigger once
     - Re-detect while ``Enabled``; refused otherwise
   * - ``Disabled``
     - Keep uninitialized
     - Reject, no network activity
     - Return pending, never triggers
     - Re-detect while ``Enabled``; refused otherwise

``trigger_detection()`` is identical in all three modes because it never
initiates communication - it is not, and must not become, an escape hatch out
of ``Disabled``. That mode therefore means what it says: with the default
plugin *nothing* brings communication up, and such a deployment inhibits
vehicle communication outright. Enabling it is the business of a replacement
plugin holding that authority, not of a detection request.

While ``Enabled``, detection is refused (``GuardsHeld``) whenever a
``CommunicationGuard`` is active. A guard is the only lock spanning a whole
multi-request sequence (a flash transfer's ``TransferData`` blocks); the
per-ECU request semaphore reopens between individual requests, so a detection
could otherwise land mid-sequence. It is refused rather than made to wait,
because waiting on a minutes-long sequence would surface as an acquisition
timeout rather than a structured failure the caller can act on.

**The exclusion runs one way only.** A sweep in flight leaves the state at
``Enabled``, so guards keep being admitted and diagnostics keep being served for
its whole duration. Blocking them would close the diagnostic surface over a
transport that is demonstrably working, for seconds at a time, and buy nothing:
per-ECU ``VariantState`` already governs the requests that actually depend on a
settled variant, and a sweep does not invalidate a variant that is already
settled.

``disable()`` is the exception, refused during a sweep with
``DisableError::InUse``. Detection is a use of communication, and since the
state remains ``Enabled`` throughout, the ``(Enabled, Disable)`` cell would
otherwise grant a lease and take the transport down underneath a running
detection. The check belongs in ``decide`` rather than in guard admission
because it rules on a transition, not on an acquisition.

``[communication] variant_detection`` selects a ``VariantDetectionMode``:
``Always`` runs the detector as the last stage of every activation; ``Never``
brings transport and hooks up without it. ``Never`` means never
*automatically* - an explicit ``trigger_detection()`` runs the detector
regardless, which is how such a runtime becomes ready. That override applies
to the detection stage only and never relaxes the state rule, so a ``Never``
runtime still has to be enabled before anything can detect. Unlike
``init_mode`` this is framework policy applied at claim time, because it
describes what an activation *is* rather than who may ask for one.

.. note::

   Setup registers the detector *before* it activates anything. That ordering
   is a requirement: registering afterwards would let an ``Always`` startup
   activate with no detector, leaving every ECU ``NotTested`` with nothing
   scheduled to settle it.

``Always`` calls ``activate(Startup)`` through the plugin at setup and
propagates failure per existing application-start semantics - the only place
the framework itself inspects ``init_mode`` to initiate communication.

**Deferred DoIP resource creation.** ``DoipDiagGateway::new()`` is purely
in-memory: no socket, no packet, no task. The UDP bind, VIR broadcast, ECU
connection, and VAM listener all happen lazily inside the gateway's own
``enable()`` - the same authorization choke point ``init_mode`` already
gates. This lets ``cda-main``'s startup construction stay unconditional (no
mode branch) while still guaranteeing zero network activity before an
authorized trigger: without a bound socket, no packet can physically be sent
or received, which is the strongest available guarantee.

Variant Detection Readiness
------------------------------

``Enabled`` means activation *completed*, **not** that detection *concluded*:
the detection stage dispatches per ECU and those settle asynchronously, with a
retry budget for ECUs that conclude offline. The per-ECU ``VariantState`` is
the actual readiness signal.

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
     - No - return pending
   * - Operation execution
     - Transport plus detected variant
     - No - return pending

The SOVD URL space is a function of the loaded databases alone and never of a
detected variant, which is why routes are registered at startup in all three
modes. Variant-dependent content instead reports not-ready rather than
answering with whatever the base or previously-detected variant described.

**No variant-dependent request ever blocks waiting for detection.** Every case
resolves immediately: already settled -> served; nothing in flight -> fire a
non-blocking activation request and answer ``CommunicationNotReady``; a
runtime that will not settle variants -> answer immediately, since waiting
would buy nothing; detection still in flight -> answer with a retry hint.

**Precedence:** the state check must precede the detection-mode check. The
effective ``VariantDetectionMode`` is published when an operation is *claimed*,
so before the first claim it reads ``Never`` regardless of configuration.
Consulting it while ``Disabled`` would read that initial value as "nothing will
ever settle this" and skip the activation request - which under ``OnDemand``
is the one request that would have brought communication up, leaving every
subsequent request pending forever. Both rules genuinely match that state;
only this ordering resolves them correctly.

Alternatives Considered
------------------------

**Lazily constructing the UDS manager**. SOVD routes hold a value snapshot
of the UDS manager baked in at route-build time, so a truly late-bound manager
needs either a late-bound ``UdsEcu``/``SchemaProvider`` wrapper spanning that
trait family's full surface, or the rebuild-and-``replace_routes`` sequence
the update reloader already uses, driven on first activation. Both remain
available as future work.

An eagerly-constructed but
network-inert UDS manager is accepted, and the property the criterion exists
to guarantee is enforced directly by two independent mechanisms instead - the
lazy DoIP socket rules out network activity before authorization, and the
readiness gate rules out premature wrong-variant data, including the
post-activation pre-detection window that deferring construction alone would
not have closed.

**An actor framework for the lifecycle worker** - see `Lifecycle Worker`_.

Deferred And Out Of Scope
--------------------------

There is no persisted ECU-to-gateway topology. Every accepted trigger
initializes the whole vehicle, and process startup never restores prior
topology or readiness. Explicitly deferred:

* ``WhenNotPersisted`` as a selectable ``init_mode`` value.
* Persisted topology storage, loading, validation, clearing, atomic updates,
  direct reconnect to a persisted gateway, per-gateway fallback discovery, and
  post-detection persistence publication.
* Per-ECU/per-gateway ``OnDemand`` initialization scope - every accepted
  trigger normalizes to whole-vehicle.
* Topology re-discovery (the ``networkreset(trigger_detection=true)``
  endpoint). Unlike variant re-detection it may construct gateways. It has no
  ``DetectionCause`` variant, so it is *unrequestable* rather than rejected;
  when the endpoint lands, its cause must be rejected while ``Enabled`` with a
  structured failure rather than silently falling back to the weaker variant
  re-detection. No failure variant is reserved in advance - an unconstructed
  variant is dead code.
* Response interception. A future generic Tower finalizer may inspect request
  metadata and downstream responses, but must remain independent of protection
  ownership and lifecycle authority, and must not grant authority to mutate
  another owner's protection.

Future persistence work must not alter the plugin authorization boundary or
permit ``Disabled``-mode traffic under any circumstance: persisted topology
may change *what* an authorized trigger does, never *whether* an unauthorized
one may act. Absence, corruption, staleness, and partial records are
unresolved - this ADR prescribes neither fail-open nor fail-closed, and a
future revision must decide before persisted topology ships.

Extension points are marked ``TODO(persistence-init-mode): ... See ADR-006.``
(currently one, at the DoIP lazy-socket bind, where a reconnect-one-gateway
bring-up would branch); do not scatter generic TODOs beyond those. The
``networkreset`` endpoint is marked separately as
``TODO(networkreset-endpoint)``, being blocked on the endpoint's existence
rather than on persisted topology.

Consequences
------------

* The selected plugin is the sole public lifecycle authority while generic
  framework invariants remain enforced.
* ``init_mode`` supports exactly ``Always``, ``OnDemand``, and ``Disabled``.
  ``Disabled`` is a strict authorization boundary: with the default plugin
  nothing initiates communication in that mode. That boundary is *plugin
  policy over three state-driven primitives*, not a privileged operation --
  the framework authorizes all three identically in every mode, and a
  replacement plugin may draw the line elsewhere.
* Enabling communication and detecting variants are separable; no hook ever
  sees a second ``initialize()`` without an intervening ``deinitialize()``.
* HTTP availability is independent owner tokens, not a global switch or shared
  admission lock.
* Diagnostic consumers and runtime update have deliberately narrow
  capabilities, type-level throughout, including over the gateway and UDS
  manager slots (see ``ComponentSlot``/``ReplaceComponent`` above).
* A failed activation is visible as structured lifecycle state, and diagnostic
  requests report handler-level ``CommunicationNotReady`` rather than relying
  on lifecycle-owned middleware protection.
* Activation triggers are durable and coalesced; mailbox saturation cannot
  lose the sole pending trigger, and shutdown cannot be blocked by a full
  mailbox.
* No network activity occurs before an authorized trigger, achieved without a
  startup-time ``init_mode`` branch in ``cda-main``.
* No variant-dependent request ever blocks waiting for detection to conclude.

Superseded Concepts
--------------------

This model replaces, with no compatibility facade:

* An ``update_in_progress: Arc<AtomicBool>`` cloned into unrelated modules,
  each reading or writing it with no single owner.
* ``UpdateGuardState``/``UpdateGuardLayer``, whose ``busy_handle()`` exposed
  that flag as the sole HTTP-restriction switch, coupling a restriction's
  lifetime to transport admission rather than to an owned record.
* A separate flash-transfer activity guard consulted ad hoc before an update,
  uncoordinated with either mechanism above.
* No deferred-startup concept at all: ``main`` always activated communication
  eagerly at process start.
