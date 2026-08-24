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

ADR-006: Centralize Communication Lifecycle Authority
=====================================================

Status
------

**Accepted**

Date: 2026-08-24

Context
-------

Deferred communication introduces coordination across transport activation,
variant detection, diagnostic admission, runtime updates, and HTTP
availability. If each subsystem controls these concerns independently, their
views can diverge: transport can be active while initialization is incomplete,
an update can race diagnostic work, or one feature can remove another feature's
HTTP restriction.

The required externally visible behavior is specified by
:need:`req~dt-deferred-initialization`, :need:`req~dt-variant-detection`, and
:need:`req~dt-ecu-states`. This ADR decides how authority and ownership are
divided to implement those contracts.

Decision
--------

Communication lifecycle changes have one public authority: the communication
plugin selected at startup. The plugin decides policy, including whether a
request is authorized to activate communication. It delegates accepted work to
a framework lifecycle coordinator; consumers do not receive direct transport
control.

The framework, rather than the plugin, enforces generic invariants:

* Lifecycle transitions are serialized
* Diagnostic use excludes an exclusive disable operation
* Transport and lifecycle hooks are initialized and deinitialized as one
  coordinated operation
* Variant re-detection is an operation on enabled communication, separate from
  transport activation and lifecycle-hook initialization.

Consumers receive capability-specific views of framework-managed resources.
Diagnostic handlers can inspect and acquire communication, while runtime update
can hold communication disabled and replace components without using those
components for diagnostics. HTTP restrictions use independent owned records,
not a shared global flag, so one owner cannot remove another owner's
restriction.

The configured post-update communication mode names the requested end state,
regardless of the communication state before the update. ``Enabled`` requests
activation after the update, while ``Deferred`` leaves communication down until
activation is requested separately. Releasing the update's exclusive disable
lease only restores the state displaced by that lease; the runtime update does
not activate communication directly. Instead, it submits the configured request
through the communication authority. The selected plugin remains free to reject
activation according to its policy: the default plugin honors the request in
``Always`` and ``OnDemand`` modes, while ``Disabled`` leaves communication down.

Configuration, databases, network-inert communication
objects, and routes are prepared at startup. This keeps route topology and
dependency wiring independent of runtime communication state while preserving
the no-traffic-before-activation property for framework-managed transports.

Rationale
---------

Separating plugin policy from framework invariants allows deployments to choose
activation policy without requiring every plugin to reproduce concurrency and
cleanup rules. Capability-specific views make accidental misuse of managed
resources harder and make ownership visible in API boundaries.

Constructing network-inert components eagerly allows SOVD routes to be derived from loaded diagnostic data.
Runtime readiness is then represented by lifecycle and per-ECU state rather than by the
presence or absence of handlers and components.

Keeping variant detection separate from lifecycle hooks reflects their
different lifetimes: transport-dependent hooks have paired initialization and
deinitialization, whereas detection is optional and repeatable while transport
remains active.

Alternatives Considered
-----------------------

Lazy Component And Route Construction
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Constructing the gateway, UDS manager, and ECU routes on first activation would
make object existence represent readiness. It was rejected because route and
component replacement would become part of every activation path, and metadata
derived from already loaded databases would be unavailable unnecessarily.

Plugin-Owned Lifecycle Mechanics
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Giving plugins raw transport control and requiring them to implement transition
and exclusion rules was rejected. Policy is intentionally extensible; safety
and ownership invariants must remain consistent across plugin implementations.

Shared Flags And Global HTTP Gating
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Shared booleans for update state, diagnostic activity, or HTTP availability
were rejected because they do not encode ownership. Independent leases, guards,
and protection records allow cleanup to affect only the resource owned by that
operation.

Variant Detection As A Lifecycle Hook
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Treating detection as a normal lifecycle hook was rejected because re-detection
would either reinitialize unrelated hooks or violate their paired lifecycle.

Consequences
------------

* Activation policy can vary by startup-selected plugin without moving generic
  lifecycle invariants into plugin code.
* Framework consumers have narrower access to managed communication resources.
* Deferred and eager modes share one application object graph and route model.
* Runtime readiness cannot be inferred solely from transport state or component
  existence; lifecycle and per-ECU state remain explicit.
* Runtime update and other HTTP restrictions require owned cleanup resources.
* The capability boundary reduces accidental authority but does not isolate
  malicious or defective in-process plugins.

Exact APIs, state transitions, synchronization, cleanup ordering, and route
behavior are documented with the owning implementation and architecture.
