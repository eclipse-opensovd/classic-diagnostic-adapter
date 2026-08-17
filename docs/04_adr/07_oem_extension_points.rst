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

ADR-007: Expose CDA's own interfaces as OEM extension points
============================================================

Status
------

**Accepted**

Date: 2026-08-15

Context
-------

OEMs embed the Classic Diagnostic Adapter and extend it: custom SOVD routes,
their own security plugin, a different storage backend, vendor rules on when the
vehicle network may be brought up, and their own runtime-update policy.

None of that was supported in any meaningful sense. An integration adding routes
reached into ``cda-main``'s internals and named the concrete UDS manager with its
full transport parameterisation
(``UdsManager<DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>>>, _>``),
so it stopped compiling every time the transport stack was refactored. The
runtime-update plugin, nominally the extension point for update handling,
depended on ``cda-sovd``, ``cda-plugin-security``,
``cda-plugin-communication-management`` and ``cda-storage``, so replacing it meant
accepting CDA's HTTP layer, security plugin, sibling communication plugin and
storage backend as a package.

Nothing in this repository consumed those extension points either, so a breaking
visibility or signature change was only discovered when an external integration
failed to build.

Decision
--------

**Expose CDA's own interfaces. Do not re-wrap them.**

The diagnostics capability hands out ``Arc<dyn UdsEcu<Response = DiagnosticResponse>>``
- the identical interface CDA's internal SOVD handlers hold. A plugin therefore
has the possibilities of an internal service: both service addressing modes,
sessions, security access, tester present, flash transfer, DTCs, database
queries, functional groups and variant state.

**Wrap only what an integration cannot get right on its own.** Three things
qualify, and nothing else is wrapped:

* *Route registration*, because the namespace recommendation and the handle
  needed to unmount a group later are CDA's to define.
* *Lock checks*, because a route that changes ECU state must apply the same rule
  as the standard component routes; reproducing that from the raw lock tables
  duplicates policy and drifts.
* *Component access*, because a runtime database update replaces the whole
  component generation, and a handle must follow it rather than pin a
  generation that has been shut down.

**Contracts live in ``cda-interfaces``; implementations live in their own crate.**
A plugin depends on the contract crate alone. Where an implementation detail was
needed by two plugins - the HTTP protection registry, the transport-disable
capability - the contract moved to ``cda-interfaces`` and the implementation
stayed put.

**The application supplies what is application-specific.** The database format
(``RuntimeFileInspector``), the authorization policy, the storage backend and the
set of routes reachable during an update are all injected by ``cda-main`` rather
than assumed by the plugin.

**Examples are workspace members.** One runnable binary per extension point,
each customising exactly one thing, built by CI so that a breaking change fails
here rather than in someone else's repository.

Rationale
---------

A curated facade was the obvious alternative and was tried first: a
``DiagnosticServices`` trait with three methods covering "send one service to one
ECU". It could not express reading DTCs, opening a session, running a
functional-group job, or waiting for variant detection - and every attempt to fix
that converged on re-declaring ``UdsEcu`` under a different name, with the
facade needing an update whenever the interface grew.

The property that actually protects integrations is *not naming concrete
transport types*. ``dyn UdsEcu`` has that property already. Wrapping it adds
maintenance cost and removes capability without adding stability.

Pinning the associated ``Response`` type is what makes ``UdsEcu`` usable as a
trait object. That type is fixed by the payload decoder rather than by the
transport, so it does not move when the transport stack does.

Consequences
------------

* An integration is coupled to ``UdsEcu`` and its sub-traits, so a change there
  is a breaking change for OEMs. This is already true for ``cda-sovd``, and it is
  better visible than hidden behind a facade that quietly cannot do the job.
* The runtime-update plugin's ``[dependencies]`` is exactly ``cda-interfaces``.
  ``cda-storage`` and the communication plugin remain as *dev*-dependencies:
  production code speaks the contract, tests may name an implementation.
* Exactly one update plugin is ever registered. ``ExclusiveRuntimePlugin`` does
  not arbitrate between plugins - it serialises concurrent HTTP requests against
  the single registered one, which would otherwise interleave on the same
  staging directory.
* OEM routes may override standard SOVD routes. CDA warns once at registration
  rather than refusing, because an integration knows its deployment and a
  deliberate override is legitimate.
