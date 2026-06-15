.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

.. _requirements-error-handling:

Error Handling
==============

The CDA must implement a structured error handling strategy that propagates domain-specific errors
through its layered architecture and maps them to SOVD-compliant API responses. The strategy must
ensure clear separation of concerns, where each layer owns its error semantics without leaking
implementation details to other layers.


Layer-Owned Error Definitions
-----------------------------

.. req:: Layer-Specific Error Definitions
    :id: req~error-handling-layer-specific-errors
    :links: arch~error-handling-layer-specific-errors
    :reqtype: functional
    :status: draft

    Each internal component of the CDA shall define its own error types using domain-appropriate
    vocabulary. Error definitions must describe failure conditions in terms meaningful to the
    component's own domain, without referencing API-level or presentation-layer concepts.

    **Rationale**

    Keeping error definitions local to each component ensures that changes in one layer do not
    cascade to unrelated layers and that error semantics remain clear and unambiguous within their
    context.


.. req:: Error Dependency Isolation
    :id: req~error-handling-dependency-isolation
    :links: arch~error-handling-dependency-isolation
    :reqtype: constraint
    :status: draft

    Internal components (communication layers, diagnostic kernel, database layer) shall not depend
    on the SOVD API layer or its interface definitions for their error type declarations.

    The only exception is components that need to carry opaque plugin errors, which may depend on
    a shared plugin error interface crate.

    **Rationale**

    This constraint preserves the architectural layering by preventing reverse dependencies from
    lower layers to the API layer.


Centralized SOVD Error Mapping
------------------------------

.. req:: Centralized Error-to-SOVD Mapping
    :id: req~error-handling-centralized-sovd-mapping
    :links: arch~error-handling-centralized-sovd-mapping
    :reqtype: functional
    :status: draft

    The SOVD API layer shall be the single point where internal domain errors are mapped to
    SOVD-compliant HTTP error responses. This mapping shall be exhaustive, such that every
    possible error variant from internal layers has a defined SOVD representation.

    **Rationale**

    Centralizing the mapping ensures consistency in error responses presented to clients,
    simplifies auditing of error behavior, and makes the mapping decision explicit for each
    error variant.


Error Parameter Propagation
---------------------------

.. req:: Contextual Error Parameter Propagation
    :id: req~error-handling-parameter-propagation
    :links: arch~error-handling-parameter-propagation
    :reqtype: functional
    :status: draft

    When an error carries contextual data (e.g., connection parameters, addresses, timeout values),
    that data shall be propagated to the SOVD error response as structured parameters. The
    mechanism shall ensure that adding contextual fields to error definitions automatically makes
    them available in the API response without requiring additional per-field wiring.

    **Rationale**

    Contextual parameters in error responses enable clients to understand failure conditions and
    take corrective actions without requiring additional diagnostic requests.


.. req:: Error Parameter Preservation Through Layers
    :id: req~error-handling-parameter-preservation
    :links: arch~error-handling-parameter-propagation
    :reqtype: functional
    :status: draft

    When errors are wrapped or forwarded through intermediate layers, the original error's
    contextual parameters shall be preserved and remain accessible for extraction at the SOVD
    conversion point.


Plugin Error Handling
---------------------

.. req:: Plugin Error Self-Containment
    :id: req~error-handling-plugin-self-containment
    :links: arch~error-handling-plugin-error-trait
    :reqtype: functional
    :status: draft

    Plugins shall be self-contained with respect to error handling: each plugin defines both its
    own error types and the mapping of those errors to SOVD-compliant responses. The CDA core
    shall not need to understand or interpret plugin-specific error semantics.

    **Rationale**

    Self-containment enables plugins to be developed independently without requiring changes
    to the CDA core when new error conditions are introduced.


.. req:: Opaque Plugin Error Propagation
    :id: req~error-handling-plugin-opaque-propagation
    :links: arch~error-handling-plugin-error-wrapper
    :reqtype: functional
    :status: draft

    Plugin errors shall be propagatable through CDA layers without those layers needing to know
    the concrete plugin error type. Intermediate layers shall treat plugin errors as opaque
    values that carry their own SOVD mapping logic.

    **Rationale**

    Opaque propagation prevents intermediate layers from coupling to specific plugin
    implementations and allows new plugins to be added without modifying layer error enums
    beyond an opaque variant.


Communication Errors
--------------------

.. req:: Communication Error Connection Context
    :id: req~comm-error-connection-context
    :links: arch~comm-error-connection-context
    :reqtype: functional
    :status: draft

    Every communication error shall carry the connection context that was active at the time of
    failure. This context shall include at minimum:

    * The target IP address.
    * The target tcp port.
    * The logical gateway address and logical ECU address.
    * The tester logical address.

    **Rationale**

    Clients receiving an error response must be able to identify which remote endpoint was unreachable
    without having to consult separate configuration or log files. The currently used tcp port of the
    target allows clients to infer the exact point in the communication, when the error occurred.

    Misdiagnosed TLS errors (treated as generic network errors) lead to unnecessarily long
    troubleshooting cycles in field scenarios.


.. req:: Communication Error Connection Phase
    :id: req~comm-error-connection-phase
    :links: arch~comm-error-connection-phase
    :reqtype: functional
    :status: draft

    Communication errors shall identify the phase of the connection lifecycle in which the failure
    occurred. The phases are, in order:

    1. TCP connection establishment
    2. TLS handshake (when TLS is enabled)
    3. DoIP routing activation
    4. Diagnostic message transmission (TX)
    5. Diagnostic ACK/NACK reception
    6. Diagnostic response reception (RX)

    The error shall clearly indicate the last phase that succeeded and the phase in which the
    failure occurred.

    **Rationale**

    Knowing the phase of failure allows operators to narrow the root cause rapidly - for instance,
    distinguishing a network-level reachability problem from a DoIP routing configuration error.


.. req:: Routing Activation Failure Context
    :id: req~comm-error-routing-activation
    :links: arch~comm-error-routing-activation
    :reqtype: functional
    :status: draft

    When DoIP routing activation is rejected by a gateway, the error shall include the rejection
    NACK code returned by the gateway in addition to the full connection context. The error shall
    be a distinct variant from generic connection failures so that routing activation problems
    are immediately identifiable without log inspection.


.. req:: Transmission Timeout Context
    :id: req~comm-error-tx-timeout
    :links: arch~comm-error-timeout-context
    :reqtype: functional
    :status: draft

    When a timeout occurs while waiting for a DoIP diagnostic ACK or NACK after transmitting a
    message, the error shall include the values of the communication parameters governing
    ACK/NACK timeout and retry behavior (see :need:`req~doip-communication-parameters`), the
    elapsed time, and the connection context.


.. req:: Response Timeout Context
    :id: req~comm-error-rx-timeout
    :links: arch~comm-error-timeout-context
    :reqtype: functional
    :status: draft

    When a timeout occurs while waiting for a UDS diagnostic response after a successful ACK,
    the error shall include the value of the active response timeout communication parameter
    (see :need:`req~uds-communication-parameters` and :need:`req~uds-request-response`), the
    elapsed time, and the connection context.


Conversion Errors
-----------------

.. req:: Conversion Error Type
    :id: req~conversion-error-type
    :links: arch~conversion-error-type
    :reqtype: functional
    :status: draft

    A dedicated error type shall represent failures that occur during the encoding of SOVD API
    parameters into UDS byte payloads, or during the decoding of UDS byte payloads into SOVD API
    JSON values. This error type shall carry:

    * The path or name of the parameter or field where the failure occurred.
    * The raw value or byte representation that could not be converted, where available.
    * A textual description of the reason for the conversion failure.


.. req:: Conversion To Payload Errors
    :id: req~conversion-to-payload-errors
    :links: arch~conversion-to-payload-type
    :reqtype: functional
    :status: draft
    :rationale: Errors that occur while converting to a payload are handled differently in other layers than errors that occur while converting from a payload

    When an error is encountered during the request phase the error is wrapped into an
    ``ConversionToPayloadError`` to make it distinguishable from errors during the reverse
    operation.


.. req:: Conversion From Payload Error Type
    :id: req~conversion-from-payload-errors
    :links: arch~conversion-from-payload-errors
    :reqtype: functional
    :status: draft
    :rationale: Errors that occur while converting from a payload are handled differently in other layers than errors that occur while converting to a payload

    When an error is encountered during the response phase the errors are wrapped into an
    ``ConversionFromPayloadError`` type to make them distinguishable from errors during the reverse
    operation. This type shall include successfully converted data, and a list of ``ConversionError``.


System Errors
-------------

.. req:: Database Error Expressiveness
    :id: req~system-error-database
    :links: arch~system-error-database
    :reqtype: functional
    :status: draft

    Errors arising from the diagnostic description database (MDD) shall distinguish between the
    following failure categories:

    * I/O failure reading the database file.
    * Structural format violation (the file is not a valid MDD/FlatBuffers container).
    * Semantic parsing failure (the structure is readable but a field cannot be interpreted).
    * Missing mandatory data (a required definition is absent from the database).
    * Invalid parameter reference (a named item does not exist in the loaded database).


.. req:: Storage Error Expressiveness
    :id: req~system-error-storage
    :links: arch~system-error-storage
    :reqtype: functional
    :status: draft

    Errors arising from storage operations shall distinguish between the following failure
    categories:

    * Key or collection not found (the requested data does not exist).
    * Permission denied (the caller lacks access rights for the operation).
    * Capacity exhausted (no storage space is available).
    * I/O failure (an underlying read/write operation failed).
    * Data integrity violation (stored data is corrupted beyond automatic recovery).
    * Transaction conflict (a concurrent or incomplete transaction prevented the operation).
