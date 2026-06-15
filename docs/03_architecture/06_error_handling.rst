.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

Error Handling
==============

Layer-Specific Error Enums
--------------------------

.. arch:: Layer-Specific Error Definitions
    :id: arch~error-handling-layer-specific-errors
    :status: draft

    Each internal crate defines its own error enum expressing failure conditions in
    domain-appropriate vocabulary. Error enums are the sole mechanism for reporting failures
    from a layer's public API.

    The following layers each maintain independent error definitions:

    * **Communication layer (DoIP)** -- connection failures, routing errors, timeouts
    * **Communication layer (UDS)** -- negative responses, session errors, protocol violations
    * **Diagnostic kernel** -- variant detection failures, service resolution errors, payload
      validation
    * **Database layer** -- loading failures, format errors, missing entries

    Error enums have no awareness of the SOVD API or HTTP semantics. They express purely what
    went wrong in their own domain.


.. arch:: Error Dependency Isolation
    :id: arch~error-handling-dependency-isolation
    :status: draft

    The dependency graph for error types enforces strict layering:

    * Communication and diagnostic kernel crates depend only on the shared interfaces crate for
      common types.
    * These crates never depend on the SOVD API layer or the SOVD interface crate for error
      definitions.
    * The only cross-cutting dependency permitted is the opaque plugin error wrapper type, which
      is defined in the shared interfaces crate.

    This ensures that changes to error-to-SOVD mappings do not trigger recompilation or
    modification of lower-layer crates.


Centralized SOVD Conversion
----------------------------

.. arch:: Centralized SOVD Error Mapping
    :id: arch~error-handling-centralized-sovd-mapping
    :status: draft

    The SOVD API layer is the single location where domain errors from internal layers are
    converted into SOVD-compliant HTTP error responses. This is achieved through explicit
    conversion implementations from each layer's error type to the API error type.

    The conversion implementations use exhaustive pattern matching, ensuring that:

    * Every error variant has a deliberate mapping to an appropriate SOVD error code and HTTP
      status.
    * Adding a new error variant in any layer produces a compile-time error until a mapping
      decision is made.
    * The mapping logic is centralized and auditable in one location.

    .. uml::

        @startuml
        package "Communication Layer" {
            [DoipError]
            [UdsError]
        }

        package "Diagnostic Kernel" {
            [CoreError]
        }

        package "SOVD API Layer" {
            [ApiError]
            [Error Conversion]
        }

        [DoipError] --> [Error Conversion] : From<DoipError>
        [UdsError] --> [Error Conversion] : From<UdsError>
        [CoreError] --> [Error Conversion] : From<CoreError>
        [Error Conversion] --> [ApiError] : produces
        @enduml


Error Parameter Propagation
---------------------------

.. arch:: Error Parameter Propagation via Serialization
    :id: arch~error-handling-parameter-propagation
    :status: draft

    Error enums derive serialization alongside their error trait implementation. Contextual data
    embedded in error variants (connection parameters, addresses, timeout values) is automatically
    extractable as a structured parameter map through serialization.

    The mechanism works as follows:

    1. Error variants embed contextual data as named fields or flattened structs.
    2. A generic extraction function serializes the error value and converts the resulting
       structure into a key-value parameter map.
    3. The SOVD conversion layer calls this extraction function to populate the ``parameters``
       field of the SOVD error response.

    When errors are wrapped through intermediate layers (e.g., a communication error embedded
    within a kernel error), the original error struct is preserved intact. The SOVD conversion
    layer matches through the wrapping and extracts parameters from the inner error, ensuring no
    contextual data is lost during propagation.

    The net effect is that adding a field to an error variant automatically surfaces it in the
    SOVD response without requiring additional wiring per field.


Plugin Error Handling
---------------------

.. arch:: Plugin Error Trait
    :id: arch~error-handling-plugin-error-trait
    :status: draft

    A trait is defined in a shared interface crate that allows plugin errors to express themselves
    as SOVD error responses. This trait requires implementations to provide:

    * An HTTP status code
    * A human-readable error message
    * A SOVD error code
    * An optional vendor-specific error code
    * Optional structured parameters

    Plugins implement this trait on their own error types, making them fully self-contained:
    they define both the error conditions and how those conditions appear to SOVD clients.

    The trait is defined in a dedicated interface crate to ensure it is visible to both plugin
    implementations and the SOVD API layer without creating circular dependencies.


.. arch:: Opaque Plugin Error Wrapper
    :id: arch~error-handling-plugin-error-wrapper
    :status: draft

    An opaque wrapper type is defined in the shared interfaces crate to allow plugin errors to
    flow through intermediate layers. The wrapper holds a trait object of the plugin error trait,
    erasing the concrete plugin error type.

    Layer error enums include a dedicated variant for carrying this opaque wrapper. This allows
    plugin errors to propagate from the plugin boundary through the diagnostic kernel and up to
    the SOVD API layer without intermediate layers needing to know or match on the concrete
    plugin error type.

    At the SOVD conversion point, the opaque wrapper is unwrapped and the trait method is called
    to obtain the SOVD error response, bypassing the normal domain-to-SOVD mapping logic.

    .. uml::

        @startuml
        package "SOVD Interface Crate" {
            interface IntoSovdError {
                +into_sovd_error() -> SovdErrorResponse
            }
        }

        package "Shared Interfaces Crate" {
            class PluginError {
                -inner: Box<dyn IntoSovdError>
                +into_sovd_error() -> SovdErrorResponse
            }
        }

        package "Plugin" {
            class ConcretePluginError
        }

        package "Diagnostic Kernel" {
            enum CoreError {
                ...
                Plugin(PluginError)
            }
        }

        package "SOVD API Layer" {
            class ApiError
        }

        ConcretePluginError ..|> IntoSovdError
        PluginError o-- IntoSovdError
        CoreError *-- PluginError
        CoreError --> ApiError : conversion
        @enduml


Communication Errors
--------------------

.. arch:: Communication Error Connection Context
    :id: arch~comm-error-connection-context
    :status: draft

    A ``ConnectionContext`` value type is defined in the shared interfaces crate and embedded in
    communication error variants that relate to a specific remote endpoint. It captures the
    network and protocol addressing information that was active at the time of the error:

    * ``target_ip`` -- IP address of the remote DoIP entity (string).
    * ``target_tcp_port`` -- TCP port used for the communication.
    * ``gateway_logical_address`` -- DoIP logical address of the gateway entity.
    * ``ecu_logical_address`` -- DoIP logical address of the target ECU.
    * ``tester_logical_address`` -- DoIP logical address of the diagnostic tester.

    ``ConnectionContext`` derives ``Serialize`` so that all fields are automatically available
    as SOVD response parameters via the serialization-based extraction mechanism.

    .. uml::

        @startuml
        class ConnectionContext {
            +target_ip: String
            +target_tcp_port: u16
            +gateway_logical_address: u16
            +ecu_logical_address: u16
            +tester_logical_address: u16
        }
        @enduml


.. arch:: Communication Error Connection Phase
    :id: arch~comm-error-connection-phase
    :status: draft

    A ``ConnectionPhase`` enum describes the stage of the DoIP connection lifecycle at which a
    failure occurred. Each variant identifies a distinct step, allowing the receiver of an error
    to determine exactly how far the connection progressed before failing:

    * ``TcpConnect`` -- failure during TCP socket connection establishment.
    * ``TlsHandshake`` -- failure during TLS handshake (only reachable when TLS is enabled;
      implies TCP succeeded).
    * ``RoutingActivation`` -- failure during DoIP routing activation (implies transport layer
      succeeded).
    * ``DiagnosticTransmit`` -- failure while sending a diagnostic message (implies connection
      was fully established).
    * ``AckReception`` -- failure or timeout while waiting for the DoIP diagnostic ACK/NACK.
    * ``ResponseReception`` -- failure or timeout while waiting for the UDS diagnostic response.
    * ``Idle`` -- failure (e.g. disconnect) occurred while connection was not in active use.

    This enum is embedded in the ``CommunicationError`` type and combined with the
    ``ConnectionContext`` to form a complete picture of where and why a failure occurred.

    .. uml::

        @startuml
        enum ConnectionPhase {
            TcpConnect
            TlsHandshake
            RoutingActivation(nack_code: u8)
            DiagnosticTransmit
            AckReception
            ResponseReception
            Idle
        }
        @enduml


.. arch:: Routing Activation Failure Context
    :id: arch~comm-error-routing-activation
    :status: draft

    The ``RoutingActivation`` variant of ``ConnectionPhase`` carries a ``nack_code: u8`` field
    containing the DoIP routing activation NACK code returned by the gateway. This code is
    defined by the DoIP specification and allows the receiver to determine the specific reason
    the gateway rejected routing activation (e.g., unsupported activation type, already
    connected, denied by security).

    The ``nack_code`` field is part of the serialized error structure and propagates
    automatically to the SOVD response parameters.


.. arch:: Communication Timeout Context
    :id: arch~comm-error-timeout-context
    :status: draft

    Timeout failures carry a ``TimeoutContext`` struct consisting of a map of communication
    parameter names to their active values and units, and the elapsed time at the point of
    failure.

    The map is populated with the communication parameters relevant to the failed phase:

    * For ``AckReception`` timeouts: the DoIP parameters governing ACK/NACK timeout and
      retry behavior, as defined in :need:`req~doip-communication-parameters`.
    * For ``ResponseReception`` timeouts: the UDS parameters governing response timeout
      behavior, as defined in :need:`req~uds-communication-parameters` and
      :need:`req~uds-request-response`.

    ``TimeoutContext`` derives ``Serialize`` so that all map entries are automatically
    available as SOVD response parameters.

    .. uml::

        @startuml
        class TimeoutContext {
            +params: Map<String, ValueUnitPair>
            +elapsed_ms: u64
        }

        class CommunicationError {
            +phase: ConnectionPhase
            +context: ConnectionContext
            +timeout: TimeoutContext [0..1]
            +message: String
        }

        CommunicationError *-- ConnectionPhase
        CommunicationError *-- ConnectionContext
        CommunicationError "1" *-- "0..1" TimeoutContext
        @enduml


Conversion Errors
-----------------

.. arch:: Conversion Error Type
    :id: arch~conversion-error-type
    :status: draft

    A ``ConversionError`` type is defined in the shared interfaces crate to represent a failure
    during encoding or decoding of diagnostic data. It carries:

    * ``field_path`` -- dot-separated path identifying the parameter or field (e.g.
      ``"EngineSpeed"`` or ``"DtcRecord.status"``).
    * ``raw_value`` -- string representation of the raw value that could not be converted, when
      available (e.g. the raw byte sequence or the out-of-range integer).
    * ``reason`` -- human-readable description of why conversion failed (e.g. "value 0xFF is
      outside the defined scale range [0, 200]").

    ``ConversionError`` derives ``Serialize`` so that all fields are available as SOVD response
    parameters.

    .. uml::

        @startuml
        class ConversionError {
            +field_path: String
            +raw_value: Option<String>
            +reason: String
        }
        @enduml


.. arch:: Conversion to Payload Errors
    :id: arch~conversion-to-payload-type
    :status: draft

    The result of encoding a SOVD API request into a UDS byte payload is represented as a
    ``Result<ServicePayload, ConversionToPayloadError>``. The ``ConversionToPayloadError`` variant
    carries a ``ConversionError`` allowing the caller to return a targeted ``BadRequest`` response
    to the SOVD client without treating all encoding failures as generic internal errors.

    The ``ConversionError`` in this context always includes the ``field_path`` corresponding to
    the SOVD API parameter name and the ``reason`` describing the encoding constraint that was
    violated.


.. arch:: Conversion Response Type
    :id: arch~conversion-from-payload-errors
    :status: draft

    The result of decoding a UDS byte payload into a SOVD API JSON value is represented as a
    ``ConversionResponse`` that separates successfully decoded data from field-level errors:

    * ``data`` -- the JSON value containing all fields that were decoded successfully.
    * ``errors`` -- a list of ``ConversionFromPayloadError`` values, one per field that could
      not be decoded. ``ConversionFromPayloadError`` wraps ``ConversionError``.

    Both ``data`` and ``errors`` may be non-empty in the same response (partial success). The
    SOVD layer inspects ``errors`` and, if non-empty, includes them in the API response's
    ``errors`` field, while still returning the successfully decoded ``data`` as the response body.

    If there's only a single entry in `errors`, and no data in `data`, the CDA shall respond with
    HTTP error code 502, and report the error as SOVD error.

    .. uml::

        @startuml
        class ConversionResponse {
            +data: JsonValue
            +errors: Vec<ConversionFromPayloadError>
        }

        ConversionResponse *-- ConversionFromPayloadError
        ConversionFromPayloadError *-- ConversionError
        @enduml


System Errors
-------------

.. arch:: Database Error Type
    :id: arch~system-error-database
    :status: draft

    Database access errors are represented by a ``DatabaseError`` enum (referred to as
    ``MddError`` in the codebase) with the following variants:

    * ``Io(String)`` -- an I/O failure occurred reading the database file; carries the OS error
      description.
    * ``InvalidFormat(String)`` -- the file is not a valid MDD/FlatBuffers container; carries the
      format violation description.
    * ``Parsing(String)`` -- the structure is readable but a field cannot be semantically
      interpreted; carries the field name and reason.
    * ``MissingData(String)`` -- a required definition is absent from the database; carries the
      identifier of the missing item.
    * ``InvalidParameter(String)`` -- a named item does not exist in the currently loaded
      database; carries the parameter name.

    These variants cover the full lifecycle of database access from file reading through semantic
    interpretation, allowing the SOVD layer to map them to appropriate HTTP responses
    (``500 Internal Server Error`` for I/O and format issues; ``404 Not Found`` for
    ``InvalidParameter``).


.. arch:: Storage Error Type
    :id: arch~system-error-storage
    :status: draft

    Storage operation errors are represented by a ``StorageError`` enum with the following
    variants:

    * ``CollectionNotFound(String)`` -- the requested collection does not exist; carries the
      collection name.
    * ``KeyNotFound(String)`` -- the requested key does not exist in the collection; carries the
      key.
    * ``PermissionDenied(String)`` -- the operation was denied by the storage backend.
    * ``NoSpaceLeft(String)`` -- the storage medium has insufficient space.
    * ``Io(io::Error)`` -- an underlying I/O operation failed; wraps the OS error.
    * ``Corruption(String)`` -- the stored data is corrupted beyond automatic recovery; the
      affected data should be considered unusable.
    * ``TransactionError(String)`` -- a transaction conflict or constraint prevented the
      operation.
