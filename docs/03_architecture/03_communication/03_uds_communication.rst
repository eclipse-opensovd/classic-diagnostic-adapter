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

.. _architecture_uds_communication:

UDS Communication
-----------------

The UDS (Unified Diagnostic Services) application layer sits above the transport
layer and implements the request-response protocol defined in ISO 14229. It handles
service payload construction, response matching, negative response code processing,
tester present session keepalive, and functional group communication.

Communication parameters control timing, retry behavior, and tester present generation.
These are sourced from the diagnostic database (MDD files) and may vary per logical link.


Communication Parameters
^^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: UDS Communication Parameters
    :id: arch~uds-communication-parameters
    :status: draft

    The UDS application layer is parameterized through a set of communication parameters
    (COM parameters) that control response timeouts, NRC handling policies, and tester
    present behavior. These parameters are sourced from the diagnostic database (MDD files)
    and can vary per logical link.

    **Response Timing Parameters**

    .. list-table::
       :header-rows: 1
       :widths: 25 40 15 20

       * - Name
         - Function
         - Default value
         - Comment
       * - CP_P6Max
         - Timeout after sending a successful request, for the complete reception of the response message (in uS)
         - 1000000
         - In case of a timeout, CP_RepeatReqCountApp has to be used to retry until exhausted, or a completion timeout is reached
       * - CP_P6Star
         - Enhanced timeout after receiving a NRC 0x78 to wait for the complete reception of the response message (in uS)
         - 1000000
         -
       * - CP_RepeatReqCountApp
         - Repetition of last request in case of timeout, transmission or receive error
         - 2
         - Only applies to application layer messages

    **NRC Handling Parameters**

    .. list-table::
       :header-rows: 1
       :widths: 25 40 15 20

       * - Name
         - Function
         - Default value
         - Comment
       * - CP_RC21Handling
         - Repetition mode in case of NRC 21
         - Continue until RC21 timeout
         - | 0 = Disabled
           | 1 = Continue handling negative responses until CP_RC21CompletionTimeout
           | 2 = Continue handling unlimited
       * - CP_RC21CompletionTimeout
         - Time period the tester accepts for repeated NRC 0x21 and retries, while waiting for a positive response in uS
         - 25000000
         -
       * - CP_RC21RequestTime
         - Time between a NRC 0x21 and the retransmission of the same request (in uS)
         - 200000
         -
       * - CP_RC78Handling
         - Repetition mode in case of NRC 78
         - Continue until RC78 timeout
         - | 0 = Disabled
           | 1 = Continue handling negative responses until CP_RC78CompletionTimeout
           | 2 = Continue handling unlimited
       * - CP_RC78CompletionTimeout
         - Time period the tester accepts for repeated NRC 0x78, and waits for a positive response (in uS)
         - 25000000
         -
       * - CP_RC94Handling
         - Repetition mode in case of NRC 94
         - Continue until RC94 timeout
         - | 0 = Disabled
           | 1 = Continue handling negative responses until CP_RC94CompletionTimeout
           | 2 = Continue handling unlimited
       * - CP_RC94CompletionTimeout
         - Time period the tester accepts for repeated NRC 0x94, and waits for a positive response (in uS)
         - 25000000
         -
       * - CP_RC94RequestTime
         - Time between a NRC 0x94 and the retransmission of the same request (in uS)
         - 200000
         -

    **Tester Present Parameters**

    .. list-table::
       :header-rows: 1
       :widths: 25 40 15 20

       * - Name
         - Function
         - Default value
         - Comment
       * - CP_TesterPresentHandling
         - Define Tester Present generation
         - Enabled
         - | 0 = Do not generate
           | 1 = Generate Tester Present Messages
       * - CP_TesterPresentAddrMode
         - Addressing mode for sending Tester Present
         - Physical
         - | 0 = Physical
           | 1 = Functional, not relevant in CDA case
       * - CP_TesterPresentReqResp
         - Define expectation for Tester Present responses
         - Response expected
         - | 0 = No response expected
           | 1 = Response expected
       * - CP_TesterPresentSendType
         - Define condition for sending tester present
         - On idle
         - | 0 = Fixed periodic
           | 1 = When bus has been idle (Interval defined by CP_TesterPresentTime)
       * - CP_TesterPresentMessage
         - Message to be sent for tester present
         - 3E00
         -
       * - CP_TesterPresentExpPosResp
         - Expected positive response (if required)
         - 7E00
         -
       * - CP_TesterPresentExpNegResp
         - Expected negative response (if required)
         - 7F3E
         - A tester present error should be reported in the log, tester present sending should be continued
       * - CP_TesterPresentTime
         - Timing interval for tester present messages in uS
         - 2000000
         -

    .. note::

       When these parameters are sourced from MDD files, multiple files could define
       different values for the same logical address due to duplicated logical addresses.


Request-Response Flow
^^^^^^^^^^^^^^^^^^^^^^

.. arch:: UDS Request-Response Flow
    :id: arch~uds-request-response
    :status: draft

    The UDS application layer implements the request-response flow using per-ECU
    semaphores for serialization, a SID-specific lookup table for response matching,
    and a layered retry strategy split between the UDS and transport layers.

    **Per-ECU Semaphore**

    A semaphore with a permit count of 1 is allocated per ECU logical address. Because
    the key is the logical address, ECUs that share a logical address (e.g., before
    variant detection) implicitly share the same semaphore. The semaphore is acquired
    before the request is sent and held for the entire send-and-receive cycle, including
    any NRC-driven waiting or retransmission. It is released only after the final response
    is received or an error occurs.

    **Request Transmission**

    The UDS layer constructs a payload containing the tester source address, target ECU
    address, and UDS request data. This payload is passed to the selected transport for
    transmission. Transport-specific transmission failures are returned to the UDS layer.

    **Response Matching Algorithm**

    Before sending, the UDS layer extracts a prefix of the request payload whose length
    is determined by a SID-to-length lookup table. This prefix is used to match the
    eventual response:

    .. list-table:: Response match length by SID
       :header-rows: 1
       :widths: 10 10 40

       * - SID
         - Length
         - Description
       * - ``0x14``
         - 1
         - ClearDiagnosticInformation (SID only)
       * - ``0x22``
         - 3
         - ReadDataByIdentifier (SID + 2-byte DID)
       * - ``0x2E``
         - 3
         - WriteDataByIdentifier (SID + 2-byte DID)
       * - ``0x31``
         - 4
         - RoutineControl (SID + sub-function + 2-byte RID)
       * - ``0x34``
         - 1
         - RequestDownload (SID only)
       * - ``0x35``
         - 1
         - RequestUpload (SID only)
       * - ``0x37``
         - 1
         - RequestTransferExit (SID only)
       * - default
         - 2
         - SID + sub-function byte (or similar)

    For a positive response, the first byte equals the sent SID plus ``0x40`` (ISO 14229
    positive response bitmask) and the subsequent bytes up to the match length equal the
    corresponding bytes of the original request. If the request payload is shorter than
    the SID-specific match length, the match is performed only up to the available payload
    length. For a negative response, the first byte is ``0x7F`` and the second byte
    equals the sent SID.

    NRC 0x78, 0x21, and 0x94 are classified at the transport boundary by the shared
    ``pending_nrc_from_raw()`` function into typed ``TransportResponse::Pending(PendingNrc)``
    variants (``ResponsePending``, ``BusyRepeatRequest``, ``TemporarilyNotAvailable``).
    This classification runs in both the DoIP transport (``doip_event_to_transport()``,
    ``cda-comm-doip/src/lib.rs``) and the CAN transport (``exchange.read_response()``,
    ``cda-comm-can/src/gateway/mod.rs``), ensuring identical behaviour across all
    transports. These typed variants are then processed by the NRC handling logic
    (see :need:`arch~uds-nrc-handling`) before SID matching is applied to the final
    response. All other NRCs flow through as ``TransportResponse::UdsResponse`` final
    responses without transport-level interception.

    **Timeout and Retry Strategy**

    The caller may optionally override the default response timeout. When NRC 0x78 is
    received, the active timeout switches from ``CP_P6Max`` to ``CP_P6Star``. Application-
    layer retries (``CP_RepeatReqCountApp``) are independent of any transport-level
    retries configured by the selected transport.

    .. uml::
        :caption: UDS Request-Response Flow

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "Caller" as Caller
        participant "CDA\n(UDS Layer)" as UDS
        participant "Transport\n(DoIP or CAN)" as Transport
        participant "ECU" as ECU

        == Request ==
        Caller -> UDS: UDS request (service, payload)
        activate UDS

        UDS -> UDS: Acquire per-ECU\nsemaphore (by logical addr)
        note right: 10s timeout\nfor acquisition

        UDS -> UDS: Extract request prefix\nfor response matching\n(length varies by SID)

        UDS -> Transport: ServicePayload\n[tester_addr, ecu_addr, data]
        Transport -> ECU: Transport request

        == Response Matching ==
        ECU --> Transport: UDS response
        Transport --> UDS: TransportResponse

        alt Positive response (SID + 0x40 + echoed prefix)
            UDS -> UDS: Prefix match confirmed
            UDS --> Caller: Response data
        else Negative response (0x7F + SID)
            UDS -> UDS: SID match confirmed
            UDS --> Caller: Negative response
        else Unmatched response
            UDS -> UDS: Log warning, discard
            UDS -> UDS: Continue waiting\nfor matching response
        end

        UDS -> UDS: Release per-ECU\nsemaphore
        deactivate UDS
        @enduml


NRC Handling
^^^^^^^^^^^^

.. arch:: UDS NRC Handling
    :id: arch~uds-nrc-handling
    :status: draft

    The UDS application layer implements a dual-loop architecture for handling Negative
    Response Codes (NRCs). The outer loop handles retransmission (for NRC 0x21 and 0x94),
    while the inner loop handles continued waiting (for NRC 0x78). Each NRC type has an
    independent handling policy and timing configuration.

    **Dual-Loop Architecture**

    - **Outer loop** (``'send``): Transmits the UDS request to the selected transport. On NRC 0x21
      (Busy, Repeat Request) or NRC 0x94 (Temporarily Not Available), control returns to
      this loop after a configured delay, causing the request to be retransmitted.
    - **Inner loop** (``'read_uds_messages``): Waits for responses from the selected transport. On
      NRC 0x78 (Response Pending), the timeout is extended and the loop continues waiting
      without retransmission.

    **NRC 0x78 -- Response Pending**

    When the ECU signals NRC 0x78, it has accepted the request but needs more time. The
    CDA switches to the enhanced timeout ``CP_P6Star`` and continues waiting in the inner
    loop. The handling policy ``CP_RC78Handling`` determines behavior:

    - **Disabled (0)**: Do not handle; report as negative response.
    - **Continue until timeout (1)**: Keep waiting until ``CP_RC78CompletionTimeout``.
    - **Continue unlimited (2)**: Keep waiting indefinitely.

    **NRC 0x21 -- Busy, Repeat Request**

    When the ECU signals NRC 0x21, it is temporarily busy. The CDA waits for
    ``CP_RC21RequestTime`` and then retransmits the original request by breaking back to
    the outer loop. The handling policy ``CP_RC21Handling`` determines behavior:

    - **Disabled (0)**: Do not handle; report as negative response.
    - **Continue until timeout (1)**: Retry until ``CP_RC21CompletionTimeout``.
    - **Continue unlimited (2)**: Retry indefinitely.

    **NRC 0x94 -- Temporarily Not Available**

    When the ECU signals NRC 0x94, the requested resource is temporarily unavailable. The
    CDA waits for ``CP_RC94RequestTime`` and then retransmits the original request. The
    handling policy ``CP_RC94Handling`` determines behavior:

    - **Disabled (0)**: Do not handle; report as negative response.
    - **Continue until timeout (1)**: Retry until ``CP_RC94CompletionTimeout``.
    - **Continue unlimited (2)**: Retry indefinitely.

    **NRC Classification**

    NRC 0x78, 0x21, and 0x94 are classified at the transport boundary by the shared
    ``pending_nrc_from_raw()`` function. Both CAN and DoIP transports call this function
    before forwarding a response, classifying the three pending-lifecycle codes into typed
    ``TransportResponse::Pending(PendingNrc)`` variants
    (``ResponsePending``, ``BusyRepeatRequest``, ``TemporarilyNotAvailable``). This
    guarantees identical classification behaviour regardless of the underlying transport.
    All other NRCs are delivered as ``TransportResponse::UdsResponse(ServicePayload)``
    for standard SID-based matching at the UDS service layer.

    .. uml::
        :caption: NRC Data Flow -- End-to-End Classification Pipeline

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam componentStyle rectangle

        title "UDS NRC Classification Pipeline"

        package "Transport Layer" {
          [DoIP TCP Reader\n(try_read)] as DoipRead
          [CAN ISO-TP Reader\n(exchange.read_response)] as CanRead
        }

        package "Receiver / Per-ECU Routing" {
          [DoIP connection_receiver\nBypass TesterPresent NRCs\nRoute by source_address] as DoipRecv
          [CAN Gateway\nExtend ISO-TP deadline\non pending NRC] as CanGw
        }

        package "Shared UDS Boundary\ncda-interfaces/src/uds.rs" {
          (pending_nrc_from_raw) as PendingCheck
          (uds_response_from_raw) as FinalWrap
        }

        package "TransportResponse\necugateway.rs" {
          [TransportResponse::Pending\n{PendingNrc}] as PendingResp
          [TransportResponse::UdsResponse\n{ServicePayload}] as FinalResp
        }

        package "UDS Transport Layer\ncda-comm-uds/src/transport.rs" {
          [send_with_raw_payload\n'read_uds_messages loop] as UdsTransport
        }

        package "UDS Service Layer\ncda-core" {
          [convert_from_uds()\nMap raw bytes to\nDiagServiceResponse] as Convert
          [as_nrc()\nExtract NRC code +\ndescription + SID] as AsNrc
          [extract_nrc_from_raw_data()\nFallback for unmapped\nnegative responses] as ExtractNrc
        }

        DoipRead --> DoipRecv : DiagnosticResponse::Msg
        CanRead --> CanGw : Raw UDS bytes

        DoipRecv --> PendingCheck : data, source_address
        CanGw --> PendingCheck : data, source_address

        PendingCheck --> PendingResp : [YES] 0x78 / 0x21 / 0x94
        PendingCheck --> FinalWrap : [NO]

        FinalWrap --> FinalResp : ServicePayload

        PendingResp --> UdsTransport : Retry or extend wait

        FinalResp --> UdsTransport : Final response

        UdsTransport --> Convert : Ok(ServicePayload)
        Convert --> AsNrc : DiagServiceResponse.as_nrc()
        Convert --> ExtractNrc : Fallback when\nno mapped response data

        note bottom of DoipRecv
            TesterPresent NRCs (7F 3E xx)
            are intercepted in connections.rs
            before any per-ECU routing.
        end note

        note bottom of CanGw
            CAN extends the ISO-TP
            socket deadline when a
            pending NRC arrives, then
            forwards to the same
            classification function.
        end note

        note bottom of PendingResp
            0x78 ResponsePending:
              extend timeout (CP_P6Star)
              keep waiting in inner loop
            0x21 BusyRepeatRequest:
              sleep CP_RC21RequestTime
              retransmit via outer loop
            0x94 TemporarilyNotAvailable:
              sleep CP_RC94RequestTime
              retransmit via outer loop
        end note

        note bottom of FinalResp
            Carries all non-pending responses:
            - Positive responses (SID | 0x40)
            - Non-pending NRCs (0x22, 0x31, 0x33, ...)
        end note
        @enduml

    **Policy Validation**

    Before acting on any NRC, the CDA validates the handling policy and checks the elapsed
    time against the configured completion timeout. If the policy is disabled or the timeout
    has been exceeded, the NRC is reported to the caller as a terminal negative response.

    .. uml::
        :caption: UDS NRC Handling -- Dual-Loop Architecture

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "CDA\n(UDS Layer)" as UDS
        participant "Transport\n(DoIP or CAN)" as Transport
        participant "ECU" as ECU

        == Outer Loop ('send): Transmit Request ==
        UDS -> Transport: UDS request
        Transport -> ECU: Transport request

        == Inner Loop ('read_uds_messages): Await Response ==

        alt NRC 0x78 (Response Pending)
            ECU --> Transport: NRC 0x78
            Transport --> UDS: ResponsePending
            note right of UDS: Switch timeout to CP_P6Star\nValidate CP_RC78Handling policy\nStay in inner loop (no retransmit)
            ECU --> Transport: Final response
            Transport --> UDS: UDS response

        else NRC 0x21 (Busy, Repeat Request)
            ECU --> Transport: NRC 0x21
            Transport --> UDS: BusyRepeatRequest
            note right of UDS: Validate CP_RC21Handling policy\nWait CP_RC21RequestTime
            UDS -> UDS: Break to outer loop\n(retransmit request)
            UDS -> Transport: UDS request (retransmit)
            Transport -> ECU: Transport request
            ECU --> Transport: Final response
            Transport --> UDS: UDS response

        else NRC 0x94 (Temporarily Not Available)
            ECU --> Transport: NRC 0x94
            Transport --> UDS: TemporarilyNotAvailable
            note right of UDS: Validate CP_RC94Handling policy\nWait CP_RC94RequestTime
            UDS -> UDS: Break to outer loop\n(retransmit request)
            UDS -> Transport: UDS request (retransmit)
            Transport -> ECU: Transport request
            ECU --> Transport: Final response
            Transport --> UDS: UDS response

        else Direct Response
            ECU --> Transport: UDS response
            Transport --> UDS: UDS response
            note right of UDS: Within CP_P6Max
        end
        @enduml

    The following diagram shows the complete lifecycle of a UDS response byte
    from the ECU, through the transport classification, through the UDS retry
    logic, and finally to the service-layer NRC interpretation:

    .. uml::
        :caption: Complete NRC Response Lifecycle

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "ECU" as ECU
        participant "Transport\n(DoIP / CAN)" as Transport
        participant "Classification\npending_nrc_from_raw()" as Classify
        participant "UDS Transport\nsend_with_raw_payload()" as UdsTx
        participant "UDS Service\nconvert_from_uds()" as UdsSvc

        == ECU sends raw UDS response ==
        ECU -> Transport: Raw bytes\n[0x7F, SID, NRC]

        == Transport classification ==
        Transport -> Classify: data, source_address

        alt Pending NRC (0x78 / 0x21 / 0x94)
            Classify -> Transport: TransportResponse::Pending(PendingNrc)
            Transport -> UdsTx: PendingNrc

            group Dual-Loop NRC Handling
                alt 0x78 (ResponsePending)
                    UdsTx -> UdsTx: Switch timeout to CP_P6Star
                    note right: Stay in inner loop,\nwait for final response
                    UdsTx -> Transport: Continue reading
                    Transport -> ECU: (no retransmit)
                    ECU -> Transport: Final response
                    Transport -> UdsTx: TransportResponse::UdsResponse

                else 0x21 (BusyRepeatRequest)
                    UdsTx -> UdsTx: Validate CP_RC21Handling
                    note right: Sleep CP_RC21RequestTime,\nthen retransmit
                    UdsTx -> Transport: Retransmit request
                    Transport -> ECU: Diagnostic Message
                    ECU -> Transport: Final response
                    Transport -> UdsTx: TransportResponse::UdsResponse

                else 0x94 (TemporarilyNotAvailable)
                    UdsTx -> UdsTx: Validate CP_RC94Handling
                    note right: Sleep CP_RC94RequestTime,\nthen retransmit
                    UdsTx -> Transport: Retransmit request
                    Transport -> ECU: Diagnostic Message
                    ECU -> Transport: Final response
                    Transport -> UdsTx: TransportResponse::UdsResponse
                end
            end

        else Non-pending NRC or positive response
            Classify -> Transport: TransportResponse::UdsResponse(ServicePayload)
            Transport -> UdsTx: ServicePayload {data, addresses}
            note right: Direct final response,\nno retry needed
        end

        == UDS Service Layer Interpretation ==
        UdsTx -> UdsSvc: Ok(ServicePayload)

        alt Positive response
            UdsSvc -> UdsSvc: Match by SID + 0x40
            UdsSvc --> Caller: Decoded response
        else Negative response (NRC)
            UdsSvc -> UdsSvc: as_nrc() or\nextract_nrc_from_raw_data()
            note right: Returns MappedNRC\n{code, description, SID}
            UdsSvc --> Caller: MappedNRC result
        end
        @enduml


Tester Present
^^^^^^^^^^^^^^

.. arch:: UDS Tester Present
    :id: arch~uds-tester-present
    :status: draft

    The CDA maintains active diagnostic sessions with ECUs by periodically sending UDS
    Tester Present (``0x3E``) messages. Tester present generation is driven by the lock
    lifecycle: tasks are started when locks are acquired and stopped when locks are
    released.

    **Lock-Driven Lifecycle**

    Tester present tasks are tied to the SOVD lock mechanism:

    - **Component (ECU) lock**: Acquiring a lock on a single ECU starts a **physical**
      tester present task for that ECU, sending to the ECU's physical address.
    - **Functional group lock**: Acquiring a lock on a functional group starts
      **functional** tester present tasks for each gateway ECU in the group, sending to
      each gateway's functional address.
    - **Vehicle lock**: Does not start any tester present tasks.

    If ``CP_TesterPresentHandling`` is set to "Disabled" (0) for an ECU, no tester present
    task is started for that ECU regardless of the lock type.

    When a lock is released, the associated tester present tasks are stopped and the
    ECU's session and security access state are reset.

    **Duplicate Prevention**

    Active tester present tasks are tracked in a HashMap keyed by ECU name. Before
    starting a new task, the system checks whether a task already exists for that ECU.
    Only one tester present task (physical or functional) can be active per ECU at any
    time.

    **Task Implementation**

    Each tester present task is a background async task that runs a periodic loop:

    1. Wait for the configured interval (``CP_TesterPresentTime``, default 2 seconds).
    2. Construct the tester present message from ``CP_TesterPresentMessage`` and send it
       through the standard UDS send path.
    3. If ``CP_TesterPresentReqResp`` indicates a response is expected, await and validate
       the response.
    4. If sending takes longer than the interval, log an error and continue.

    The interval uses a delay-on-miss strategy: if a tick is missed (e.g., due to slow
    sending), the next tick is delayed rather than bursting to catch up.

    **Message Format**

    The tester present message is constructed from ``CP_TesterPresentMessage`` (default:
    ``[0x3E, 0x00]``). When ``CP_TesterPresentReqResp`` indicates no response is expected,
    the suppress-positive-response bit (``0x80``) is OR-ed onto the sub-function byte,
    producing ``[0x3E, 0x80]``. In this mode the message is sent with
    ``expect_response = false``, meaning the CDA does not await a UDS-level response.
    When a response is expected,
    the message is sent as-is and the CDA validates the response against
    ``CP_TesterPresentExpPosResp`` and ``CP_TesterPresentExpNegResp``.

    The target address depends on the tester present type:

    - **Physical** (ECU lock): Sent to the ECU's physical logical address.
    - **Functional** (functional group lock): Sent to the ECU's functional logical address.

    **Functional Group Resolution**

    When starting functional tester present, the system resolves the functional group to
    its member ECUs and starts individual tester present tasks for each **gateway** ECU
    in the group (ECUs whose logical address equals their gateway address). Each gateway
    receives its own dedicated background task sending to that gateway's functional address.

    **Error Handling**

    - Tester present NRCs received from the transport layer are logged at debug level but
      do not cause task termination. The tester present task continues sending on the next
      interval.
    - Send failures (e.g., connection loss) are handled by the standard UDS send path,
      which may trigger transport-level connection recovery. The tester present task
      continues attempting to send on subsequent intervals.

    **COM Parameter Usage**

    All tester present COM parameters are loaded from the diagnostic database per ECU. The
    tester present task evaluates them as follows:

    - ``CP_TesterPresentTime`` -- The sending interval in microseconds (default:
      2,000,000 µS = 2 s). The periodic loop waits this duration between sends.
    - ``CP_TesterPresentHandling`` -- Controls whether tester present messages are
      generated. When set to "Disabled" (0), no tester present task shall be started for
      the ECU even when a lock is held. When set to "Enabled" (1, default), tester present
      messages are generated normally.
    - ``CP_TesterPresentAddrMode`` -- Addressing mode for tester present messages. When
      set to "Physical" (0, default), messages are sent to the ECU's physical logical
      address. When set to "Functional" (1), messages are sent to the ECU's functional
      logical address. The lock type takes precedence: functional group locks always use
      functional addressing regardless of this parameter.
    - ``CP_TesterPresentReqResp`` -- Whether a UDS-level response is expected. When set
      to "No response expected" (0), the suppress-positive-response bit (sub-function
      ``0x80``) is set on the message and the task does not await a UDS-level response.
      When set to "Response expected" (1, default), the task awaits a response and
      validates it against the expected positive and negative response patterns.
    - ``CP_TesterPresentSendType`` -- Sending strategy. When set to "Fixed periodic" (0),
      tester present messages are sent at the configured interval regardless of other bus
      activity. When set to "On idle" (1, default), tester present messages are sent only
      when no other diagnostic communication has occurred on the connection within the
      interval defined by ``CP_TesterPresentTime``.
    - ``CP_TesterPresentMessage`` -- The raw message bytes for the tester present request
      (default: ``[0x3E, 0x00]``). When ``CP_TesterPresentReqResp`` indicates no response
      expected, the suppress-positive-response bit is OR-ed onto the sub-function byte
      (e.g., ``[0x3E, 0x00]`` becomes ``[0x3E, 0x80]``).
    - ``CP_TesterPresentExpPosResp`` -- Expected positive response bytes (default:
      ``[0x7E, 0x00]``). Used to validate the ECU response when ``CP_TesterPresentReqResp``
      indicates a response is expected.
    - ``CP_TesterPresentExpNegResp`` -- Expected negative response prefix (default:
      ``[0x7F, 0x3E]``). When a negative response is received, it is logged but does not
      cause the tester present task to stop.

    .. note::

        The current implementation uses only ``CP_TesterPresentTime`` at runtime. All other
        COM parameters are loaded from the database but are not yet evaluated. The
        implementation currently hardcodes the message as ``[0x3E, 0x80]`` (suppress
        positive response), uses fixed periodic sending, and always generates tester present
        when a lock is held.

    .. uml::
        :caption: Tester Present -- Component Lock

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "SOVD\nLock Manager" as LM
        participant "CDA\n(UDS Layer)" as UDS
        participant "Transport\n(DoIP / CAN)" as Transport
        participant "ECU" as ECU

        LM -> UDS: acquire component lock (ECU)
        UDS -> UDS: check_tester_present_active(ECU)
        note right: No existing task found

        UDS -> UDS: Start physical TP task\n(interval = CP_TesterPresentTime)
        activate UDS #LightBlue

        loop Every CP_TesterPresentTime
            UDS -> Transport: [0x3E, 0x00] to ECU\nphysical address
            Transport -> ECU: Tester Present
            ECU --> Transport: [0x7E, 0x00]
            Transport --> UDS: Tester Present Response
        end

        note over LM, ECU: This shows the typical flow.\nActual message content, timing, and response\nhandling depend on the CP_TesterPresent*\ncommunication parameters.

        LM -> UDS: release component lock (ECU)
        UDS -> UDS: Stop physical TP\ntask for ECU
        deactivate UDS
        @enduml

    .. uml::
        :caption: Tester Present -- Functional Group Lock

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "SOVD\nLock Manager" as LM
        participant "CDA\n(UDS Layer)" as UDS
        participant "Transport\n(DoIP / CAN)" as Transport
        participant "ECU A\n(Gateway)" as ECUA

        LM -> UDS: acquire functional group lock
        UDS -> UDS: Resolve group to\ngateway ECUs

        UDS -> UDS: Start functional TP task\nfor ECU A (gateway)
        activate UDS #LightGreen

        loop Every CP_TesterPresentTime
            UDS -> Transport: [0x3E, 0x80] to ECU A\nfunctional address
            Transport -> ECUA: Tester Present
            ECUA --> Transport: ACK
        end

        LM -> UDS: release functional group lock
        UDS -> UDS: Stop functional TP\ntask for ECU A
        deactivate UDS
        @enduml


Functional Communication
^^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: UDS Functional Communication
    :id: arch~uds-functional-communication
    :status: draft

    The CDA supports functional group communication, where a single UDS request is sent
    to multiple ECUs simultaneously using functional addressing. ECUs are grouped by their
    gateway, and each gateway receives one functional request with responses collected from
    all ECUs behind it in parallel.

    **Functional Group Resolution**

    A functional group is resolved to its member ECUs from the diagnostic database. The
    following filters are applied:

    - Only physical ECUs are included (virtual/description ECUs are excluded).
    - Only ECUs that are currently online (detected during vehicle identification) are
      included.

    **Grouping by Gateway**

    ECUs in the functional group are grouped by their gateway logical address:

    - An ECU whose logical address equals its gateway address is the **gateway ECU** itself.
      It provides the UDS parameters, tester address, and functional address for its group.
    - ECUs whose logical address differs from their gateway address are placed **behind**
      the corresponding gateway.

    Each gateway group produces one diagnostic request targeted at the gateway's functional
    address (e.g., ``CP_DoIPLogicalFunctionalAddress`` for DoIP gateways).

    **Parallel Gateway Communication**

    When a functional group spans multiple gateways, the CDA sends to all gateways in
    parallel. For each gateway, the flow is:

    1. Construct a ``ServicePayload`` with the gateway's tester address as source and the
       functional address as target.
    2. Send the diagnostic message once to the gateway via the transport layer.
    3. Wait for responses from all expected ECUs behind the gateway, in parallel.

    **Response Collection**

    After the gateway forwards the functional request, the transport layer
    demultiplexes incoming responses by source address. Each ECU behind the gateway has its
    own receive channel, allowing responses to be collected concurrently. ECUs that do not
    respond within ``CP_P6Max`` are reported as individual timeout errors.

    **No NRC Handling on Functional Path**

    Unlike physical (unicast) communication, the functional communication path does not
    implement UDS-level NRC 0x21/0x78/0x94 handling. NRC responses on the functional path
    are returned as-is to the caller.

    .. uml::
        :caption: UDS Functional Communication Flow

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "Caller" as Caller
        participant "CDA\n(UDS Layer)" as UDS
        participant "Transport\n(DoIP Gateway 1)" as GW1
        participant "ECU A\n(behind GW1)" as ECUA
        participant "ECU B\n(behind GW1)" as ECUB
        participant "Transport\n(DoIP Gateway 2)" as GW2
        participant "ECU C\n(behind GW2)" as ECUC

        == Resolve Functional Group ==
        Caller -> UDS: Functional group request
        activate UDS
        UDS -> UDS: Resolve group to\nonline ECUs
        UDS -> UDS: Group ECUs by\ngateway address

        == Parallel Send to Gateways ==
        par Gateway 1
            UDS -> GW1: Diagnostic Message\n[functional_addr, UDS request]
            GW1 --> UDS: ACK

            par Collect Responses
                GW1 -> ECUA: Forward UDS request
                GW1 -> ECUB: Forward UDS request
                ECUA --> GW1: UDS response
                GW1 --> UDS: Response (ECU A)
                ECUB --> GW1: UDS response
                GW1 --> UDS: Response (ECU B)
            end

        else Gateway 2
            UDS -> GW2: Diagnostic Message\n[functional_addr, UDS request]
            GW2 --> UDS: ACK

            GW2 -> ECUC: Forward UDS request
            ECUC --> GW2: UDS response
            GW2 --> UDS: Response (ECU C)
        end

        UDS --> Caller: Aggregated results\n{ECU A: response, ECU B: response,\nECU C: response}
        deactivate UDS

        note right of Caller: ECUs that do not respond\nwithin CP_P6Max are reported\nas individual timeouts
        @enduml
