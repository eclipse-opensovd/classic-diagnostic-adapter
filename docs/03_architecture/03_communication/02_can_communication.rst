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

.. _architecture_can_communication:

CAN Communication
-----------------

The CAN gateway transports UDS messages over ISO-TP (ISO 15765-2). It supports
physical UDS communication with ECUs using SocketCAN ISO-TP sockets. The ``can``
feature is required; on non-Linux systems it additionally requires the
``can-socketcand`` feature.


Addressing And Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: CAN Addressing And Configuration
    :id: arch~can-addressing-configuration
    :status: draft

    Each physical ECU connection requires a request CAN ID (tester to ECU) and a
    response CAN ID (ECU to tester). The gateway accepts 11-bit standard IDs and
    29-bit extended IDs. Addressing is resolved in this order:

    1. A ``[[can.ecu_mappings]]`` configuration entry for the ECU.
    2. The ECU MDD communication parameters ``CP_CanPhysReqId`` and
       ``CP_CanRespUSDTId``. The MDD ``CP_UniqueRespIdTable`` takes precedence
       when it contains the corresponding values.

    Explicit configuration overrides MDD values. An ECU with no complete request/response
    pair has no CAN connection. The gateway rejects unusable configuration, including an
    empty usable mapping set, out-of-range IDs, and IDs reserved for the functional
    TesterPresent broadcast.

Physical ISO-TP Exchange
^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: CAN Physical ISO-TP Exchange
    :id: arch~can-physical-isotp-exchange
    :status: draft

    The gateway opens a fresh ISO-TP socket for each physical request. Its receive ID is
    the ECU response ID and its transmit ID is the ECU request ID. TX padding is enabled
    with ``0x00`` so the gateway can communicate with ECUs that require padded eight-byte
    CAN frames. The socket stays open for the entire exchange, which is required to receive
    a final response after an NRC ``0x78``.

    The CAN bus is shared. Before forwarding a terminal response, the gateway verifies that
    its response SID belongs to the sent request. Frames that do not match are discarded and
    do not extend the receive deadline. This avoids accepting unrelated traffic, including a
    physical negative response to a functional TesterPresent broadcast.

    .. uml::
        :caption: CAN Physical UDS Exchange

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "UDS Layer" as UDS
        participant "CAN Gateway" as CAN
        participant "ISO-TP Socket\n(request ID / response ID)" as ISOTP
        participant "ECU" as ECU

        UDS -> CAN: ServicePayload
        CAN -> ISOTP: Open socket and send UDS request
        ISOTP -> ECU: ISO-TP request

        loop Until terminal response or deadline
            ECU --> ISOTP: ISO-TP response
            ISOTP --> CAN: Reassembled UDS bytes

            alt Pending NRC (7F SID 78 / 21 / 94)
                CAN -> CAN: Extend transport deadline
                CAN --> UDS: TransportResponse::Pending
            else Matching final response
                CAN --> UDS: TransportResponse::UdsResponse
                CAN -> ISOTP: Drop socket
            else Unrelated response
                CAN -> CAN: Discard and continue reading
            end
        end
        @enduml


NRC Classification
^^^^^^^^^^^^^^^^^^

.. arch:: CAN NRC Classification
    :id: arch~can-nrc-classification
    :status: draft

    The CAN gateway classifies every incoming UDS response through the shared
    ``pending_nrc_from_raw()`` helper from ``cda-interfaces/src/uds.rs``, identically to
    the DoIP transport. The classification happens inside ``exchange.read_response()``
    (``cda-comm-can/src/gateway/mod.rs``), before request-SID filtering.

    The helper recognizes three pending-lifecycle NRCs -- ``0x78`` (Response Pending), ``0x21``
    (Busy Repeat Request), ``0x94`` (Temporarily Not Available) -- and returns a
    ``TransportResponse::Pending(PendingNrc)`` variant. For all other responses (positive
    or non-pending negative), it returns ``None`` and the gateway wraps them with
    ``uds_response_from_raw()`` into a terminal ``TransportResponse::UdsResponse``.

    When a pending NRC arrives, the gateway extends the ISO-TP socket receive deadline
    (``can.response_timeout_ms``) from the current time and retains the socket. This allows
    the ECU to send the final response within the extended window. The UDS layer owns the
    retry policy: it continues waiting after ``0x78`` and retransmits after ``0x21`` or
    ``0x94`` per the configured ``CP_RC*Handling`` parameters (see
    :need:`arch~uds-nrc-handling`).

    .. uml::
        :caption: CAN NRC Classification Flow

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam componentStyle rectangle

        title "CAN NRC Classification Flow"

        package "ISO-TP Socket" as ISOTP {
          (Raw CAN frames\nreassembled into\nUDS bytes) as Raw
        }

        package "mod.rs: exchange.read_response()" as ReadResp {
          (pending_nrc_from_raw?) as NrcCheck
          (Match SID to\nsent request) as SidMatch
          (uds_response_from_raw) as FinalWrap
        }

        package "TransportResponse" as RespPkg {
          (TransportResponse::Pending\n{PendingNrc}) as Pending
          (TransportResponse::UdsResponse\n{ServicePayload}) as Final
        }

        package "ISO-TP Deadline" as Deadline {
          (Extend receive\ndeadline on\npending NRC) as Extend
        }

        Raw --> NrcCheck : Reassembled UDS bytes

        NrcCheck --> Extend : [YES]\n0x78 / 0x21 / 0x94
        NrcCheck --> SidMatch : [NO]

        Extend --> Pending : TransportResponse::Pending
        SidMatch --> FinalWrap : [matching SID]
        SidMatch --> Raw : [unrelated SID]\ndiscard and continue

        FinalWrap --> Final : TransportResponse::UdsResponse

        note bottom of NrcCheck
            Shared classification using
            pending_nrc_from_raw() from
            cda-interfaces/src/uds.rs.
            Identical logic for both
            CAN and DoIP transports.
        end note

        note bottom of SidMatch
            CAN verifies that the
            response SID belongs to
            the sent request. Frames
            from unrelated ECUs or
            functional broadcasts
            are discarded.
        end note

        note bottom of Extend
            The gateway restarts the
            can.response_timeout_ms
            deadline from the current
            time, keeping the ISO-TP
            socket open for the ECU's
            final response.
        end note

        note bottom of Final
            Carries all non-pending
            responses: positive (SID | 0x40)
            and non-pending NRCs (0x22,
            0x31, 0x33, ...).
        end note
        @enduml

    The classification functions are defined in ``cda-interfaces/src/uds.rs``:

    * ``pending_nrc_from_raw(data, source_address)`` -- recognises ``0x78``/``0x21``/``0x94``
      and returns the corresponding ``PendingNrc`` variant; returns ``None`` for all other
      responses
    * ``uds_response_from_raw(data, source_address, target_address)`` -- wraps any remaining
      response (positive or non-pending negative) into a ``ServicePayload``

    Unlike the DoIP transport, CAN does not intercept TesterPresent NRCs (``0x7F 0x3E xx``)
    at the transport level. The functional TesterPresent broadcast uses a separate path and
    its NRC responses are logged at debug level by the keep-alive task.


Discovery And Keep-Alive
^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: CAN Discovery And Keep-Alive
    :id: arch~can-discovery-keepalive
    :status: draft

    CAN has no connection-establishment event. The gateway probes every configured ECU at
    startup and marks it discovered when any non-empty response is received, including a
    negative response. The default probe is physical ``TesterPresent`` (``3E 00``). Optional
    fallback probes can be configured for ECUs that do not answer this request.

    Undiscovered ECUs are re-probed sequentially every five seconds. A physical request with
    no received frame for at least the probe timeout also removes that ECU from the discovered
    set, allowing the rediscovery task to recover it after wake-up or reboot. An on-demand
    probe is also made when a caller checks a currently undiscovered ECU.

    Independently, the gateway can send ``TesterPresent`` with the
    ``suppressPositiveResponse`` bit (``3E 80``) on the functional broadcast ID to keep ECUs
    awake. It uses ``CP_CanFuncReqId`` when available and otherwise ``0x7DF``. This broadcast
    is a keep-alive only; CAN functional diagnostic requests are not implemented.

    .. uml::
        :caption: CAN Discovery And Rediscovery

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "CAN Gateway" as CAN
        participant "Configured ECU" as ECU
        participant "Variant Detection" as Variant

        == Startup ==
        CAN -> ECU: Physical TesterPresent (3E 00)
        alt ECU answers
            ECU --> CAN: Any non-empty UDS response
            CAN -> Variant: Report discovered ECU
        else No response
            CAN -> CAN: Mark ECU undiscovered
        end

        == Background Rediscovery ==
        loop Every 5 seconds, undiscovered ECUs only
            CAN -> ECU: Configured probe sequence
            alt ECU answers
                ECU --> CAN: Any non-empty UDS response
                CAN -> Variant: Report rediscovered ECU
            end
        end
        @enduml


Functional Communication Limitation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. note::

   ``CanDiagGateway::send_functional()`` currently returns
   ``DiagServiceError::RequestNotSupported``. The functional CAN ID is used only by the
   optional gateway keep-alive broadcast, not to implement functional diagnostic requests.
