.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

Communication
=============


DoIP Communication
------------------

DoIP Communication is described in the ISO 13400 standard. Specific communication
parameters and implementation details will be defined and linked in this document.

The communication parameters depend on the logical link used for the communication,
filtered by configuration and actual ECU detection/availability.


Protocol Versions
^^^^^^^^^^^^^^^^^

.. req:: DoIP Protocol Version Support
    :id: req~doip-protocol-versions
    :links: arch~doip-protocol-versions
    :status: draft

    The CDA shall support the DoIP protocol versions defined in ISO 13400-2.

    The default protocol version shall be ISO 13400-2:2012 (``0x02``). The protocol
    version shall be configurable.

    **Rationale**

    ISO 13400-2:2012 is the most widely deployed version across vehicle platforms.
    Configurable version support ensures compatibility with DoIP entities implementing
    different standard revisions.


Message Framing
^^^^^^^^^^^^^^^

.. req:: DoIP Message Framing
    :id: req~doip-message-framing
    :links: arch~doip-message-framing
    :status: draft

    The CDA shall frame all DoIP messages according to the ISO 13400 header format,
    consisting of:

    - Protocol version (1 byte)
    - Inverse protocol version (1 byte)
    - Payload type (2 bytes, big-endian)
    - Payload length (4 bytes, big-endian)

    The CDA shall support encoding and decoding of the following payload types:

    - Vehicle Identification Request (``0x0001``)
    - Vehicle Identification Request by EID (``0x0002``)
    - Vehicle Identification Request by VIN (``0x0003``)
    - Vehicle Announcement Message (``0x0004``)
    - Routing Activation Request (``0x0005``) and Response (``0x0006``)
    - Alive Check Request (``0x0007``) and Response (``0x0008``)
    - Diagnostic Message (``0x8001``), ACK (``0x8002``), and NACK (``0x8003``)
    - Generic NACK (``0x0000``)

    **Rationale**

    Correct message framing is essential for interoperability with any ISO 13400
    compliant DoIP entity. Supporting the full set of relevant payload types enables
    complete diagnostic communication workflows.


Communication Parameters
^^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: DoIP Communication Parameters
    :id: req~doip-communication-parameters
    :links: arch~doip-communication-parameters
    :status: draft

    The CDA must support configuration of DoIP communication parameters as defined in
    the following table. Parameters are sourced from the diagnostic database (MDD files)
    and may vary per logical link.

    .. list-table:: DoIP Communication parameters
       :header-rows: 1
       :widths: 30 35 15 20

       * - Name
         - Function
         - Default value
         - Comment
       * - CP_DoIPLogicalGatewayAddress
         - Logical address of a DoIP entity. In case of a directly reachable DoIP entity it is equal to CP_DoIPLogicalEcuAddress, otherwise data is sent via this address to the CP_DoIPLogicalEcuAddress
         - 0
         -
       * - CP_DoIPLogicalEcuAddress
         - Logical/Physical address of the ECU
         - 0
         -
       * - CP_DoIPLogicalFunctionalAddress
         - Functional address of the ECU
         - 0
         -
       * - CP_DoIPLogicalTesterAddress
         - Logical address of the tester
         - 0
         -
       * - CP_DoIPNumberOfRetries
         - Number of retries for specific diagnostic message NACKs
         - 3 (for OUT_OF_MEMORY)
         - Retry count is configured per NACK code
       * - CP_DoIPDiagnosticAckTimeout
         - Maximum time the tester waits for an ACK or NACK from the DoIP entity
         - 1s
         -
       * - CP_DoIPRetryPeriod
         - Period between retries after specific NACK conditions are encountered
         - 200ms
         -
       * - CP_DoIPRoutingActivationTimeout
         - Maximum time allowed for the ECU's routing activation response
         - 30s
         -
       * - CP_RepeatReqCountTrans
         - Number of retries in case of a transmission error, receive error, or transport layer timeout
         - 3
         -
       * - CP_DoIPConnectionTimeout
         - Timeout after which a connection attempt should have been successful
         - 30s
         -
       * - CP_DoIPConnectionRetryDelay
         - Delay before attempting to reconnect
         - 5s
         -
       * - CP_DoIPConnectionRetryAttempts
         - Number of attempts to retry connection before giving up
         - 100
         -


Vehicle Identification
^^^^^^^^^^^^^^^^^^^^^^

.. req:: Vehicle Identification
    :id: req~doip-vehicle-identification
    :links: arch~doip-vehicle-identification
    :status: draft

    The CDA shall discover DoIP entities on the network by broadcasting a Vehicle
    Identification Request (VIR) via UDP and processing Vehicle Announcement Message
    (VAM) responses.

    The CDA shall:

    1. Broadcast VIR messages to ``255.255.255.255`` on the configured gateway port
       (default: 13400).
    2. Collect VAM responses within a configurable timeout window.
    3. Filter VAM responses by subnet mask, accepting only responses from IP addresses
       within the tester's configured subnet.
    4. Match discovered DoIP entity logical addresses against known ECUs from the
       diagnostic databases.
    5. Continuously listen for spontaneous VAM broadcasts after initial discovery
       to detect gateways that come online later or reconnect after disconnection.

    .. uml::
        :caption: Vehicle Identification Overview

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "CDA" as CDA
        participant "DoIP Entity" as GW

        == Discovery ==
        CDA -> GW: VIR broadcast via UDP\n(0x0001, to 255.255.255.255:13400)
        GW --> CDA: VAM response via UDP\n(0x0004, [VIN, logical_addr, EID, GID])

        CDA -> CDA: Filter by subnet mask
        CDA -> CDA: Match to known ECUs

        == Continuous Listening ==
        note over CDA: Background listener\nfor spontaneous VAMs
        GW --> CDA: Spontaneous VAM\n(entity online)
        CDA -> CDA: Connect and trigger\nvariant detection
        @enduml

    **Rationale**

    UDP-based discovery enables automatic detection of DoIP entities without
    requiring static IP configuration. Subnet filtering prevents unintended
    communication with entities on unrelated networks. Continuous VAM listening
    ensures the CDA adapts to dynamic network conditions.


Routing Activation
^^^^^^^^^^^^^^^^^^

.. req:: Routing Activation
    :id: req~doip-routing-activation
    :links: arch~doip-routing-activation
    :status: draft

    The CDA shall perform routing activation on each TCP connection before exchanging
    diagnostic messages. The routing activation shall:

    1. Send a Routing Activation Request with the tester's logical address and default
       activation type.
    2. Handle all defined routing activation response codes, including:

       - **Successfully activated** (``0x10``): Proceed with diagnostic communication.
       - **Denied, encrypted TLS required** (``0x07``): Automatically fall back to a
         TLS connection (see :need:`req~doip-tls`) and retry routing activation.
       - **All other denial codes**: Report routing activation failure.

    3. Complete routing activation within ``CP_DoIPRoutingActivationTimeout``.

    **Rationale**

    Routing activation is a mandatory step in the DoIP protocol to register the tester
    with the DoIP entity.


TLS Communication
^^^^^^^^^^^^^^^^^

.. req:: DoIP TLS Communication
    :id: req~doip-tls
    :links: arch~doip-tls
    :status: draft

    The CDA shall support TLS-secured DoIP connections as defined in ISO 13400.

    **TLS Fallback**

    When a DoIP entity denies routing activation with the code
    ``DeniedRequestEncryptedTLSConnection`` (``0x07``), the CDA shall:

    1. Close the plain TCP connection.
    2. Establish a new TCP connection to the configured TLS port (default: 3496).
    3. Perform a TLS handshake.
    4. Re-send the Routing Activation Request over the secured connection.

    **TLS Version**

    - The CDA shall support a minimum TLS version of TLS 1.2.
    - The CDA shall support a maximum TLS version of TLS 1.3.

    The supported versions for DoIP-connections shall be configurable.

    **TLS Ciphers**

    The CDA shall support the following TLS cipher suites.

    *TLS 1.2 Cipher Suites:*

    - ``TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256``
    - ``TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384``
    - ``TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256``
    - ``TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384``
    - ``TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256``
    - ``TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256``

    *TLS 1.3 Cipher Suites:*

    - ``TLS_AES_128_GCM_SHA256``
    - ``TLS_AES_256_GCM_SHA384``
    - ``TLS_CHACHA20_POLY1305_SHA256``

    *Null Cipher Suites:*

    - ``TLS_ECDHE_ECDSA_WITH_NULL_SHA``
    - ``TLS_ECDHE_RSA_WITH_NULL_SHA``
    - ``TLS_RSA_WITH_NULL_SHA256``

    The supported cipher suites for DoIP-connections must be configurable through a configuration option.

    **Certificate Chain Verification**

    - The CDA shall provide a configuration option to enable or disable server certificate
      chain verification.
    - When certificate verification is enabled, the CDA shall allow configuration of
      custom Certificate Authority (CA) certificates to be used for verification, enabling
      operation with private PKI infrastructures.
    - When certificate verification is disabled, the CDA shall accept any server certificate
      presented by the DoIP entity.

    **Rationale**

    TLS support is required for DoIP entities that mandate encrypted communication.
    Configurable certificate verification and custom CA support are necessary because
    automotive environments typically use private PKI infrastructures rather than
    publicly trusted CAs. The option to disable verification ensures compatibility
    with test and development environments.


Diagnostic Message Exchange
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: Diagnostic Message Exchange
    :id: req~doip-diagnostic-message
    :links: arch~doip-diagnostic-message
    :status: draft

    The CDA shall send and receive diagnostic messages (UDS payloads) through the DoIP
    transport layer with proper acknowledgement and error handling.

    **Sending**

    - The CDA shall send Diagnostic Messages (``0x8001``) containing the tester source
      address, target ECU address, and UDS payload.
    - On transmission failure, the CDA shall retry up to ``CP_RepeatReqCountTrans`` times.

    **Acknowledgement**

    - The CDA shall wait for a Diagnostic Message ACK (``0x8002``) or NACK (``0x8003``)
      within ``CP_DoIPDiagnosticAckTimeout``.
    - On NACK, the CDA shall retry based on ``CP_DoIPNumberOfRetries`` with
      ``CP_DoIPRetryPeriod`` delay between attempts, depending on the NACK code.

    **Response Forwarding**

    - After a successful ACK, the CDA shall receive the UDS response encapsulated in a
      Diagnostic Message (``0x8001``) from the DoIP entity and forward it to the
      application layer for UDS-level processing (see :need:`req~uds-nrc-handling`).

    **Functional Addressing**

    - The CDA shall support sending diagnostic messages to a functional address,
      collecting responses from multiple ECUs simultaneously.

    .. uml::
        :caption: DoIP Diagnostic Message Transport

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "CDA" as CDA
        participant "DoIP Entity\n(Gateway)" as GW

        == Send Request ==
        CDA -> GW: Diagnostic Message (0x8001)\n[tester_addr -> ecu_addr, UDS payload]

        alt ACK
            GW --> CDA: Diagnostic Message ACK (0x8002)
            note right: Within\nCP_DoIPDiagnosticAckTimeout
        else NACK
            GW --> CDA: Diagnostic Message NACK (0x8003)\n[nack_code]
            note right of CDA: Retry per\nCP_DoIPNumberOfRetries
        end

        == Receive Response ==
        GW --> CDA: Diagnostic Message (0x8001)\n[UDS response payload]
        CDA -> GW: Diagnostic Message ACK (0x8002)
        note right of CDA: Forward UDS payload\nto application layer
        @enduml

    **Rationale**

    Proper ACK/NACK handling with configurable retries ensures reliable delivery of
    diagnostic messages at the DoIP transport layer. UDS-level response interpretation
    (including NRC handling) is handled separately at the application layer.


Alive Check
^^^^^^^^^^^

.. req:: Alive Check
    :id: req~doip-alive-check
    :links: arch~doip-alive-check
    :status: draft

    The CDA shall perform periodic alive checks on idle DoIP connections to detect
    connection loss.

    - The CDA shall send an Alive Check Request (``0x0007``) when no diagnostic
      communication has occurred on a connection for a defined idle period.
    - If no Alive Check Response (``0x0008``) is received within the alive check timeout,
      the CDA shall consider the connection lost and initiate connection recovery, if
      the ECU has responded with alive check responses in the past.

    **Rationale**

    TCP connections may be silently lost due to network disruption or gateway restart.
    Periodic alive checks enable early detection of connection loss and timely recovery.
    Some ECUs do not implement this feature, so the CDA should only consider it a failure if
    the ECU has previously responded to alive checks, indicating support for this mechanism.


Connection Management
^^^^^^^^^^^^^^^^^^^^^

.. req:: DoIP Connection Management
    :id: req~doip-connection-management
    :links: arch~doip-connection-management, arch~doip-connection-establishment
    :status: draft

    The CDA shall manage TCP connections to DoIP entities with automatic recovery from
    connection failures.

    - Each TCP connection attempt to a DoIP entity shall time out after
      ``CP_DoIPConnectionTimeout``.
    - On connection failure, the CDA shall retry with ``CP_DoIPConnectionRetryDelay``
      between attempts, up to ``CP_DoIPConnectionRetryAttempts`` times.
    - The CDA shall automatically re-establish connections and perform routing activation
      when a connection is lost (due to alive check failure, remote close, or send failure).
    - All ECUs behind a single DoIP gateway shall share one TCP connection, multiplexed
      by logical address.

    **Rationale**

    Automatic connection recovery ensures continuous diagnostic availability despite
    transient network issues. Sharing a single TCP connection per gateway aligns with
    the DoIP protocol model where the gateway multiplexes ECU communication.


Error Handling
^^^^^^^^^^^^^^

.. req:: DoIP Error Handling
    :id: req~doip-error-handling
    :links: arch~doip-error-handling
    :status: draft

    The CDA shall handle DoIP communication errors with configurable retry behavior.

    - **Connection errors**: The CDA shall retry connection establishment per the
      connection retry parameters (``CP_DoIPConnectionRetryDelay``,
      ``CP_DoIPConnectionRetryAttempts``).
    - **Routing activation errors**: The CDA shall report routing activation failures
      for non-recoverable denial codes. For TLS-required denials, the CDA shall
      automatically fall back to a TLS connection.
    - **Diagnostic message NACKs**: The CDA shall retry based on the NACK code,
      ``CP_DoIPNumberOfRetries``, and ``CP_DoIPRetryPeriod``.
    - **Transmission errors**: The CDA shall retry up to ``CP_RepeatReqCountTrans`` times.
    - **ACK timeouts**: The CDA shall report a timeout error to the caller when no
      ACK/NACK is received within ``CP_DoIPDiagnosticAckTimeout``.

    **Rationale**

    Configurable retry behavior enables adaptation to different network conditions and
    ECU response characteristics. Distinguishing between recoverable and non-recoverable
    errors prevents unnecessary retry attempts on permanent failures.


UDS Communication (DoIP)
-------------------------

This describes the relevant UDS communication parameters when used with DoIP, and how they are used.

Communication parameters
^^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: The CDA must support configuration of UDS communication as defined in the following table.
    :id: req~uds-communication-parameters
    :links: arch~uds-communication-parameters
    :status: draft

    .. list-table:: UDS Communication parameters (DoIP)
       :header-rows: 1

       * - Name
         - Function
         - Default value
         - Comment
       * - CP_TesterPresentHandling
         - Define Tester Present generation
         - Enabled
         - - 0 = Do not generate
           - 1 = Generate Tester Present Messages
       * - CP_TesterPresentAddrMode
         - Addressing mode for sending Tester Present
         - Physical
         - - 0 = Physical
           - 1 = Functional, not relevant in CDA case
       * - CP_TesterPresentReqResp
         - Define expectation for Tester Present responses
         - Response expected
         - - 0 = No response expected
           - 1 = Response expected
       * - CP_TesterPresentSendType
         - Define condition for sending tester present
         - On idle
         - - 0 = Fixed periodic
           - 1 = When bus has been idle (Interval defined by CP_TesterPresentTime)
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
         - Timing interval for tester present messages in µs
         - 2000000
         -
       * - CP_RepeatReqCountApp
         - Repetition of last request in case of timeout, transmission or receive error
         - 2
         - Only applies to application layer messages
       * - CP_RC21Handling
         - Repetition mode in case of NRC 21
         - Continue until RC21 timeout
         - - 0 = Disabled
           - 1 = Continue handling negative responses until CP_RC21CompletionTimeout
           - 2 = Continue handling unlimited
       * - CP_RC21CompletionTimeout
         - Time period the tester accepts for repeated NRC 0x21 and retries, while waiting for a positive response in µS
         - 25000000
         -
       * - CP_RC21RequestTime
         - Time between a NRC 0x21 and the retransmission of the same request (in µS)
         - 200000
         -
       * - CP_RC78Handling
         - Repetition mode in case of NRC 78
         - Continue until RC78 timeout
         - - 0 = Disabled
           - 1 = Continue handling negative responses until CP_RC78CompletionTimeout
           - 2 = Continue handling unlimited
       * - CP_RC78CompletionTimeout
         - Time period the tester accepts for repeated NRC 0x78, and waits for a positive response (in µS)
         - 25000000
         -
       * - CP_RC94Handling
         - Repetition mode in case of NRC 94
         - Continue until RC94 timeout
         - - 0 = Disabled
           - 1 = Continue handling negative responses until CP_RC94CompletionTimeout
           - 2 = Continue handling unlimited
       * - CP_RC94CompletionTimeout
         - Time period the tester accepts for repeated NRC 0x94, and waits for a positive response (in µS)
         - 25000000
         -
       * - CP_RC94RequestTime
         - Time between a NRC 0x94 and the retransmission of the same request (in µS)
         - 200000
         -
       * - CP_P6Max
         - Timeout after sending a successful request, for the complete reception of the response message (in µS)
         - 1000000
         - In case of a timeout, CP_RepeatReqCountApp has to be used to retry until exhausted, or a completion timeout is reached
       * - CP_P6Star
         - Enhanced timeout after receiving a NRC 0x78 to wait for the complete reception of the response message (in µS)
         - 1000000
         -


Request-Response Flow
^^^^^^^^^^^^^^^^^^^^^^

.. req:: UDS Request-Response Flow
    :id: req~uds-request-response
    :links: arch~uds-request-response
    :status: draft

    The CDA shall implement a UDS request-response protocol for diagnostic communication
    with vehicle ECUs, satisfying the following behavioral constraints.

    **Per-ECU Serialization**

    - The CDA shall serialize all UDS requests to the same ECU so that only one request
      is outstanding per ECU at any time.
    - If access to a serialized ECU cannot be obtained within a configurable period (default 10s),
      the request shall fail with a timeout error.

    **Response Matching**

    - The CDA shall match each incoming UDS response to the outstanding request based on
      the Service Identifier (SID), per ISO 14229.
    - A positive response shall be accepted only when the echoed request prefix in the
      response matches the original request up to a SID-specific length.
    - A negative response shall be accepted when it contains the matching SID.
    - Responses that do not match the outstanding request shall be logged and discarded.
      The CDA shall continue waiting for a matching response.

    **Response Timeout and Retry**

    - The CDA shall use ``CP_P6Max`` as the default timeout for waiting for a UDS response
      after the DoIP transport layer has acknowledged the message.
    - When NRC 0x78 (Response Pending) is received, the CDA shall switch to the enhanced
      timeout ``CP_P6Star`` for subsequent waits.
    - On timeout, the CDA shall retry the request up to ``CP_RepeatReqCountApp`` times
      before reporting failure.

    **Rationale**

    Per-ECU serialization prevents interleaving of diagnostic requests to the same ECU,
    which would violate the UDS protocol's assumption of single-outstanding-request per
    tester-ECU pair. SID-based response matching ensures that only the correct response
    is accepted, discarding stale or misrouted messages. Configurable timeouts and retries
    allow adaptation to ECUs with varying response characteristics.


NRC Handling
^^^^^^^^^^^^^

.. req:: UDS Negative Response Code Handling
    :id: req~uds-nrc-handling
    :links: arch~uds-nrc-handling
    :status: draft

    The CDA shall handle UDS Negative Response Codes (NRCs) at the application layer
    according to the configured handling policies and timing parameters.

    **NRC 0x78 -- Response Pending**

    When the ECU responds with NRC 0x78, it indicates that the request was received
    but the ECU requires additional time to process it. The CDA shall:

    - Continue waiting for the final response using the enhanced timeout ``CP_P6Star``.
    - Follow the policy defined by ``CP_RC78Handling``:

      - Disabled (0): Do not handle, report as negative response.
      - Continue until timeout (1): Keep waiting until ``CP_RC78CompletionTimeout`` is reached.
      - Continue unlimited (2): Keep waiting indefinitely for a final response.

    **NRC 0x21 -- Busy, Repeat Request**

    When the ECU responds with NRC 0x21, it indicates that the ECU is temporarily busy.
    The CDA shall:

    - Retransmit the original request after ``CP_RC21RequestTime``.
    - Follow the policy defined by ``CP_RC21Handling``:

      - Disabled (0): Do not handle, report as negative response.
      - Continue until timeout (1): Retry until ``CP_RC21CompletionTimeout`` is reached.
      - Continue unlimited (2): Retry indefinitely.

    **NRC 0x94 -- Temporarily Not Available**

    When the ECU responds with NRC 0x94, it indicates that the requested resource is
    temporarily not available. The CDA shall:

    - Retransmit the original request after ``CP_RC94RequestTime``.
    - Follow the policy defined by ``CP_RC94Handling``:

      - Disabled (0): Do not handle, report as negative response.
      - Continue until timeout (1): Retry until ``CP_RC94CompletionTimeout`` is reached.
      - Continue unlimited (2): Retry indefinitely.

    **Application Layer Timeout and Retry**

    - The CDA shall use ``CP_P6Max`` as the default timeout for waiting for a UDS response
      after the DoIP transport layer has acknowledged the message.
    - On timeout, the CDA shall retry the request up to ``CP_RepeatReqCountApp`` times
      before reporting a failure.

    .. uml::
        :caption: UDS NRC Handling

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "CDA\n(Application Layer)" as CDA
        participant "DoIP Entity\n(Gateway)" as GW
        participant "ECU" as ECU

        == UDS Request (after DoIP ACK) ==
        GW -> ECU: UDS request
        activate ECU

        alt NRC 0x78 (Response Pending)
            ECU --> GW: NRC 0x78
            GW --> CDA: UDS response [NRC 0x78]
            note right of CDA: Switch to CP_P6Star timeout\nContinue per CP_RC78Handling

            ECU --> GW: UDS positive response
            deactivate ECU
            GW --> CDA: UDS response [positive]

        else NRC 0x21 (Busy, Repeat Request)
            ECU --> GW: NRC 0x21
            deactivate ECU
            GW --> CDA: UDS response [NRC 0x21]
            note right of CDA: Wait CP_RC21RequestTime\nthen retransmit

            CDA -> GW: UDS request (retransmit)
            GW -> ECU: UDS request
            activate ECU
            ECU --> GW: UDS positive response
            deactivate ECU
            GW --> CDA: UDS response [positive]

        else Direct Response
            ECU --> GW: UDS response
            deactivate ECU
            GW --> CDA: UDS response
            note right of CDA: Within CP_P6Max
        end
        @enduml

    **Rationale**

    NRC handling is a UDS application layer concern independent of the DoIP transport.
    Configurable policies and timeouts per NRC code allow the CDA to adapt to different
    ECU response characteristics, ensuring that transient busy conditions and processing
    delays do not cause premature failure of diagnostic requests.


Tester Present
^^^^^^^^^^^^^^

.. req:: UDS Tester Present
    :id: req~uds-tester-present
    :links: arch~uds-tester-present
    :status: draft

    The CDA shall maintain active diagnostic sessions with ECUs by periodically sending
    UDS Tester Present (``0x3E``) messages. Tester present generation shall be driven by
    the lock lifecycle.

    **Lock-Driven Lifecycle**

    - **Component (ECU) lock**: Acquiring a component lock on an ECU shall start a
      physical tester present task for that ECU, sending to the ECU's physical address.
    - **Functional group lock**: Acquiring a functional group lock shall start functional
      tester present tasks for each gateway ECU in the group, sending to each gateway's
      functional address.
    - **Vehicle lock**: Shall not start any tester present tasks.
    - **Lock release**: Releasing a lock shall stop all associated tester present tasks
      and reset the ECU's session and security access state.

    **Tester Present Deduplication**

    - Only one tester present task (physical or functional) shall be active per ECU at
      any time.

    **Message Format and Timing**

    - The CDA shall send ``CP_TesterPresentMessage`` (default: ``[0x3E, 0x00]``) as the
      tester present message.
    - When ``CP_TesterPresentReqResp`` is set to "No response expected" (0), the CDA shall
      set the suppress-positive-response bit (sub-function ``0x80``) and shall not wait
      for a UDS-level response.
    - When ``CP_TesterPresentReqResp`` is set to "Response expected" (1), the CDA shall
      await and validate the response against ``CP_TesterPresentExpPosResp`` and
      ``CP_TesterPresentExpNegResp``.
    - The sending interval shall be ``CP_TesterPresentTime`` (default: 2,000,000 uS).
    - The CDA shall use a delay-on-miss strategy: if a sending interval is missed, the
      next send shall be delayed rather than bursting to catch up.

    **Send Type**

    - When ``CP_TesterPresentSendType`` is "Fixed periodic" (0), the CDA shall send tester
      present messages at the configured interval regardless of other bus activity.
    - When ``CP_TesterPresentSendType`` is "On idle" (1), the CDA shall send tester present
      messages only when no other diagnostic communication has occurred on the connection
      within the interval defined by ``CP_TesterPresentTime``.

    **Addressing Mode**

    - When ``CP_TesterPresentAddrMode`` is "Physical" (0), the CDA shall send tester
      present to the ECU's physical logical address.
    - When ``CP_TesterPresentAddrMode`` is "Functional" (1), the CDA shall send tester
      present to the ECU's functional logical address.
    - The addressing mode shall be overridden by the lock type: functional group locks
      always use functional addressing regardless of ``CP_TesterPresentAddrMode``.

    **Generation Control**

    - When ``CP_TesterPresentHandling`` is "Enabled" (1), tester present messages shall be
      generated when a lock is held.
    - When ``CP_TesterPresentHandling`` is "Disabled" (0), the CDA shall not generate
      tester present messages for that ECU, even when a lock is held.

    **Error Handling**

    - Tester present negative response codes shall be logged but shall not cause the
      tester present task to stop. The task shall continue sending on the next interval.
    - Send failures due to connection loss shall be handled by the standard DoIP connection
      recovery mechanism. The tester present task shall continue attempting to send on
      subsequent intervals.

    .. uml::
        :caption: Tester Present -- Component Lock

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "SOVD\nLock Manager" as LM
        participant "CDA\n(UDS Layer)" as UDS
        participant "DoIP\nTransport" as DoIP
        participant "ECU" as ECU

        LM -> UDS: acquire component lock
        UDS -> UDS: Start physical TP\nfor ECU
        activate UDS #LightBlue

        loop Every CP_TesterPresentTime
            UDS -> DoIP: [0x3E, 0x00] to\nphysical address
            DoIP -> ECU: Tester Present
            ECU --> DoIP: [0x7E, 0x00]
            DoIP --> UDS: Tester Present Response
        end

        note over LM, ECU: This shows the typical flow.\nActual message content, timing, and response\nhandling depend on the CP_TesterPresent*\ncommunication parameters.

        LM -> UDS: release component lock
        UDS -> UDS: Stop physical TP task
        deactivate UDS
        UDS -> UDS: Reset session and\nsecurity access
        @enduml

    .. uml::
        :caption: Tester Present -- Functional Group Lock

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "SOVD\nLock Manager" as LM
        participant "CDA\n(UDS Layer)" as UDS
        participant "DoIP\nTransport" as DoIP
        participant "ECU\n(Gateway)" as GW

        LM -> UDS: acquire functional group lock
        UDS -> UDS: Resolve group to\ngateway ECUs
        UDS -> UDS: Start functional TP\nfor each gateway
        activate UDS #LightGreen

        loop Every CP_TesterPresentTime
            UDS -> DoIP: [0x3E, 0x80] to\nfunctional address
            DoIP -> GW: Tester Present
        end

        LM -> UDS: release functional group lock
        UDS -> UDS: Stop functional TP tasks
        deactivate UDS
        UDS -> UDS: Reset session and\nsecurity access
        @enduml

    **Rationale**

    Tester present messages prevent ECU diagnostic sessions from timing out during periods
    of inactivity between diagnostic requests. Tying tester present to the lock lifecycle
    ensures that session keepalive is active only when a client has expressed intent to
    communicate with the ECU. The deduplication rule prevents duplicate tester present
    traffic to the same ECU. Configurable COM parameters allow adaptation to
    different ECU requirements regarding message format, timing, and response expectations.


Functional Communication
^^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: UDS Functional Communication
    :id: req~uds-functional-communication
    :links: arch~uds-functional-communication
    :status: draft

    The CDA shall support functional group communication, sending a single UDS request
    to multiple ECUs simultaneously using functional addressing with parallel response
    collection.

    **Functional Group Resolution**

    - The CDA shall resolve a functional group to its member ECUs from the diagnostic
      database.
    - Only ECUs that are currently online (detected during vehicle identification) shall be
      included in the request.
    - Non-physical ECUs (virtual/description ECUs) shall be excluded.

    **Gateway Grouping**

    - The CDA shall group ECUs in the functional group by their gateway logical address.
    - Each gateway group shall produce one diagnostic request targeted at the gateway's
      functional address (``CP_DoIPLogicalFunctionalAddress``).
    - When a functional group spans multiple gateways, the CDA shall send to all gateways
      in parallel.

    **Response Collection**

    - After a gateway acknowledges the functional request, the CDA shall collect responses
      from all expected ECUs behind that gateway in parallel.
    - Responses shall be demultiplexed by source address, with each ECU receiving its
      response independently.
    - ECUs that do not respond within ``CP_P6Max`` shall be reported as individual timeout
      errors without affecting the results from other ECUs.

    **NRC Handling**

    - The functional communication path shall not implement UDS-level NRC 0x21/0x78/0x94
      handling. NRC responses shall be returned as-is to the caller.

    .. uml::
        :caption: Functional Communication Flow

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "Caller" as Caller
        participant "CDA\n(UDS Layer)" as UDS
        participant "Gateway A" as GW1
        participant "ECU A" as ECUA
        participant "ECU B" as ECUB

        == Functional Request ==
        Caller -> UDS: Functional group request
        activate UDS

        UDS -> UDS: Resolve group to\nonline ECUs
        UDS -> UDS: Group by gateway

        UDS -> GW1: Diagnostic Message\n[functional_addr, UDS request]
        GW1 --> UDS: ACK

        par Parallel Response Collection
            GW1 -> ECUA: Forward request
            ECUA --> GW1: UDS response
            GW1 --> UDS: Response (ECU A)
        else
            GW1 -> ECUB: Forward request
            ECUB --> GW1: UDS response
            GW1 --> UDS: Response (ECU B)
        end

        UDS --> Caller: Aggregated results\nper ECU
        deactivate UDS

        note right of Caller: ECUs not responding within\nCP_P6Max reported as\nindividual timeout errors
        @enduml

    **Rationale**

    Functional addressing enables efficient broadcast-style communication where the same
    diagnostic service must be executed across multiple ECUs (e.g., sending Tester Presents
    to all ECUs in a vehicle). Grouping by gateway and sending one request per gateway
    minimizes network traffic. Parallel response collection ensures that slow-responding
    ECUs do not delay results from other ECUs. Returning NRCs as-is on the functional path
    avoids complex retry orchestration across multiple ECUs simultaneously.
