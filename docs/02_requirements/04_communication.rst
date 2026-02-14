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

DoIP Communication is described in the ISO 13400 standard. Specific communication parameters and implementation details will be defined and linked in this document.

The communication parameters depend on the used logical link for the communication, itself will be filtered by configuration, and actual ecu detection/availability.

Supported protocol versions
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. TODO: Define supported protocol versions

Communication parameters
^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: The CDA must support configuration of DoIP communication parameters as defined in the following table.
    :id: req~doip-communication-parameters

    .. list-table:: DoIP Communication parameters
       :header-rows: 1

       * - Name
         - Function
         - Default value
         - Comment
       * - CP_DoIPLogicalGatewayAddress
         - Logical address of a DoIP entity. In case of directly reachable DoIP entity it's equal to the CP_DoIPLogicalEcuAddress, otherwise data will be sent via this address to the CP_DoIPLogicalEcuAddress
         -
         -
       * - CP_DoIPLogicalEcuAddress
         - Logical/Physical address of the ECU
         -
         -
       * - CP_DoIPLogicalFunctionalAddress
         - Functional address of the ECU
         -
         -
       * - CP_DoIPLogicalTesterAddress
         - Logical address of the tester
         -
         -
       * - CP_DoIPNumberOfRetries
         - Number of retries for specific NACKs
         -
         - "NACK: OUT_OF_MEMORY (3)"
       * - CP_DoIPDiagnosticAckTimeout
         - Maximum time the tester waits for an ACK or NACK of the DoIP entity
         -
         -
       * - CP_DoIPRetryPeriod
         - Period between retries, after specific NACK conditions are encountered
         -
         -
       * - CP_DoIPRoutingActivationTimeout
         - Maximum time allowed for the ECUs routing activation
         -
         -
       * - CP_RepeatReqCountTrans
         - Number of retries in case a transmission error, a receive error, or transport layer timeout is encountered
         - 0
         -
       * - CP_DoIPConnectionTimeout
         - Timeout after which a connection attempt should've been successful
         -
         -
       * - CP_DoIPConnectionRetryDelay
         - Delay before attempting to reconnect
         - 0
         -
       * - CP_DoIPConnectionRetryAttempts
         - Attempts to retry connection before giving up
         -
         -

Connection establishment
^^^^^^^^^^^^^^^^^^^^^^^^

.. uml::
    :caption: Establishing DoIP connection

    @startuml
    participant "CDA"
    participant "DoIP-Entity" as ECU
    group establish connection
       CDA -> ECU: connect
       activate ECU
       ECU -> CDA: success
       note right: Maximum of CP_DoIPConnectionTimeout
       deactivate ECU
    end
    group connection attempt fails / times out
       loop CP_DoIPConnectionRetryAttempts times
           note right of CDA:  Wait for CP_DoIPConnectionRetryDelay
           CDA -> ECU: connect
           activate ECU
           ECU -> CDA: success
           deactivate ECU
           note right: Maximum of CP_DoIPConnectionTimeout
           note right of CDA: break loop on success, continue on failure
       end
    end
    @enduml

    .. note::

    When these parameters are set via mdd, multiple mdd-files could match due to duplicated logical addresses.

    .. TODO: specify how to resolve this behavior (e.g. use most lax settings?)

In case a connection was to be established as part of a diagnostic request, and a timeout is encountered, an error is reported on failure.

Communication
^^^^^^^^^^^^^

.. note::

   .. TODO


UDS Communication (DoIP)
------------------------

This describes the relevant uds communication parameters when used with DoIP, and how they are used.

Communication parameters
^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: The CDA must support configuration of UDS communication as defined in the following table.
    :id: req~uds-communication-parameters

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
