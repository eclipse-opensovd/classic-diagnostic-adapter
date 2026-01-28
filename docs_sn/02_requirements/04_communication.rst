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

- Name: CP_DoIPLogicalGatewayAddress
  Function: Logical address of a DoIP entity. In case of directly reachable DoIP entity it's equal to the CP_DoIPLogicalEcuAddress, otherwise data will be sent via this address to the CP_DoIPLogicalEcuAddress
  Default value:
  Comment:

- Name: CP_DoIPLogicalEcuAddress
  Function: Logical/Physical address of the ECU
  Default value:
  Comment:

- Name: CP_DoIPLogicalFunctionalAddress
  Function: Functional address of the ECU
  Default value:
  Comment:

- Name: CP_DoIPLogicalTesterAddress
  Function: Logical address of the tester
  Default value:
  Comment:

- Name: CP_DoIPNumberOfRetries
  Function: Number of retries for specific NACKs
  Default value:
  Comment: "NACK: OUT_OF_MEMORY (3)"

- Name: CP_DoIPDiagnosticAckTimeout
  Function: Maximum time the tester waits for an ACK or NACK of the DoIP entity
  Default value:
  Comment:

- Name: CP_DoIPRetryPeriod
  Function: Period between retries, after specific NACK conditions are encountered
  Default value:
  Comment:

- Name: CP_DoIPRoutingActivationTimeout
  Function: Maximum time allowed for the ECUs routing activation
  Default value:
  Comment:

- Name: CP_RepeatReqCountTrans
  Function: Number of retries in case a transmission error, a receive error, or transport layer timeout is encountered
  Default value: 0
  Comment:

- Name: CP_DoIPConnectionTimeout
  Function: Timeout after which a connection attempt should've been successful
  Default value:
  Comment:

- Name: CP_DoIPConnectionRetryDelay
  Function: Delay before attempting to reconnect
  Default value: 0
  Comment:

- Name: CP_DoIPConnectionRetryAttempts
  Function: Attempts to retry connection before giving up
  Default value:
  Comment:

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

- Name: CP_TesterPresentHandling
  Function: Define Tester Present generation
  Default value: Enabled
  Comment:

  * 0 = Do not generate
  * 1 = Generate Tester Present Messages

- Name: CP_TesterPresentAddrMode
  Function: Addressing mode for sending Tester Present
  Default value: Physical
  Comment:

  * 0 = Physical
  * 1 = Functional, not relevant in CDA case

- Name: CP_TesterPresentReqResp
  Function: Define expectation for Tester Present responses
  Default value: Response expected
  Comment:

  * 0 = No response expected
  * 1 = Response expected

- Name: CP_TesterPresentSendType
  Function: Define condition for sending tester present
  Default value: On idle
  Comment:

  * 0 = Fixed periodic
  * 1 = When bus has been idle (Interval defined by CP_TesterPresentTime)

- Name: CP_TesterPresentMessage
  Function: Message to be sent for tester present
  Default value: 3E00
  Comment:

- Name: CP_TesterPresentExpPosResp
  Function: Expected positive response (if required)
  Default value: 7E00
  Comment:

- Name: CP_TesterPresentExpNegResp
  Function: Expected negative response (if required)
  Default value: 7F3E
  Comment: A tester present error should be reported in the log, tester present sending should be continued

- Name: CP_TesterPresentTime
  Function: Timing interval for tester present messages in µs
  Default value: 2000000
  Comment:

- Name: CP_RepeatReqCountApp
  Function: Repetition of last request in case of timeout, transmission or receive error
  Default value: 2
  Comment: Only applies to application layer messages

- Name: CP_RC21Handling
  Function: Repetition mode in case of NRC 21
  Default value: Continue until RC21 timeout
  Comment:

  * 0 = Disabled
  * 1 = Continue handling negative responses until CP_RC21CompletionTimeout
  * 2 = Continue handling unlimited

- Name: CP_RC21CompletionTimeout
  Function: Time period the tester accepts for repeated NRC 0x21 and retries, while waiting for a positive response in µS
  Default value: 25000000
  Comment:

- Name: CP_RC21RequestTime
  Function: Time between a NRC 0x21 and the retransmission of the same request (in µS)
  Default value: 200000
  Comment:

- Name: CP_RC78Handling
  Function: Repetition mode in case of NRC 78
  Default value: Continue until RC78 timeout
  Comment:

  * 0 = Disabled
  * 1 = Continue handling negative responses until CP_RC78CompletionTimeout
  * 2 = Continue handling unlimited

- Name: CP_RC78CompletionTimeout
  Function: Time period the tester accepts for repeated NRC 0x78, and waits for a positive response (in µS)
  Default value: 25000000
  Comment:

- Name: CP_RC94Handling
  Function: Repetition mode in case of NRC 94
  Default value: Continue until RC94 timeout
  Comment:

  * 0 = Disabled
  * 1 = Continue handling negative responses until CP_RC94CompletionTimeout
  * 2 = Continue handling unlimited

- Name: CP_RC94CompletionTimeout
  Function: Time period the tester accepts for repeated NRC 0x94, and waits for a positive response (in µS)
  Default value: 25000000
  Comment:

- Name: CP_RC94RequestTime
  Function: Time between a NRC 0x94 and the retransmission of the same request (in µS)
  Default value: 200000
  Comment:

- Name: CP_P6Max
  Function: Timeout after sending a successful request, for the complete reception of the response message (in µS)
  Default value: 1000000
  Comment: In case of a timeout, CP_RepeatReqCountApp has to be used to retry, until exhausted, or a completion timeout is reached

- Name: CP_P6Star
  Function: Enhanced timeout after receiving a NRC 0x78 to wait for the complete reception of the response message (in µS)
  Default value: 1000000
  Comment:
