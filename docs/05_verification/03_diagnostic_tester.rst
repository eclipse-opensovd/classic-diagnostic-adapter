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

*****************
Diagnostic Tester
*****************

.. testset:: Deferred Communication Startup
    :id: testset~deferred-communication-startup
    :links: test~deferred-communication-config, test~deferred-startup-policy, test~deferred-doip-passive-construction, itest~deferred-on-demand-pending, itest~deferred-on-demand-uds-silence, itest~deferred-disabled-uds-silence, itest~deferred-on-demand-all-gateways, itest~deferred-on-demand-one-vir
    :status: draft

    Verifies that communication is only activated at startup when configured and that
    no UDS traffic is sent before an authorized trigger.

.. testset:: Deferred Communication Activation
    :id: testset~deferred-communication-activation
    :links: test~deferred-admitting-modes-activate, test~deferred-disabled-rejects-activation, test~deferred-request-activation-policy, test~deferred-activation-retry, test~deferred-sovd-admission, test~communication-explicit-detection-enables
    :status: draft

    Verifies admission and activation of deferred communication triggered by SOVD requests.

.. testset:: Post-Update Deferred Communication
    :id: testset~deferred-post-update
    :links: test~deferred-communication-config, test~deferred-post-update-apply, test~deferred-post-update-rollback, itest~deferred-post-update
    :status: draft

    Verifies that communication stays disabled after a database update apply or rollback
    until it is reactivated.

.. testset:: Explicit Variant Detection
    :id: testset~variant-detection-explicit
    :links: itest~variant-detection-explicit
    :status: draft

    Verifies that an explicit ECU variant detection trigger works with automatic
    variant detection disabled.

.. testset:: Persisted Topology Reconnect
    :id: testset~persisted-topology-reconnect
    :links: test~ecu-topology-reconnect-search, test~doip-aborted-discovery-finishes, test~doip-vam-only-reconnect-without-search, test~doip-failed-announcement-connect-reported, test~doip-reconnect-decides-deferred-announcement-failures, test~doip-uncovered-announcement-failure-reported-at-once, test~doip-unreachable-reported-after-state-change, test~doip-plan-reconnect, test~doip-reconnect-plan-reconnect-rejects-renamed-gateway, test~doip-vam-during-reconnect-does-not-connect-twice, test~doip-vam-during-connect-connects-after-failure, test~doip-discovery-connect-waits-for-direct-connect, test~doip-cancelled-connect-reverts-ecu-states, test~doip-cancelled-connect-without-brought-online-ecus-reports-nothing, test~doip-cancelled-connect-reverts-only-brought-online-ecus, test~doip-connection-reset-requests-detection-for-the-report, test~doip-vam-only-reconnect-reports-unusable
    :status: draft

    Verifies the direct reconnect to persisted gateways, the broadcast fallback for
    unreachable gateways and the handling of announcements during a reconnect.

.. testset:: ECU State Restore
    :id: testset~ecu-state-restore
    :links: test~ecu-state-restore-without-assume-online-only-last-seen-is-restored, test~ecu-state-restore-variant-missing-from-the-database-is-detected-again, test~ecu-state-restore-address-mismatch-restores-nothing, test~ecu-state-restore-can-pinned-ecu-is-not-assumed-online, test~ecu-state-restore-inconsistent-duplicate-group-is-detected-again, test~ecu-state-restore-independent-of-discovery-mode
    :status: draft

    Verifies that persisted ECU states are only restored when they still match the
    database and the configured addressing, and are detected again otherwise.

.. testset:: ECU States
    :id: testset~ecu-states
    :links: test~ecu-last-seen, test~uds-ecu-reply-contact, test~uds-gateway-disconnect-applied-before-return, test~uds-suppressed-response-no-contact, test~uds-state-assumed-online-becomes-online-on-response, test~uds-state-restored-duplicate-survives-connect-but-real-reconnect-redetects, test~uds-gateway-connect-report-lists-only-offline-ecus, test~uds-gateway-connect-undo-keeps-assumed-online-ecu, test~uds-gateway-connect-undo-leaves-offline-ecu-offline, test~ecu-state-assumed-online-keeps-state-without-gateway, test~ecu-state-assumed-online-reported-as-online, test~ecu-state-assumed-online-unreachable-is-offline, test~ecu-state-assumed-online-failed-detection-is-offline
    :status: draft

    Verifies the ECU connectivity states, including ``AssumedOnline`` for restored ECUs,
    and the ``last_seen`` tracking of ECU replies.

.. testset:: ECU List Persistence
    :id: testset~ecu-list-persistence
    :links: test~doip-direct-connect-not-recorded, test~ecu-topology-store-cancelled-call-keeps-lock, test~detection-activity-running-work-keeps-busy, test~detection-activity-idle-wakes-when-last-work-ends, test~ecu-list-persistence-snapshot-name-case, test~ecu-list-persistence-unreachable-not-reached-is-offline, test~ecu-topology-persist-after-detection, test~ecu-topology-prune, test~ecu-topology-persist-serialized, itest~ecu-list-persistence-unreachable, itest~ecu-list-persistence-unreachable-gateway, test~ecu-list-persistence-requires-doip, itest~ecu-list-persistence-disabled, itest~ecu-list-persistence-reuse, test~ecu-list-persistence-reuse-plan, test~detection-activity-finished-work-visible-through-generation, test~ecu-list-persistence-runs-during-write-coalesce-into-one-more-write, test~ecu-list-persistence-waits-for-discovery-and-detection, test~ecu-list-persistence-persisted-state-follows-sovd-mapping, test~ecu-topology-store-unreadable-entries-are-skipped, test~ecu-topology-store-persist-gateways-keeps-other-entries, test~ecu-list-persistence-unchanged-restart-writes-nothing, test~ecu-list-persistence-only-changed-gateways-written, test~ecu-topology-store-serialized
    :status: draft

    Verifies storing, pruning and reusing the persisted ECU topology after discovery
    and variant detection.

.. testset:: ECU List Persistence Shutdown Update
    :id: testset~ecu-list-persistence-shutdown
    :links: itest~ecu-list-persistence-shutdown, test~ecu-list-persistence-shutdown-with-running-detection-writes-last-seen-only, test~ecu-list-persistence-shutdown-snapshot, test~ecu-list-persistence-shutdown-serialized-with-clear, test~ecu-list-persistence-failed-clear-keeps-unwritten, test~ecu-list-persistence-clear-restores-task, test~ecu-list-persistence-clear-skips-initial-write, test~ecu-list-persistence-shutdown-after-clear-does-not-recreate-entries
    :status: draft

    Verifies that the persisted ECU states and ``last_seen`` timestamps are updated at a
    graceful shutdown.

.. testset:: Communication Quiesce
    :id: testset~communication-quiesce
    :links: test~doip-refused-reconnect-not-reported, test~doip-closed-gate-searches-nothing, test~doip-refused-announcement-not-reported, test~communication-quiesce-closes-gate, test~transport-gate-refuses-send-while-quiesced, test~doip-gate-refuses-connect-while-quiesced, test~doip-gate-closed-during-connect, test~communication-quiesce-conflicts-with-disable-and-detection, test~communication-quiesce-rejects-active-guards, test~doip-gate-refuses-direct-connect, test~transport-gate-refuses-direct-connect-while-quiesced
    :status: draft

    Verifies that the quiesce lease closes the transport gate, that no gateway is
    connected or searched and no request is sent while it is closed, and that
    gateways refused by the gate are not reported unreachable.

.. testset:: Vehicle Topology Plugin - Retrieval
    :id: testset~plugin-vehicle-topology-retrieval
    :links: test~networkstructure-conflict-during-reset
    :status: draft

    Verifies that the network structure is not served while a ``networkreset`` runs.

.. testset:: Vehicle Topology Plugin - Reset
    :id: testset~plugin-vehicle-topology-reset
    :links: itest~plugin-vehicle-topology-reset, test~plugin-vehicle-topology-reset-single-execution, test~plugin-vehicle-topology-reset-deadline, test~plugin-vehicle-topology-reset-delete-during-clear, test~plugin-vehicle-topology-reset-deadline-before-finish, test~plugin-vehicle-topology-reset-verdict-from-persistence, test~plugin-vehicle-topology-reset-persist-timeout, test~plugin-vehicle-topology-reset-delete-lock, test~plugin-vehicle-topology-reset-failed-rediscover-reports-disabled-communication, test~plugin-vehicle-topology-reset-delete-interrupts-hanging-rediscover, test~plugin-vehicle-topology-reset-panicking-reset-reports-failed, test~plugin-vehicle-topology-reset-dropped-delete-still-removes-the-execution, test~plugin-vehicle-topology-reset-diagnostics-in-progress-reject-the-reset, test~plugin-vehicle-topology-reset-http-post-maps-plugin-conflicts-to-409, itest~plugin-vehicle-topology-reset-networkreset-without-persistence-completes, test~plugin-vehicle-topology-reset-failed-clear-gives-the-lease-back, test~plugin-vehicle-topology-reset-timeout-stops-the-execution, test~plugin-vehicle-topology-reset-http-timeout
    :status: draft

    Verifies the ``networkreset`` operation: single execution, deadlines, the HTTP
    interface and the rediscovery after the reset.

.. testset:: Vehicle Topology Plugin - Reset with Persisted List Control
    :id: testset~plugin-vehicle-topology-reset-persistence
    :links: test~plugin-vehicle-topology-reset-request-body, test~plugin-vehicle-topology-reset-doip-reset-requires-a-new-settled-discovery, test~ecu-list-persistence-failed-write-of-a-settled-rediscovery-is-reported, test~ecu-list-persistence-rediscovery-verdict, test~plugin-vehicle-topology-reset-failed-persisting-of-the-rediscovered-topology-is-reported, test~plugin-vehicle-topology-reset-clear-and-detect-runs-one-rediscovery-and-blocks-network-structure, test~plugin-vehicle-topology-reset-http-misunderstood-bodies-are-rejected-without-executing
    :status: draft

    Verifies clearing and rewriting the persisted ECU topology by a ``networkreset``
    and the verdict reported from it.
