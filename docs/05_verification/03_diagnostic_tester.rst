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
    :links: test~deferred-admitting-modes-activate, test~deferred-disabled-rejects-activation, test~deferred-request-activation-policy, test~deferred-activation-retry, test~deferred-sovd-admission
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
    :links: test~doip-direct-connect-not-recorded, test~ecu-topology-store-cancelled-call-keeps-lock, test~detection-activity-running-work-keeps-busy, test~detection-activity-idle-wakes-when-last-work-ends, test~ecu-list-persistence-snapshot-name-case, test~ecu-list-persistence-unreachable-not-reached-is-offline, test~ecu-topology-persist-after-detection, test~ecu-topology-prune, test~ecu-topology-persist-serialized, itest~ecu-list-persistence-unreachable, itest~ecu-list-persistence-unreachable-gateway, test~ecu-list-persistence-requires-doip, itest~ecu-list-persistence-disabled, itest~ecu-list-persistence-reuse, test~ecu-list-persistence-reuse-plan, test~detection-activity-finished-work-visible-through-generation, test~ecu-list-persistence-runs-during-write-coalesce-into-one-more-write, test~ecu-list-persistence-waits-for-discovery-and-detection, test~ecu-list-persistence-persisted-state-follows-sovd-mapping, test~ecu-topology-store-unreadable-entries-are-skipped, test~ecu-topology-store-persist-gateways-keeps-other-entries, test~ecu-list-persistence-unchanged-restart-writes-nothing, test~ecu-list-persistence-only-changed-gateways-written
    :status: draft

    Verifies storing, pruning and reusing the persisted ECU topology after discovery
    and variant detection.

.. testset:: ECU List Persistence Shutdown Update
    :id: testset~ecu-list-persistence-shutdown
    :links: itest~ecu-list-persistence-shutdown, test~ecu-list-persistence-shutdown-with-running-detection-writes-last-seen-only, test~ecu-list-persistence-shutdown-snapshot
    :status: draft

    Verifies that the persisted ECU states and ``last_seen`` timestamps are updated at a
    graceful shutdown.
