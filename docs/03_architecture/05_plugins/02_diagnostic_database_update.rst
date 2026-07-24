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

Diagnostic Database Update Plugin
---------------------------------

.. arch:: Diagnostic Database Update Plugin
    :id: arch~plugin-diagnostic-database-update
    :status: draft

    **Endpoints and Security**

    By default, all modifying actions to any endpoint require an exclusive vehicle lock. It must be ensured, that no
    diagnostic operations are in progress, when the "Apply" action is triggered - this includes functional
    and component locks.

    Only the subject of the lock is allowed to use the endpoints. This ensures that the database isn't used
    while it is being updated, and that no 3rd party could add additional files to the update while it is being
    prepared, which could lead to security issues.

    This behavior and additional security requirements must be modifiable through a trait provided to the plugin,
    to support more specific OEM requirements for security and individual environments during the update process.

    The diagnostic database update plugin must provide the following bulk-data categories/endpoints for
    file management, and a separate ``operations`` endpoint for applying/rolling back/cleaning up updates:

    .. list-table:: Bulk-Data Paths for Diagnostic Database Update Preparation
       :header-rows: 1

       * - Method
         - Path
         - Description

       * - GET
         - ``/apps/sovd2uds/bulk-data/runtimefiles-current``
         - Return a list of items in the currently active diagnostic database.

       * - GET
         - ``/apps/sovd2uds/bulk-data/runtimefiles-nextupdate``
         - Returns a list of the next update of the diagnostic database. Initially it shows the existing diagnostic database, and applies all pending updates to it, to show the state of the diagnostic database after applying the pending updates.

       * - POST
         - ``/apps/sovd2uds/bulk-data/runtimefiles-nextupdate``
         - Adds files to the next update of the diagnostic database. Two content types are supported: ``multipart/form-data`` (one or more files, filenames taken from each part's ``filename`` parameter), and ``application/octet-stream`` (a single file per request, whose filename must be provided via the ``Content-Disposition`` header, e.g. ``Content-Disposition: attachment; filename="foo.mdd"``). Returns 201 with all created IDs and a ``Location`` header for the first created file.

       * - DELETE
         - ``/apps/sovd2uds/bulk-data/runtimefiles-nextupdate``
         - Removes all pending changes to the next update of the diagnostic database, to reset the state of the next update to the currently active database. Returns 200 with ``deleted_ids`` and ``errors``.

       * - DELETE
         - ``/apps/sovd2uds/bulk-data/runtimefiles-nextupdate/{id}``
         - Deletes the file from the pending update - in case of a file that was previously part of the current database, it'll be deleted in the current database upon applying the next update.

       * - GET
         - ``/apps/sovd2uds/bulk-data/runtimefiles-backup``
         - Returns a list of items of the previously used diagnostic database, which can be used to roll back the diagnostic database in case of issues.

       * - DELETE
         - ``/apps/sovd2uds/bulk-data/runtimefiles-backup``
         - Deletes the backup of the previously used diagnostic database, to free up storage space. This also means that rolling back to the previous state isn't possible anymore after deleting the backup. Returns 200 with ``deleted_ids`` and ``errors``.

    .. list-table:: Operations Paths for Applying/Rolling Back/Cleaning Up Diagnostic Database Updates
       :header-rows: 1

       * - Method
         - Path
         - Description

       * - GET
         - ``/apps/sovd2uds/operations/runtimefilesupdate/executions``
         - Returns the list of current execution identifiers. Always contains at most one entry.

       * - GET
         - ``/apps/sovd2uds/operations/runtimefilesupdate/executions/{id}``
         - Returns the status of a specific execution by its ID.

       * - POST
         - ``/apps/sovd2uds/operations/runtimefilesupdate/executions``
         - Starts a new execution (Apply, Rollback, or Cleanup). Returns 202 Accepted with the execution ID.

    .. note:: The following query parameters must be supported for the GET endpoints:

       - ``x-sovd2uds-include-hash`` (string, default: not present -- supported is only sha256) - to include file hashes of the files
       - ``x-sovd2uds-include-file-size`` (boolean, default: false) - to include file sizes of the files
       - ``x-sovd2uds-include-revision`` (boolean, default: false) - to include the revision inside the files
       - ``created-after`` and ``created-before`` (string:date-time) are accepted for ISO 17978-3 compatibility but do not currently filter results.

    **Configuration File Support**

    In addition to MDD database files (``.mdd``), the plugin supports uploading CDA configuration
    files (``.toml``) through the **same** ``runtimefiles-*`` bulk-data endpoints. The upload handler
    routes each file to the appropriate internal storage collection based on its extension:

    - ``.mdd`` files go to the ``DiagnosticDatabase*`` collections.
    - ``.toml`` files go to the ``Configuration*`` collections.

    Only one ``.toml`` configuration file per upload request is supported; uploading more than one
    in a single ``POST`` to ``runtimefiles-nextupdate`` is rejected.

    All GET endpoints (``runtimefiles-current``, ``runtimefiles-nextupdate``, ``runtimefiles-backup``)
    return both MDD and configuration file entries in a single combined response.

    The HTTP handler implementation for the bulk-data endpoints resides in
    ``cda-sovd/src/sovd/apps/sovd2uds/bulk_data/runtimefiles.rs``. The execution endpoints
    (Apply/Rollback/Cleanup) reside in ``cda-sovd/src/sovd/apps/sovd2uds/operations.rs``.

    **Coupled MDD and Configuration Updates**

    When an MDD file update requires a simultaneous configuration change (e.g., a new MDD file
    introduces changes that require updated communication parameters in the CDA configuration), both
    files must be uploaded to ``runtimefiles-nextupdate`` and applied via a **single** ``Apply``
    execution. A single ``Apply`` execution will atomically apply all pending MDD and configuration
    changes together in one transaction, provided both ``NextUpdate`` collections are populated.

    .. warning::

        There is **no guaranteed atomic coupling** when MDD and configuration updates are applied
        in separate executions. Applying them independently means they take effect at different
        points in time, which may leave the system in a partially updated state during the interval
        between the two applies.

        Users must account for this by uploading all related files (MDD and configuration) in the
        same ``runtimefiles-nextupdate`` batch and triggering a single ``Apply``. This is an accepted
        limitation of the unified endpoint design.

    **Limitations to bulk-data operations**

    For Security reasons, none of the endpoints should allow retrieval of the files by default - there may be an option
    to enable it. Adding or deleting files must only be allowed in the ``runtimefiles-nextupdate`` category, and not
    for the ``runtimefiles-backup`` or ``runtimefiles-current`` category, to avoid security issues, and to ensure
    consistency of the backup and current state of the diagnostic database.

    **File Handling**

    The id for the files within the diagnostic database update plugin must be the file name, to ensure consistency
    when files are overwritten, deleted, or added.

    File names must be handled case-insensitively on all operating systems to make usage regardless of OS consistent,
    to avoid duplicated entries, and to allow case-insensitive paths for deletion.

    There must be an option to normalize file names to the name of the ECU they belong to, to ensure consistency and
    to avoid duplicated entries for the same ECU with different file names.

    Files must be verifiable through a ``trait`` provided to the plugin before being applied as the new current state.

    The verification includes, but is not limited to, signature verification, hash verification, and version checks
    of the currently active database, as well as the new one.

    **Providing a Custom Update Plugin**

    Applications embedding CDA can replace the complete runtime update implementation at startup.
    Implement ``cda_interfaces::runtime_update_api::RuntimeFilesUpdatePlugin`` and pass a builder
    to ``Setup::with_update_plugin``. The builder receives ``CdaRuntime``, which exposes the live
    configuration, UDS manager, DoIP gateway, lock provider, storage directory, update guard, and
    reload-related infrastructure required by an implementation.

    The ``update_plugin_fn`` helper adapts an async closure without requiring a separate builder
    type:

    .. code:: rust

       use opensovd_cda_lib::{Setup, run_with_ext_from_config};
       use opensovd_cda_lib::update::update_plugin_fn;

       let setup = Setup::<MySecurityPlugin, MySecurityLoader>::new()
           .with_update_plugin(update_plugin_fn(|runtime| async move {
               Ok(MyRuntimeUpdatePlugin::new(runtime))
           }));

       run_with_ext_from_config(config, setup).await?;

    CDA mounts the returned plugin on the standard ``runtimefiles-*`` endpoints and wraps it
    with read/write mutual exclusion. A replacement plugin therefore implements the complete
    update lifecycle (listing, upload, deletion, apply, rollback, cleanup, and execution status).

    Implementations that only need custom authorization, signature checks, version policy, or
    reload behavior should normally retain ``DefaultRuntimeUpdatePlugin`` and provide custom
    ``RuntimeUpdateSecurityPlugin`` and/or ``RuntimeReloaderPlugin`` implementations instead.


    **Application of the update**

    To delete all pending updates from ``runtimefiles-nextupdate``, or to delete the backup in ``runtimefiles-backup``
    ``DELETE`` on the respective bulk-data endpoint must be supported.

    To apply all the pending updates to the current diagnostic database, an additional endpoint is required:

    ``POST /apps/sovd2uds/operations/runtimefilesupdate/executions`` with a JSON-payload containing a
    ``parameters`` object with the property ``mode``, following the standard convention of wrapping
    operation-specific inputs in a ``parameters`` field, with the following possible values for ``mode``
    (all case-insensitive):

    - ``Apply`` - to apply the pending updates.
    - ``Rollback`` - to roll back to the backup state of the diagnostic database (also clears pending nextupdate)
    - ``Cleanup`` - to reset all pending updates, as well as deleting the backup

    **Execution Lifecycle**

    Only one execution can be in-flight at a time. Starting a new execution while one is already running must
    be rejected with a conflict error.

    Execution entries are retained in memory and remain queryable via
    ``GET /apps/sovd2uds/operations/runtimefilesupdate/executions/{id}`` until the next execution is
    started. When a new execution is started, all previous terminal-state (``Completed`` or ``Failed``)
    entries are removed. Entries must not be removed based on time (no TTL). This ensures that the result
    of the last execution remains available for inspection without requiring indefinite memory growth.

    The list endpoint ``GET /apps/sovd2uds/operations/runtimefilesupdate/executions`` returns all
    currently tracked execution identifiers and always contains at most one entry. No vehicle lock is
    required to use the list or status endpoints.

    After applying, or rolling back the diagnostic database, the new database must be active immediately, without
    requiring a restart of the CDA, and the old state must be available as a backup until the next update is applied,
    the backup is deleted, or a cleanup is initiated. The state of nextupdate must also be reset after applying or
    rolling back, to ensure that pending updates aren't reapplied unintentionally after a rollback, and to ensure
    that the state of the next update is consistent with the currently active database.

    **Atomicity**

    Every action must be atomically applied, meaning that if any part of the action fails, the entire action must be
    rolled back, and the state of the diagnostic database while the adapter is running must be consistent with either
    the state before the action, or the state after the action, but not a partially applied state.

    This also applies to power cycles and crashes during the application of the update, to ensure this, journaling and
    transactional file handling can be used, but the exact mechanism is up to the implementation of the plugin. This
    may require flushing filesystem caches frequently to guarantee consistency.
