.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

Diagnostic Database Update Plugin
---------------------------------

.. arch:: Diagnostic Database Update Plugin
    :id: arch~plugin-diagnostic-database-update

    **Endpoints and Security**

    By default, all modifying actions to any endpoint require an exclusive vehicle lock. It must be ensured, that no
    diagnostic operations are in progress, when the "Apply" action is triggered - this includes functional
    and component locks.

    Only the subject of the lock is allowed to use the endpoints. This ensures that the database isn't used
    while it is being updated, and that no 3rd party could add additional files to the update while it is being
    prepared, which could lead to security issues.

    This behavior and additional security requirements must be modifiable through a trait provided to the plugin,
    to support more specific OEM requirements for security and individual environments during the update process.

    The diagnostic database update plugin must provide the following bulk-data categories/endpoints:

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
         - Adds files to the next update of the diagnostic database, using multipart form data. The files provided through this endpoint are added to the pending update.

       * - DELETE
         - ``/apps/sovd2uds/bulk-data/runtimefiles-nextupdate``
         - Removes all pending changes to the next update of the diagnostic database, to reset the state of the next update to the currently active database.

       * - DELETE
         - ``/apps/sovd2uds/bulk-data/runtimefiles-nextupdate/{id}``
         - Deletes the file from the pending update - in case of a file that was previously part of the current database, it'll be deleted in the current database upon applying the next update.

       * - GET
         - ``/apps/sovd2uds/bulk-data/runtimefiles-backup``
         - Returns a list of items of the previously used diagnostic database, which can be used to roll back the diagnostic database in case of issues.

       * - DELETE
         - ``/apps/sovd2uds/bulk-data/runtimefiles-backup``
         - Deletes the backup of the previously used diagnostic database, to free up storage space. This also means that rolling back to the previous state isn't possible anymore after deleting the backup.

    .. note:: The following query parameters must be supported for the GET endpoints:

       - ``x-sovd2uds-include-hash`` (string, default: not present -- supported is only sha256) - to include file hashes of the files
       - ``x-sovd2uds-include-file-size`` (boolean, default: false) - to include file sizes of the files
       - ``x-sovd2uds-include-revision`` (boolean, default: false) - to include the revision inside the files

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


    **Application of the update**

    To delete all pending updates from ``runtimefiles-nextupdate``, or to delete the backup in ``runtimefiles-backup``
    ``DELETE`` on the respective bulk-data endpoint must be supported.

    To apply all the pending updates to the current diagnostic database, an additional endpoint is required:

    ``POST /apps/sovd2uds/bulk-data/runtimefiles-nextupdate/executions`` with a JSON-payload containing the property
    ``mode``, with the following possible values (all case-insensitive):

    - ``Apply`` - to apply the pending updates.
    - ``Rollback`` -  to roll back to the backup state of the diagnostic database (also clears pending nextupdate)
    - ``Cleanup`` - (case-insensitive) to reset all pending updates, as well as deleting the backup

    The same endpoint must also be made available as ``/apps/sovd2uds/operations/diagnostic-database-update``
    to allow triggering the actions through a standard compliant operation.

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
