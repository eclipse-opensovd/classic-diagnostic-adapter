.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

General
=======

Storage Access
--------------

.. arch:: Storage Access API
    :id: arch~system-storage-access-abstraction
    :status: draft

    The Storage Access API provides an abstraction layer for storage access, allowing the CDA to interact with different types of storage systems (e.g., local file system, databases) without being tightly coupled to a specific implementation.

    To achieve atomicity and consistent behavior across different storage implementations, the API defines the following semantics:

    * All operations must be atomic, meaning that either all changes are applied successfully, or none are applied in case of an error.
    * The API should provide a consistent interface for reading and writing data, regardless of the underlying storage system.
    * Error handling should be standardized, allowing the CDA to gracefully handle storage-related exceptions and errors.
    * Keys shall be handled case-insensitive, to simplify usage, and to avoid issues with different storage implementations.

    .. uml::

        @startuml
        package "Storage Access API" {
            +enum StorageError {
                CollectionNotFound(String)
                KeyNotFound(String)
                PermissionDenied(String)
                TransactionError(String)
                NoSpaceLeft(String)
                Other(String)
            }

            +enum CollectionName {
                DiagnosticDatabase
                DiagnosticDatabaseNextUpdate
                DiagnosticDatabaseBackup
                Custom(String)
            }

            +interface Storage {
                +get_collection(collection: CollectionName) -> Result<Collection, StorageError>
                +get_or_create_collection(collection: CollectionName) -> Result<Collection, StorageError>
                +create_collection(tx: &TransactionCtx, collection: CollectionName) -> Result<Collection, StorageError>
                +delete_collection(tx: &TransactionCtx, collection: CollectionName) -> Result<(), StorageError>
                +copy_collection(tx: &TransactionCtx, source: CollectionName, destination: CollectionName) -> Result<(), StorageError>
            }

            +interface Collection {
                +read(key: String) -> Result<RandomAccessData, StorageError>
                +write(tx: &TransactionCtx, key: String, data: &ReadableStream) -> Result<(), StorageError>
                +delete(tx: &TransactionCtx, key: String) -> Result<(), StorageError>
                +delete_all(tx: &TransactionCtx) -> Result<(), StorageError>
                +metadata(key: String) -> Result<Metadata, StorageError>
                +list() -> Result<Vec<String>, StorageError>
                +len() -> Result<usize, StorageError>
            }

            +interface Metadata {
                +name() -> Result<String, StorageError>
                +data_size() -> Result<usize, StorageError>
                +custom_props() -> Result<Vec<MetadataProperty>, StorageError>
            }

            +interface MetadataProperty {
                +key() -> String
                +value() -> String
            }

            Storage ..> Collection
            Storage ..> CollectionName
            Collection ..> StorageError
            Collection ..> Metadata
            Storage ..> StorageError
            Metadata ..> StorageError
            Metadata ..> MetadataProperty
        }
        @enduml

    A transaction context shall be created through a ``transaction { ... }`` block, which ensures that all operations
    within the block are treated as a single atomic transaction. If any operation within the block fails, the entire
    transaction will be rolled back, and the result of the transaction will be an error.

    If all operations succeed, the transaction will be committed, and the result will be a success.

    Should an unexpected interruption event (power-off, reset) occur during a transaction, the transaction must be
    rolled back on the next startup, to ensure consistency of the storage state.

    For reading data, random access to the data must be supported, to allow for efficient reading of arbitrary chunks
    without needing to load it entirely into memory. This might be required for memory efficient handling of the
    diagnostic database.

    The ``get_or_create_collection`` function creates an implicit transaction for the creation of the collection only,
    if it does not exist. If the collection already exists, it simply returns it.


Persistence
-----------

.. arch:: Persistence API
    :id: arch~system-persistence-api
    :status: draft

    The Persistence API provides a durable key-value storage abstraction. Data is organized into Buckets, each
    representing a named, logically separated set of key-value pairs. The API is accessed through an exchangeable
    provider, enabling different storage backends without affecting consuming code.

    .. uml::

        @startuml
        package "Persistence API" {
            +enum PersistenceError {
                BucketNotFound(String)
                KeyNotFound(String)
                IoError(String)
                Other(String)
            }

            +interface Persistence {
                +get(bucket: String, key: String) -> Result<String, PersistenceError>
                +set(bucket: String, key: String, value: String) -> Result<(), PersistenceError>
                +delete(bucket: String, key: String) -> Result<(), PersistenceError>
                +contains(bucket: String, key: String) -> Result<bool, PersistenceError>
                +list_keys(bucket: String) -> Result<Vec<String>, PersistenceError>
                +flush() -> Result<(), PersistenceError>
            }

            Persistence ..> PersistenceError
        }
        @enduml

    The ``Persistence`` interface is the single access point for all persistence operations. Callers specify the
    target Bucket by name alongside the key for each operation. Bucket management (creation, lifecycle) is handled
    transparently by the provider implementation.

    The ``flush`` operation explicitly persists all buffered data to the underlying storage media. Providers that
    buffer writes in memory shall guarantee that all data is durable after a successful flush call.

    Providers are exchangeable at compile time, allowing the use of alternative backends (e.g., an in-memory
    provider for testing purposes) without modifying consuming code.


.. arch:: Default redb Persistence Provider
    :id: arch~system-default-redb-persistence-provider
    :status: draft

    The default persistence provider uses `redb`_ as its storage backend. It implements the ``Persistence``
    interface with the following characteristics:

    .. _redb: https://www.redb.org

    * All write operations (set, delete) are performed within ACID transactions, ensuring durability and consistency.
    * The database file path is configurable.
    * On unexpected interruption (power-off, crash), redb guarantees that uncommitted transactions are rolled back
      on the next open, preserving data integrity.


Systemd Watchdog Integration
----------------------------

.. arch:: Systemd Watchdog Integration
    :id: arch~system-sd-notify-watchdog-integration
    :links: dimpl~system-sd-notify-watchdog-integration; test~system-sd-notify-watchdog-integration
    :status: draft

    The systemd watchdog integration is implemented as an optional background task that bridges the CDA health system
    with the systemd service manager notification protocol.

    **Startup Detection**

    At initialization, the component checks whether the process was launched by systemd and whether the watchdog is
    enabled. If either condition is not met, no task is spawned and the CDA operates without watchdog integration.

    **Notification Interval**

    The notification interval is derived from the systemd-configured watchdog timeout, reduced by a safety margin to
    ensure notifications arrive before systemd considers the service unresponsive.

    **Health Aggregation**

    On each tick, the task queries all registered health providers and folds their individual statuses into a single
    aggregated status. The folding semantics are:

    * A single failed provider causes the aggregate to be failed.
    * All providers must report healthy for the aggregate to be healthy.
    * While any provider is still pending or starting, the aggregate remains in the starting state.

    **State Machine**

    The notification sent to systemd is determined by the transition between the previous and current aggregated status:

    .. uml::

        @startuml
        [*] --> Starting
        Starting --> Up : all providers healthy\n(notify: Ready)
        Up --> Up : still healthy\n(notify: Watchdog)
        Up --> Failed : provider degraded\n(notify: WatchdogTrigger)
        @enduml

    **Shutdown**

    The task terminates gracefully when the application shutdown signal is received.
