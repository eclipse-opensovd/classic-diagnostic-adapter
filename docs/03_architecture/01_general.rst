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

    The Storage Access API provides an abstraction layer for storage access, allowing the CDA to interact with different types of storage systems (e.g., local file system, databases) without being tightly coupled to a specific implementation.

    To achieve atomicity and consistent behavior across different storage implementations, the API defines the following semantics:

    * All operations must be atomic, meaning that either all changes are applied successfully, or none are applied in case of an error.
    * The API should provide a consistent interface for reading and writing data, regardless of the underlying storage system.
    * Error handling should be standardized, allowing the CDA to gracefully handle storage-related exceptions and errors.
    * Keys shall be handled case-insensitive, to simplify usage, and to avoid issues with different storage implementations.

    .. uml::

        @startuml
        package "Storage Access API" {
            enum StorageError {
                CollectionNotFound
                KeyNotFound
                PermissionDenied
                TransactionError
                NoSpaceLeft
                Other(String)
            }

            enum CollectionName {
                DiagnosticDatabase
                DiagnosticDatabaseNextUpdate
                DiagnosticDatabaseBackup
                Custom(String) // For plugins to define their own collections
            }

            interface Storage {
                +get_collection(collection: CollectionName) -> Result<Collection, StorageError>
                +get_or_create_collection(collection: CollectionName) -> Result<Collection, StorageError>
                +create_collection(tx: &TransactionCtx, collection: CollectionName) -> Result<Collection, StorageError>
                +delete_collection(tx: &TransactionCtx, collection: CollectionName) -> Result<(), StorageError>
                +copy_collection(tx: &TransactionCtx, source: CollectionName, destination: CollectionName, options: CopyOptions) -> Result<(), StorageError>
            }

            interface Collection {
                +read(key: &str) -> Result<ReadableStream, StorageError>
                +write(tx: &TransactionCtx, key: &str, data: &ReadableStream) -> Result<(), StorageError>
                +delete(tx: &TransactionCtx, key: &str) -> Result<(), StorageError>
                +delete_all(tx: &TransactionCtx) -> Result<(), StorageError>
                +metadata(key: &str) -> Result<Metadata, StorageError>
                +list() -> Result<Vec<String>, StorageError>
                +len() -> Result<usize, StorageError>
            }

            interface Metadata {
                +name() -> Result<String, StorageError>
                +data_size() -> Result<usize, StorageError>
                +custom_props() -> Result<dict[String, String], StorageError>
            }

            Storage ..> Collection
            Storage ..> CollectionName
            Collection ..> StorageError
            Collection ..> Metadata
            Storage ..> StorageError
            Metadata ..> StorageError
        }
        @enduml
