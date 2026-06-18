/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

use std::sync::Arc;

use super::{
    collection::{Collection, CollectionName, DirectFileAccess},
    error::StorageError,
    transaction::Transaction,
};

/// Top-level storage abstraction.
///
/// Provides access to named collections and manages transaction lifecycle. Only one transaction
/// may be active at a time. Attempting to begin a second transaction returns
/// [`StorageError::TransactionBusy`].
///
/// Reads are always available (even while a transaction is open) and return committed state.
/// During [`Transaction::commit`], reads are blocked until the commit completes to ensure
/// consistency.
pub trait Storage: Send + Sync {
    /// The concrete collection type returned by this storage backend.
    type CollectionHandle: Collection + DirectFileAccess + Send + Sync + 'static;

    /// Get an existing collection by name.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::CollectionNotFound`] if the collection does not exist.
    fn get_collection(
        &self,
        name: &CollectionName,
    ) -> impl Future<Output = Result<Arc<Self::CollectionHandle>, StorageError>> + Send;

    /// Get a collection by name, creating it if it does not already exist.
    ///
    /// If the collection does not exist, it is created in an implicit single-operation
    /// transaction (i.e., no explicit transaction is required).
    fn get_or_create_collection(
        &self,
        name: &CollectionName,
    ) -> impl Future<Output = Result<Arc<Self::CollectionHandle>, StorageError>> + Send;

    /// Begin a new transaction.
    ///
    /// Returns a [`Transaction`] that can be passed to mutation methods on [`Collection`] and
    /// [`Storage`].
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::TransactionBusy`] if a transaction is already active.
    fn begin_transaction(&self) -> Result<Transaction, StorageError>;

    /// Create a new, empty collection within a transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::TransactionConflict`] if the collection already exists, or if no
    /// transaction is active.
    fn create_collection(
        &self,
        tx: &mut Transaction,
        name: &CollectionName,
    ) -> impl Future<Output = Result<Arc<Self::CollectionHandle>, StorageError>> + Send;

    /// Delete a collection and all its entries within a transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::CollectionNotFound`] if the collection does not exist.
    fn delete_collection(
        &self,
        tx: &mut Transaction,
        name: &CollectionName,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Copy all entries from one collection to another within a transaction.
    ///
    /// If the destination collection does not exist, it is created. If it already exists, its
    /// contents are replaced.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::CollectionNotFound`] if the source collection does not exist.
    fn copy_collection(
        &self,
        tx: &mut Transaction,
        source: &CollectionName,
        dest: &CollectionName,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}
