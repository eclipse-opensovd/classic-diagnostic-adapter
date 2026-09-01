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

use cda_interfaces::storage_api::{
    Collection, CollectionName, ReadableStream, Storage, StorageError,
};

/// Seeds a storage collection from an iterator of `(key, data)` pairs when the collection does
/// not exist yet. No-op if the collection already exists.
///
/// Returns the number of entries written, or `None` when seeding was skipped.
pub async fn seed_storage_collection_if_nonexistent(
    storage: &impl Storage,
    collection_name: &CollectionName,
    entries: impl IntoIterator<Item = (String, impl ReadableStream)>,
) -> Option<usize> {
    let mut tx = match storage.begin_transaction() {
        Ok(tx) => tx,
        Err(e) => {
            tracing::warn!(error = %e, "Cannot begin transaction for seeding");
            return None;
        }
    };

    match storage.get_collection(collection_name).await {
        Err(StorageError::CollectionNotFound(_)) => {} // continue
        Ok(_) => {
            tracing::debug!(collection = %collection_name, "Collection already exists, skipping seed.");
            return None;
        }
        Err(error) => {
            tracing::warn!(
                collection = %collection_name,
                error = %error,
                "Failed to check collection, skipping seed"
            );
            return None;
        }
    }

    let collection = match storage.create_collection(&mut tx, collection_name).await {
        Ok(collection) => collection,
        Err(source) => {
            tracing::warn!(
                collection = %collection_name,
                error = %source,
                "Cannot create collection, skipping seed"
            );
            return None;
        }
    };

    let mut count = 0usize;
    for (key, mut data) in entries {
        if let Err(e) = collection.write(&mut tx, &key, &mut data).await {
            tracing::warn!(key, collection = %collection_name, error = %e, "Failed to write entry to storage, skipping");
            continue;
        }
        count = count.saturating_add(1);
    }

    // Commit even with no entries: creating the collection is itself the durable
    // record that seeding ran, and later resolution treats an existing empty
    // collection as authoritative instead of falling back to the seed directory.
    if let Err(e) = tx.commit().await {
        tracing::error!(error = %e, "Failed to commit seed transaction");
        return None;
    }

    Some(count)
}
