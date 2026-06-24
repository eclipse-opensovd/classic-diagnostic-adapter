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
    Collection,
    CollectionName,
    Storage,
};

/// Seeds a storage collection from an iterator of `(key, data)` pairs when the collection is
/// empty.  No-op if the collection is already populated or the iterator yields no items.
///
/// Returns the number of entries written, or `None` when seeding was skipped.
pub async fn seed_storage_collection(
    storage: &impl Storage,
    collection_name: &CollectionName,
    entries: impl IntoIterator<Item = (String, Vec<u8>)>,
) -> Option<usize> {
    let collection = match storage.get_or_create_collection(collection_name).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                collection = %collection_name,
                error = %e,
                "Cannot access collection, skipping seed"
            );
            return None;
        }
    };

    match collection.is_empty().await {
        Ok(true) => {}
        Ok(false) => {
            tracing::debug!(collection = %collection_name, "Collection already populated, skipping seed");
            return None;
        }
        Err(e) => {
            tracing::warn!(
                collection = %collection_name,
                error = %e,
                "Failed to check collection, skipping seed"
            );
            return None;
        }
    }

    let mut tx = match storage.begin_transaction() {
        Ok(tx) => tx,
        Err(e) => {
            tracing::warn!(error = %e, "Cannot begin transaction for seeding");
            return None;
        }
    };

    let mut count = 0usize;
    for (key, data) in entries {
        let mut cursor = std::io::Cursor::new(data);
        if let Err(e) = collection.write(&mut tx, &key, &mut cursor).await {
            tracing::warn!(key, collection = %collection_name, error = %e, "Failed to write entry to storage, skipping");
            continue;
        }
        count = count.saturating_add(1);
    }

    if count == 0 {
        return Some(0);
    }

    if let Err(e) = tx.commit().await {
        tracing::error!(error = %e, "Failed to commit seed transaction");
        return None;
    }

    Some(count)
}
