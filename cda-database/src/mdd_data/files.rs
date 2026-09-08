/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use cda_interfaces::{
    HashMap, dlt_ctx,
    mdd_chunks::{Chunk, ChunkMetaData, MddError},
};
use tokio::sync::RwLock;

use crate::mdd_data::load_chunk;

#[allow(
    unknown_lints,
    clippy::duration_suboptimal_units,
    reason = "Literal duration value is intentional. Duration_suboptimal_units not available in \
              all toolchain versions"
)]
const CACHE_LIFETIME: Duration = Duration::from_secs(60 * 5);

pub struct EmbeddedFileStore {
    mdd_path: String,
    files: Arc<RwLock<HashMap<String, CacheEntry>>>,
    expiry: Option<tokio::task::JoinHandle<()>>,
}

struct CacheEntry {
    last_accessed: Option<Instant>,
    chunk: Chunk,
}

impl EmbeddedFileStore {
    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("DB"),
        )
    )]
    #[must_use]
    pub fn new(mdd_path: String, files: Vec<Chunk>) -> Self {
        let files = Arc::new(RwLock::new(
            files
                .into_iter()
                .map(|chunk| {
                    (
                        uuid::Uuid::new_v4().to_string(),
                        CacheEntry {
                            last_accessed: None,
                            chunk,
                        },
                    )
                })
                .collect::<HashMap<_, _>>(),
        ));

        Self {
            mdd_path,
            files,
            expiry: None,
        }
    }

    /// Starts the cache expiry task, which drops payloads that have not been
    /// accessed for `CACHE_LIFETIME`.
    ///
    /// Separate from [`Self::new`], so a store can be built outside a tokio
    /// runtime; only the production load path starts the task. The task holds a
    /// strong handle to the cache because its lifetime is bounded by the
    /// store's: [`Drop`] aborts it, so teardown happens at the point the store
    /// is dropped instead of at some later tick.
    ///
    /// The task name is observability only, so a path with no file name falls
    /// back to a placeholder rather than costing the caller its ECU database.
    #[must_use]
    pub fn with_expiry(mut self) -> Self {
        let mdd_name = Path::new(&self.mdd_path).file_name().map_or_else(
            || "unnamed".to_owned(),
            |name| name.to_string_lossy().into_owned(),
        );
        let files = Arc::clone(&self.files);
        self.expiry = Some(cda_interfaces::spawn_named!(
            &format!("filemanager-cache-{mdd_name}"),
            async move {
                loop {
                    let next_expiration = {
                        let now = Instant::now();
                        let mut files_lock = files.write().await;
                        files_lock
                            .values_mut()
                            .filter_map(|entry| {
                                entry.last_accessed.map(|last_accessed| {
                                    let elapsed = now.duration_since(last_accessed);
                                    if let Some(lifetime) = CACHE_LIFETIME.checked_sub(elapsed) {
                                        Some(lifetime)
                                    } else {
                                        tracing::debug!(
                                            file_name = %entry.chunk.meta_data.name,
                                            elapsed = ?elapsed,
                                            cache_lifetime = ?CACHE_LIFETIME,
                                            "Removing expired cache entry for file"
                                        );
                                        entry.chunk.payload = None;
                                        None
                                    }
                                })
                            })
                            .flatten()
                            .min()
                    };

                    let sleep_time = if let Some(duration) = next_expiration {
                        duration
                    } else {
                        CACHE_LIFETIME
                    };
                    cda_interfaces::util::tokio_ext::sleep_for(sleep_time).await;
                }
            }
        ));
        self
    }

    /// Drops every cached payload, without waiting for it to expire.
    ///
    /// Called when the owning `EcuManager` unloads its database, so everything
    /// derived from one MDD is released at the same point.
    pub async fn release(&self) {
        for entry in self.files.write().await.values_mut() {
            entry.last_accessed = None;
            entry.chunk.payload = None;
        }
    }
}

impl Drop for EmbeddedFileStore {
    fn drop(&mut self) {
        if let Some(task) = self.expiry.take() {
            task.abort();
        }
    }
}

impl cda_interfaces::mdd_chunks::EmbeddedFiles for EmbeddedFileStore {
    async fn list(&self) -> HashMap<String, ChunkMetaData> {
        self.files
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.chunk.meta_data.clone()))
            .collect()
    }

    /// Retrieves the data of a file along with its metadata by its ID.
    /// # Errors
    /// If the file with the given ID does not exist, it returns an `MddError::InvalidParameter`.
    /// Also returns the errors from `load_chunk` if the chunk data cannot be read or
    /// parsed correctly.
    async fn get(&self, id: &str) -> Result<(ChunkMetaData, Bytes), MddError> {
        let mut files = self.files.write().await;
        files.get_mut(id).map_or(
            Err(MddError::InvalidParameter(format!(
                "No file with name {id} found"
            ))),
            |cache| {
                cache.last_accessed = Some(Instant::now());
                Ok((
                    cache.chunk.meta_data.clone(),
                    load_chunk(&mut cache.chunk, &self.mdd_path)?.clone(),
                ))
            },
        )
    }
}
