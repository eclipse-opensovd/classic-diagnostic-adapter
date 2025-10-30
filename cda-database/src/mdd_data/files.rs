/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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
    sync::Arc,
    time::{Duration, Instant},
};

use cda_interfaces::file_manager::{Chunk, ChunkMetaData, MddError};
use hashbrown::HashMap;
use tokio::sync::RwLock;

use crate::mdd_data::load_chunk;

#[derive(Clone)]
pub struct FileManager {
    mdd_path: String,
    files: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

struct CacheEntry {
    last_accessed: Option<Instant>,
    chunk: Chunk,
}

impl FileManager {
    #[must_use]
    pub fn new(mdd_path: String, files: Vec<Chunk>) -> Self {
        let mdd_name = mdd_path.split('/').next_back().unwrap_or("mdd").to_string();
        let cache_lifetime = Duration::from_secs(60 * 5);

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

        let files_clone = Arc::clone(&files);
        cda_interfaces::spawn_named!(&format!("filemanager-cache-{mdd_name}"), async move {
            loop {
                let next_expiration = {
                    let now = Instant::now();
                    let mut files_lock = files_clone.write().await;
                    files_lock
                        .values_mut()
                        .filter_map(|entry| {
                            entry.last_accessed.map(|last_accessed| {
                                let elapsed = now.duration_since(last_accessed);
                                if let Some(lifetime) = cache_lifetime.checked_sub(elapsed) {
                                    Some(lifetime)
                                } else {
                                    tracing::debug!(
                                        file_name = %entry.chunk.meta_data.name,
                                        elapsed = ?elapsed,
                                        cache_lifetime = ?cache_lifetime,
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
                    cache_lifetime
                };
                tokio::time::sleep(sleep_time).await;
            }
        });

        Self { mdd_path, files }
    }
}

impl cda_interfaces::file_manager::FileManager for FileManager {
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
    /// Also returns the errors from `load_data` if the chunk data cannot be read or
    /// parsed correctly.
    async fn get(&self, id: &str) -> Result<(ChunkMetaData, Vec<u8>), MddError> {
        let mut files = self.files.write().await;
        files.get_mut(id).map_or(
            Err(MddError::InvalidParameter(format!(
                "No file with name {id} found"
            ))),
            |cache| {
                cache.last_accessed = Some(Instant::now());
                Ok((
                    cache.chunk.meta_data.clone(),
                    load_chunk(&mut cache.chunk, &self.mdd_path).cloned()?,
                ))
            },
        )
    }
}
