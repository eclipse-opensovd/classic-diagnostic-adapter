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

//! The diagnostic databases in storage and in the configured `database.dir`.
//!
//! Startup never writes to the storage, so the CDA can run from a read-only
//! partition. Until the storage is seeded, the databases in `database.dir` are
//! the current ones. The first write of an update seeds the storage from
//! `database.dir`, exactly once, see [`seed_if_nonexistent`].
//! From then on the storage holds the current databases, and `database.dir` is ignored.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use cda_interfaces::{
    HashMap, HashMapEntry, HashMapExtensions,
    storage_api::{Collection, CollectionName, Storage, StorageError},
};

/// Where the current diagnostic databases are.
pub enum DatabaseLocation<C> {
    /// The storage was seeded. This collection holds the current databases.
    Storage(Arc<C>),
    /// The storage was never seeded. These MDD files in `database.dir` are current.
    Dir(Vec<PathBuf>),
}

/// Returns where the current diagnostic databases are: the `DiagnosticDatabase` collection
/// whenever it exists, even when it is empty, otherwise the MDD files in `database_dir`.
///
/// # Errors
///
/// Returns [`StorageError`] if the collection cannot be accessed, or the storage was not seeded
/// yet and `database_dir` cannot be read.
pub async fn current_database_location<S: Storage>(
    storage: &S,
    database_dir: &Path,
) -> Result<DatabaseLocation<S::CollectionHandle>, StorageError> {
    Ok(match seeded_collection(storage).await? {
        Some(collection) => DatabaseLocation::Storage(collection),
        None => DatabaseLocation::Dir(mdd_files_in_dir(database_dir).await?),
    })
}

/// Returns the `DiagnosticDatabase` collection, or `None` while the storage is not seeded.
async fn seeded_collection<S: Storage>(
    storage: &S,
) -> Result<Option<Arc<S::CollectionHandle>>, StorageError> {
    match storage
        .get_collection(&CollectionName::DiagnosticDatabase)
        .await
    {
        Ok(collection) => Ok(Some(collection)),
        Err(StorageError::CollectionNotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Returns the name of the database in the MDD file at `path`: its lowercase file name, the key
/// it is stored under once seeded.
///
/// # Errors
///
/// Returns [`StorageError`] if the file name is not valid UTF-8. A lossy conversion could map
/// different files to the same name, so one database would silently replace another.
pub fn database_name(path: &Path) -> Result<String, StorageError> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_lowercase)
        .ok_or_else(|| {
            StorageError::Other(format!(
                "File name of '{}' is not valid UTF-8",
                path.display()
            ))
        })
}

/// Returns the MDD files in `dir`, in no particular order.
///
/// # Errors
///
/// Returns [`StorageError`] if `dir` cannot be read, including when it does not exist. A missing
/// directory is a misconfiguration, not an empty set of databases: seeding it would commit an
/// empty database that is never seeded again, even after the directory appears.
///
/// Also fails if a file name is not valid UTF-8.
///
/// Names are case-insensitive, so e.g. `ECU.mdd` and `ecu.mdd` are the same database. Of such
/// files only the one with the newer revision is returned, see [`is_preferred`], so loading,
/// listing and seeding all use the same one.
pub async fn mdd_files_in_dir(dir: &Path) -> Result<Vec<PathBuf>, StorageError> {
    let mut entries = tokio::fs::read_dir(dir).await?;

    // Names are case-insensitive, so e.g. `ECU.mdd` and `ecu.mdd` are the same database.
    let mut files: HashMap<String, PathBuf> = HashMap::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "mdd")
            && tokio::fs::metadata(&path)
                .await
                .is_ok_and(|meta| meta.is_file())
        {
            match files.entry(database_name(&path)?) {
                HashMapEntry::Vacant(entry) => {
                    entry.insert(path);
                }
                HashMapEntry::Occupied(mut entry) => {
                    let ignored = if is_preferred(&path, entry.get()) {
                        entry.insert(path)
                    } else {
                        path
                    };
                    tracing::warn!(
                        database = %entry.key(),
                        kept = %entry.get().display(),
                        ignored = %ignored.display(),
                        "Two files have the same database name, keeping the newer revision."
                    );
                }
            }
        }
    }
    Ok(files.into_values().collect())
}

/// Whether the MDD file at `candidate` replaces the one at `current` with the same database
/// name: it has a newer revision, or the same revision and is larger. This is the file the
/// startup keeps when it loads both.
fn is_preferred(candidate: &Path, current: &Path) -> bool {
    let rank = |path: &Path| {
        let size = std::fs::metadata(path).map_or(0, |meta| meta.len());
        (mdd_revision(path), size)
    };
    rank(candidate) > rank(current)
}

/// The revision in the header of the MDD file at `path`. A file whose header cannot be read
/// ranks as the oldest.
fn mdd_revision(path: &Path) -> Option<String> {
    let decoded = path
        .to_str()
        .ok_or_else(|| "path is not valid UTF-8".to_owned())
        .and_then(|path| crate::mmap_and_decode_mdd(path).map_err(|e| e.to_string()));
    match decoded {
        Ok(mdd) => mdd.revision,
        Err(error) => {
            tracing::error!(path = %path.display(), %error, "Cannot read the MDD revision.");
            None
        }
    }
}

/// Seeds `DiagnosticDatabase` from the MDD files in `database_dir`, unless it already exists.
///
/// The seed holds exactly the databases the CDA runs from `database_dir`, so the running state
/// does not change, and an update, its backup and its rollback start from them. Update plugins
/// call this before their first write of an update.
///
/// Seeding is keyed on the collection's existence, not its emptiness: the collection is created
/// even when `database_dir` holds no databases, so a database that was emptied on purpose is
/// never seeded again.
///
/// Commits its own transaction, so no other transaction may be active.
///
/// Returns the number of databases seeded, or `None` when the collection already existed.
///
/// # Errors
///
/// Returns [`StorageError`] if `database_dir` or one of its MDD files cannot be read, or the
/// storage cannot be written. Nothing is committed in that case.
pub async fn seed_if_nonexistent(
    storage: &impl Storage,
    database_dir: &Path,
) -> Result<Option<usize>, StorageError> {
    // Checked again inside the transaction, this only avoids opening the files needlessly.
    if seeded_collection(storage).await?.is_some() {
        return Ok(None);
    }

    let mut files = Vec::new();
    for path in mdd_files_in_dir(database_dir).await? {
        let key = database_name(&path)?;
        let file = tokio::fs::File::open(&path).await?;
        files.push((key, file));
    }

    let mut tx = storage.begin_transaction()?;

    // Checked inside the transaction, so a concurrent seed either fails to begin its
    // transaction or sees the committed collection.
    if seeded_collection(storage).await?.is_some() {
        return Ok(None);
    }

    let collection = storage
        .create_collection(&mut tx, &CollectionName::DiagnosticDatabase)
        .await?;
    let count = files.len();
    for (key, mut file) in files {
        collection.write(&mut tx, &key, &mut file).await?;
    }
    tx.commit().await?;

    tracing::info!(
        database_count = %count,
        database_dir = %database_dir.display(),
        "Seeded DiagnosticDatabase from the database directory."
    );
    Ok(Some(count))
}

#[cfg(test)]
mod tests {
    use cda_interfaces::storage_api::DirectFileAccess;
    use cda_storage::LocalStorage;
    use tempfile::TempDir;

    use super::*;

    /// A file in the test `database.dir`.
    struct DirFile {
        name: &'static str,
        content: &'static [u8],
    }

    struct Fixture {
        storage: LocalStorage,
        database_dir: TempDir,
        _storage_dir: TempDir,
    }

    impl Fixture {
        /// Storage without any collection, and a `database.dir` holding `files` plus a file
        /// that is not a database.
        fn new(files: &[DirFile]) -> Self {
            let storage_dir = tempfile::tempdir().expect("storage dir");
            let database_dir = tempfile::tempdir().expect("database dir");
            for file in files {
                std::fs::write(database_dir.path().join(file.name), file.content)
                    .expect("write MDD file");
            }
            std::fs::write(database_dir.path().join("readme.txt"), b"not a database")
                .expect("write file");
            Self {
                storage: LocalStorage::new(storage_dir.path()).expect("storage"),
                database_dir,
                _storage_dir: storage_dir,
            }
        }

        async fn create_empty_collection(&self) {
            let mut tx = self.storage.begin_transaction().unwrap();
            self.storage
                .create_collection(&mut tx, &CollectionName::DiagnosticDatabase)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }

        async fn keys(&self) -> Vec<String> {
            let mut keys = self
                .storage
                .get_collection(&CollectionName::DiagnosticDatabase)
                .await
                .expect("collection exists")
                .list()
                .await
                .unwrap();
            keys.sort();
            keys
        }
    }

    #[tokio::test]
    async fn current_databases_are_served_from_dir_until_seeded() {
        let fixture = Fixture::new(&[DirFile {
            name: "ECU_A.mdd",
            content: b"A",
        }]);

        let DatabaseLocation::Dir(paths) =
            current_database_location(&fixture.storage, fixture.database_dir.path())
                .await
                .unwrap()
        else {
            panic!("an unseeded storage must fall back to database.dir");
        };
        assert_eq!(paths, vec![fixture.database_dir.path().join("ECU_A.mdd")]);
    }

    #[tokio::test]
    async fn current_databases_are_an_existing_empty_collection() {
        let fixture = Fixture::new(&[DirFile {
            name: "ECU_A.mdd",
            content: b"A",
        }]);
        fixture.create_empty_collection().await;

        let current = current_database_location(&fixture.storage, fixture.database_dir.path())
            .await
            .unwrap();
        assert!(
            matches!(current, DatabaseLocation::Storage(_)),
            "an empty collection is a deliberate empty data set, not a reason to use the dir"
        );
    }

    #[tokio::test]
    async fn seed_copies_the_mdd_files_with_lowercase_keys() {
        let fixture = Fixture::new(&[
            DirFile {
                name: "ECU_A.mdd",
                content: b"A",
            },
            DirFile {
                name: "ecu_b.mdd",
                content: b"B",
            },
        ]);

        let count = seed_if_nonexistent(&fixture.storage, fixture.database_dir.path())
            .await
            .unwrap();

        assert_eq!(count, Some(2));
        assert_eq!(fixture.keys().await, vec!["ecu_a.mdd", "ecu_b.mdd"]);
        let collection = fixture
            .storage
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(collection.file_path("ecu_a.mdd").unwrap()).unwrap(),
            b"A",
            "seeding must preserve the file content"
        );
    }

    #[tokio::test]
    async fn seed_skips_an_existing_empty_collection() {
        let fixture = Fixture::new(&[DirFile {
            name: "ecu_a.mdd",
            content: b"A",
        }]);
        fixture.create_empty_collection().await;

        let count = seed_if_nonexistent(&fixture.storage, fixture.database_dir.path())
            .await
            .unwrap();

        assert_eq!(count, None);
        assert!(
            fixture.keys().await.is_empty(),
            "a database emptied on purpose must not be seeded again"
        );
    }

    #[tokio::test]
    async fn seed_from_an_empty_dir_creates_an_empty_collection() {
        let fixture = Fixture::new(&[]);

        let count = seed_if_nonexistent(&fixture.storage, fixture.database_dir.path())
            .await
            .unwrap();

        assert_eq!(count, Some(0));
        assert!(
            fixture.keys().await.is_empty(),
            "the seed must create the collection even without files, so it runs only once"
        );
    }

    #[tokio::test]
    async fn seed_from_a_missing_dir_fails_without_creating_the_collection() {
        let fixture = Fixture::new(&[]);
        let missing = fixture.database_dir.path().join("missing");

        let result = seed_if_nonexistent(&fixture.storage, &missing).await;

        assert!(
            result.is_err(),
            "a missing database.dir is a misconfiguration"
        );
        assert!(
            matches!(
                fixture
                    .storage
                    .get_collection(&CollectionName::DiagnosticDatabase)
                    .await,
                Err(StorageError::CollectionNotFound(_))
            ),
            "the seed must stay possible once the directory appears"
        );
    }

    #[tokio::test]
    async fn current_databases_fail_for_a_missing_dir_until_seeded() {
        let fixture = Fixture::new(&[]);
        let missing = fixture.database_dir.path().join("missing");

        let result = current_database_location(&fixture.storage, &missing).await;

        assert!(
            matches!(result, Err(StorageError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound),
            "a missing database.dir must not look like an empty one"
        );
    }

    /// A minimal MDD file for `ecu` with the header revision `revision`.
    fn mdd(ecu: &str, revision: &str) -> Vec<u8> {
        mdd_with_version(ecu, revision, "1")
    }

    /// Like [`mdd`], with a format `version` whose length controls the file size.
    fn mdd_with_version(ecu: &str, revision: &str, version: &str) -> Vec<u8> {
        let mut buf = b"MDD version 0      \0".to_vec();
        for (tag, value) in [(0x0A, version), (0x1A, ecu), (0x22, revision)] {
            buf.push(tag);
            buf.push(u8::try_from(value.len()).unwrap());
            buf.extend_from_slice(value.as_bytes());
        }
        buf
    }

    /// Writes `ECU.mdd` and `ecu.mdd`, or returns `None` on a case-insensitive file system,
    /// where both names are the same file.
    fn write_case_duplicates(dir: &Path, upper: &[u8], lower: &[u8]) -> Option<()> {
        std::fs::write(dir.join("ECU.mdd"), upper).unwrap();
        std::fs::write(dir.join("ecu.mdd"), lower).unwrap();
        (std::fs::read_dir(dir).unwrap().count() == 3).then_some(())
    }

    #[test]
    fn newer_revision_is_preferred_regardless_of_size() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("old.mdd");
        let new = dir.path().join("new.mdd");
        std::fs::write(&old, mdd_with_version("ECU", "1.0", &"1".repeat(64))).unwrap();
        std::fs::write(&new, mdd("ECU", "2.0")).unwrap();

        assert!(
            mdd_revision(&old).is_some(),
            "the larger file must stay a valid MDD"
        );
        assert!(is_preferred(&new, &old));
        assert!(!is_preferred(&old, &new));
    }

    #[test]
    fn same_revision_prefers_the_larger_file_like_the_startup() {
        let dir = tempfile::tempdir().unwrap();
        let small = dir.path().join("small.mdd");
        let large = dir.path().join("large.mdd");
        std::fs::write(&small, mdd("ECU", "1.0")).unwrap();
        std::fs::write(&large, mdd_with_version("ECU", "1.0", &"1".repeat(64))).unwrap();

        assert!(
            mdd_revision(&large).is_some(),
            "the larger file must stay a valid MDD"
        );
        assert!(is_preferred(&large, &small));
        assert!(!is_preferred(&small, &large));
    }

    #[test]
    fn unreadable_mdd_ranks_as_the_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let broken = dir.path().join("broken.mdd");
        let valid = dir.path().join("valid.mdd");
        std::fs::write(&broken, vec![0xFF; 256]).unwrap();
        std::fs::write(&valid, mdd("ECU", "0.1")).unwrap();

        assert!(is_preferred(&valid, &broken));
        assert!(!is_preferred(&broken, &valid));
    }

    #[tokio::test]
    async fn current_databases_keep_the_newer_of_two_files_with_the_same_name() {
        let fixture = Fixture::new(&[]);
        let dir = fixture.database_dir.path();
        let Some(()) = write_case_duplicates(dir, &mdd("ECU", "2.0"), &mdd("ECU", "1.0")) else {
            return;
        };

        let DatabaseLocation::Dir(paths) = current_database_location(&fixture.storage, dir)
            .await
            .unwrap()
        else {
            panic!("an unseeded storage must fall back to database.dir");
        };

        assert_eq!(paths, vec![dir.join("ECU.mdd")]);
    }

    #[tokio::test]
    async fn seed_keeps_the_newer_of_two_files_with_the_same_name() {
        let fixture = Fixture::new(&[]);
        let dir = fixture.database_dir.path();
        let newer = mdd("ECU", "2.0");
        let Some(()) = write_case_duplicates(dir, &mdd("ECU", "1.0"), &newer) else {
            return;
        };

        let count = seed_if_nonexistent(&fixture.storage, dir).await.unwrap();

        assert_eq!(count, Some(1));
        let collection = fixture
            .storage
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(collection.file_path("ecu.mdd").unwrap()).unwrap(),
            newer
        );
    }
}
