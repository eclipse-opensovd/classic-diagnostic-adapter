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
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use cda_comm_doip::DoipDiagGateway;
use cda_comm_uds::UdsManager;
use cda_core::{DiagServiceResponseStruct, EcuManager};
use cda_database::{FileManager, ProtoLoadConfig};
use cda_interfaces::{
    Protocol, TesterPresentControlMessage,
    datatypes::{ComParams, DatabaseNamingConvention},
    file_manager::{Chunk, ChunkType},
};
use cda_sovd::WebServerConfig;
use hashbrown::HashMap;
use tokio::{
    signal,
    sync::{RwLock, mpsc},
};
use tracing::Instrument;

pub mod config;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// todo scope after poc: make this configurable
const DB_PARALLEL_LOAD_TASKS: usize = 2;

pub type DatabaseMap = HashMap<String, RwLock<EcuManager>>;
pub type FileManagerMap = HashMap<String, FileManager>;

#[tracing::instrument(skip(com_params, database_naming_convention), fields(databases_path))]
pub async fn load_databases(
    databases_path: &str,
    protocol: Protocol,
    com_params: ComParams,
    database_naming_convention: DatabaseNamingConvention,
) -> (DatabaseMap, FileManagerMap) {
    let databases: Arc<RwLock<HashMap<String, EcuManager>>> = Arc::new(RwLock::new(HashMap::new()));

    let file_managers: Arc<RwLock<HashMap<String, FileManager>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let com_params = Arc::new(com_params);

    let mut database_load_futures = Vec::new();
    let databases_count = Arc::new(AtomicUsize::new(0));
    let start = std::time::Instant::now();
    'load_database: {
        let files = match std::fs::read_dir(databases_path) {
            Ok(files) => files,
            Err(e) => {
                tracing::error!(error = %e, "Failed to read directory");
                break 'load_database;
            }
        };
        let mut files = files
            .filter_map(|entry| {
                entry.ok().and_then(|entry| {
                    let path = entry.path();
                    if path.is_file() && path.extension().is_some_and(|ext| ext == "mdd") {
                        let filesize = std::fs::metadata(&path).ok().map_or(0u64, |m| m.len());
                        Some((path, filesize))
                    } else {
                        None
                    }
                })
            })
            .collect::<Vec<_>>();

        files.sort_by(|a, b| b.1.cmp(&a.1));

        let chunk_size = (files.len() / DB_PARALLEL_LOAD_TASKS + 1).max(1);

        tracing::info!(chunk_size = %chunk_size, "Loading databases");

        for (i, mddfiles) in files.chunks(chunk_size).enumerate() {
            let database = Arc::clone(&databases);
            let file_managers = Arc::clone(&file_managers);
            let paths = mddfiles.to_vec();
            let database_count = Arc::clone(&databases_count);
            let com_params = Arc::clone(&com_params);
            let database_naming_convention = database_naming_convention.clone();

            database_load_futures.push(cda_interfaces::spawn_named!(
                &format!("load-database-{i}"),
                async move {
                    load_database(
                        protocol,
                        database,
                        file_managers,
                        paths,
                        database_count,
                        com_params,
                        database_naming_convention,
                    )
                    .await;
                }
                .instrument(tracing::info_span!("load_database_chunk", chunk_id = i))
            ));
        }
    }

    for f in database_load_futures {
        tokio::select! {
            () = shutdown_signal() => {
                tracing::info!("Shutdown triggered. Aborting DB load...");
                std::process::exit(0);
            },
            res = f =>{
                if let Err(e) = res {
                    tracing::error!(error = ?e, "Failed to load ecu data");
                }
            }
        }
    }
    let end = std::time::Instant::now();
    let databases = databases
        .write()
        .await
        .drain()
        .map(|(k, v)| (k.to_lowercase().to_string(), RwLock::new(v)))
        .collect::<HashMap<String, RwLock<EcuManager>>>();

    let file_managers = file_managers
        .write()
        .await
        .drain()
        .map(|(k, v)| (k.to_lowercase().to_string(), v))
        .collect::<HashMap<String, FileManager>>();

    tracing::info!(database_count = %databases_count.load(Ordering::Relaxed), duration = ?{end - start}, "Loaded databases");
    if databases_count.load(Ordering::Relaxed) == 0 {
        tracing::error!("Database load failed, no databases found");
        std::process::exit(1);
    }

    (databases, file_managers)
}

#[tracing::instrument(skip_all, fields(paths_count = paths.len()))]
async fn load_database(
    protocol: Protocol,
    database: Arc<RwLock<HashMap<String, EcuManager>>>,
    file_managers: Arc<RwLock<HashMap<String, FileManager>>>,
    paths: Vec<(PathBuf, u64)>,
    database_count: Arc<AtomicUsize>,
    com_params: Arc<ComParams>,
    database_naming_convention: DatabaseNamingConvention,
) {
    for (mddfile, _) in paths {
        match cda_database::load_proto_data(
            mddfile.to_str().unwrap(),
            &[
                ProtoLoadConfig {
                    type_: ChunkType::DiagnosticDescription,
                    load_data: true,
                    name: None,
                },
                ProtoLoadConfig {
                    type_: ChunkType::JarFile,
                    load_data: false,
                    name: None,
                },
                ProtoLoadConfig {
                    type_: ChunkType::JarFilePartial,
                    load_data: false,
                    name: None,
                },
                ProtoLoadConfig {
                    type_: ChunkType::EmbeddedFile,
                    load_data: false,
                    name: None,
                },
            ],
        ) {
            Ok((ecu_name, mut proto_data)) => {
                let Some(ecu_data) = proto_data.remove(&ChunkType::DiagnosticDescription) else {
                    tracing::error!(mdd_file = %mddfile.display(), "No diagnostic description found in MDD file");
                    continue;
                };

                let ecu_payload: Vec<u8> = if let Some(payload) =
                    ecu_data.into_iter().next().and_then(|c| c.payload)
                {
                    payload
                } else {
                    tracing::error!(ecu_name = %ecu_name, "No payload found in diagnostic description for ECU");
                    continue;
                };

                let diag_data_base = match cda_database::datatypes::DiagnosticDatabase::new(
                    mddfile.to_str().unwrap().to_owned(),
                    &ecu_payload,
                ) {
                    Ok(db) => db,
                    Err(e) => {
                        tracing::error!(mdd_file = %mddfile.display(), error = %e, "Failed to create database from MDD file");
                        continue;
                    }
                };
                let diag_service_manager = match EcuManager::new(
                    diag_data_base,
                    protocol,
                    &com_params,
                    database_naming_convention.clone(),
                )
                .map_err(|e| format!("Failed to create DiagServiceManager: {e:?}"))
                {
                    Ok(manager) => manager,
                    Err(e) => {
                        tracing::error!(ecu_name = %ecu_name, error = ?e, "Failed to create DiagServiceManager");
                        continue;
                    }
                };
                database
                    .write()
                    .await
                    .insert(ecu_name.clone(), diag_service_manager);
                database_count.fetch_add(1, Ordering::SeqCst);

                let filtered_chunks: Vec<Chunk> = [
                    ChunkType::JarFile,
                    ChunkType::JarFilePartial,
                    ChunkType::EmbeddedFile,
                ]
                .iter()
                .filter_map(|chunk_type| proto_data.remove(chunk_type))
                .flat_map(std::iter::IntoIterator::into_iter)
                .collect();

                let files: Vec<Chunk> = filtered_chunks
                    .into_iter()
                    .chain(
                        proto_data
                            .into_iter()
                            .flat_map(|(_, chunks)| chunks.into_iter()),
                    )
                    .collect();

                file_managers.write().await.insert(
                    ecu_name,
                    FileManager::new(mddfile.to_str().unwrap().to_owned(), files),
                );
            }
            Err(e) => {
                tracing::error!(mdd_file = %mddfile.display(), error = %e, "Failed to load ecu data from file");
            }
        }
    }
}

#[tracing::instrument(skip_all, fields(database_count = databases.len()))]
pub async fn create_uds_manager(
    gateway: DoipDiagGateway<EcuManager>,
    databases: Arc<HashMap<String, RwLock<EcuManager>>>,
    variant_detection_receiver: mpsc::Receiver<Vec<String>>,
    tester_present_sender: mpsc::Receiver<TesterPresentControlMessage>,
) -> Result<UdsManager<DoipDiagGateway<EcuManager>, DiagServiceResponseStruct, EcuManager>, String>
{
    UdsManager::new(
        gateway,
        databases,
        variant_detection_receiver,
        tester_present_sender,
    )
    .await
}

/// Creates a new diagnostic gateway for the webserver.
/// # Errors
/// Returns a string error if the gateway cannot be initialized.
#[tracing::instrument(
    skip(databases, variant_detection, tester_present, shutdown_signal),
    fields(database_count = databases.len())
)]
pub async fn create_diagnostic_gateway(
    databases: Arc<HashMap<String, RwLock<EcuManager>>>,
    doip_tester_address: &str,
    doip_tester_subnet: &str,
    doip_gateway_port: u16,
    variant_detection: mpsc::Sender<Vec<String>>,
    tester_present: mpsc::Sender<TesterPresentControlMessage>,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + Clone + 'static,
) -> Result<DoipDiagGateway<EcuManager>, String> {
    DoipDiagGateway::new(
        doip_tester_address,
        doip_tester_subnet,
        doip_gateway_port,
        databases,
        variant_detection,
        tester_present,
        shutdown_signal,
    )
    .await
}

#[tracing::instrument(
    skip(file_managers, webserver_config, ecu_uds, shutdown_signal),
    fields(file_manager_count = file_managers.len())
)]
pub fn start_webserver(
    flash_files_path: String,
    file_managers: HashMap<String, FileManager>,
    webserver_config: WebServerConfig,
    ecu_uds: UdsManager<DoipDiagGateway<EcuManager>, DiagServiceResponseStruct, EcuManager>,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> tokio::task::JoinHandle<Result<(), String>> {
    cda_interfaces::spawn_named!("webserver", async move {
        cda_sovd::launch_webserver::<_, DiagServiceResponseStruct, _, _>(
            webserver_config,
            ecu_uds,
            flash_files_path,
            file_managers,
            shutdown_signal,
        )
        .await
    })
}

/// Waits for a shutdown signal, such as Ctrl+C or SIGTERM (on unix).
/// # Panics
/// * If subscribing to the signals fails.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
