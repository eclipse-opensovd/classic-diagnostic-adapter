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

use std::{future::Future, path::PathBuf, sync::Arc};

use cda_comm_doip::{DoipDiagGateway, config::DoipConfig};
use cda_comm_uds::UdsManager;
use cda_core::{DiagServiceResponseStruct, EcuManager};
use cda_database::{FileManager, ProtoLoadConfig};
use cda_interfaces::{
    DoipGatewaySetupError, EcuAddressProvider, EcuManager as EcuManagerTrait, HashMap,
    HashMapEntry, HashMapExtensions, HashSet, Protocol, UdsEcu,
    datatypes::{ComParams, DatabaseNamingConvention, FlatbBufConfig},
    dlt_ctx,
    file_manager::{Chunk, ChunkType},
};
use cda_plugin_security::SecurityPlugin;
use cda_sovd::Locks;
use cda_tracing::{OtelGuard, TracingSetupError, TracingWorkerGuard};
use tokio::{
    signal,
    sync::{RwLock, mpsc},
};
use tracing::Instrument;
use tracing_subscriber::layer::SubscriberExt;

use crate::config::configfile::Configuration;

pub mod config;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// todo scope after poc: make this configurable
const DB_PARALLEL_LOAD_TASKS: usize = 2;

pub type DatabaseMap<S> = HashMap<String, RwLock<EcuManager<S>>>;
pub type FileManagerMap = HashMap<String, FileManager>;

#[derive(Debug)]
struct EcuMetadata {
    mdd_path: String,
    valid: bool,
}

type LoadedEcuMap<S> = HashMap<String, (EcuManager<S>, EcuMetadata)>;

pub struct VehicleData<S: SecurityPlugin> {
    pub file_managers: FileManagerMap,
    pub uds_manager: UdsManagerType<S>,
    pub locks: Arc<cda_sovd::Locks>,
}

/// Loads vehicle databases and sets up SOVD routes in the webserver.
/// # Errors
/// Returns `DoipGatewaySetupError` if we failed to create the diagnostic gateway
pub async fn load_vehicle_data<
    F: Future<Output = ()> + Clone + Send + 'static,
    S: SecurityPlugin,
>(
    config: &Configuration,
    clonable_shutdown_signal: F,
) -> Result<VehicleData<S>, DoipGatewaySetupError> {
    // Load databases in the background
    let database_path = config.databases_path.clone();
    let protocol = if config.onboard_tester {
        cda_interfaces::Protocol::DoIpDobt
    } else {
        cda_interfaces::Protocol::DoIp
    };

    let (databases, file_managers) = load_databases::<S>(
        &database_path,
        protocol,
        config.com_params.clone(),
        config.database_naming_convention.clone(),
        config.flat_buf.clone(),
    )
    .await;

    tracing::debug!("Databases loaded. Setting up diagnostic gateway...");

    let (variant_detection_tx, variant_detection_rx) = mpsc::channel(50);
    let databases = Arc::new(databases);
    let diagnostic_gateway = match create_diagnostic_gateway(
        Arc::clone(&databases),
        &config.doip,
        variant_detection_tx,
        clonable_shutdown_signal.clone(),
    )
    .await
    {
        Ok(gateway) => gateway,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create diagnostic gateway");
            return Err(e);
        }
    };

    let uds = create_uds_manager(diagnostic_gateway, databases, variant_detection_rx);
    tracing::debug!("Starting variant detection");
    let vdetect = uds.clone();
    cda_interfaces::spawn_named!("startup-variant-detection", async move {
        vdetect.start_variant_detection().await;
    });

    let ecu_names = uds.get_ecus().await;
    Ok(VehicleData {
        uds_manager: uds,
        file_managers,
        locks: Arc::new(Locks::new(ecu_names)),
    })
}

#[tracing::instrument(skip(com_params, database_naming_convention), fields(databases_path))]
pub async fn load_databases<S: SecurityPlugin>(
    databases_path: &str,
    protocol: Protocol,
    com_params: ComParams,
    database_naming_convention: DatabaseNamingConvention,
    flat_buf_settings: FlatbBufConfig,
) -> (DatabaseMap<S>, FileManagerMap) {
    let databases: Arc<RwLock<LoadedEcuMap<S>>> = Arc::new(RwLock::new(HashMap::new()));

    let file_managers: Arc<RwLock<HashMap<String, FileManager>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let com_params = Arc::new(com_params);

    let mut database_load_futures = Vec::new();
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

        let chunk_size = files
            .len()
            .checked_div(DB_PARALLEL_LOAD_TASKS.saturating_add(1))
            .unwrap_or(1)
            .max(1);

        tracing::info!(chunk_size = %chunk_size, "Loading databases");

        for (i, mddfiles) in files.chunks(chunk_size).enumerate() {
            let database = Arc::clone(&databases);
            let file_managers = Arc::clone(&file_managers);
            let paths = mddfiles.to_vec();
            let com_params = Arc::clone(&com_params);
            let database_naming_convention = database_naming_convention.clone();
            let flat_buf_settings = flat_buf_settings.clone();

            database_load_futures.push(cda_interfaces::spawn_named!(
                &format!("load-database-{i}"),
                async move {
                    load_database(
                        protocol,
                        database,
                        file_managers,
                        paths,
                        com_params,
                        database_naming_convention,
                        flat_buf_settings,
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

    let databases = databases
        .write()
        .await
        .drain()
        .filter(|(_, (_, meta))| meta.valid)
        .map(|(k, (ecu_manager, _))| (k.to_lowercase(), RwLock::new(ecu_manager)))
        .collect::<HashMap<String, RwLock<EcuManager<S>>>>();
    mark_duplicate_ecus_by_address(&databases).await;

    let file_managers = file_managers
        .write()
        .await
        .drain()
        .map(|(k, v)| (k.to_lowercase().clone(), v))
        .collect::<HashMap<String, FileManager>>();

    let end = std::time::Instant::now();

    tracing::info!(database_count = &databases.len(), duration = ?end.saturating_duration_since(start), "Loaded databases");
    if databases.is_empty() {
        tracing::error!("Database load failed, no databases found");
        std::process::exit(1);
    }

    (databases, file_managers)
}

async fn mark_duplicate_ecus_by_address<S: SecurityPlugin>(
    databases: &HashMap<String, RwLock<EcuManager<S>>>,
) {
    let mut ecus_by_address: HashMap<u16, HashMap<u16, Vec<String>>> = HashMap::new();
    for (name, db_lock) in databases {
        let db = db_lock.read().await;
        let logical_address = db.logical_address();
        let gateway_address = db.logical_gateway_address();
        ecus_by_address
            .entry(gateway_address)
            .or_default()
            .entry(logical_address)
            .or_default()
            .push(name.clone());
    }

    for logical_map in ecus_by_address.values() {
        for ecu_names in logical_map.values() {
            if ecu_names.len() <= 1 {
                continue;
            }

            for ecu_name in ecu_names {
                let Some(db_lock) = databases.get(ecu_name) else {
                    continue;
                };

                let mut db = db_lock.write().await;
                let duplicates: HashSet<String> = ecu_names
                    .iter()
                    .filter(|&name| name != ecu_name)
                    .cloned()
                    .collect();
                db.set_duplicating_ecu_names(duplicates);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    skip_all,
    fields(
        paths_count = paths.len(),
        dlt_context = dlt_ctx!("MAIN"),
    )
)]
async fn load_database<S: SecurityPlugin>(
    protocol: Protocol,
    database: Arc<RwLock<LoadedEcuMap<S>>>,
    file_managers: Arc<RwLock<HashMap<String, FileManager>>>,
    paths: Vec<(PathBuf, u64)>,
    com_params: Arc<ComParams>,
    database_naming_convention: DatabaseNamingConvention,
    flat_buf_settings: FlatbBufConfig,
) {
    for (mddfile, _) in paths {
        let Some(mdd_path) = mddfile.to_str().map(ToOwned::to_owned) else {
            tracing::error!(mdd_file = %mddfile.display(), "Failed to convert MDD file path to string");
            continue;
        };

        match cda_database::load_proto_data(
            &mdd_path,
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
                    tracing::error!(
                        mdd_file = %mddfile.display(),
                        "No diagnostic description found in MDD file");
                    continue;
                };

                let ecu_payload: Vec<u8> =
                    if let Some(payload) = ecu_data.into_iter().next().and_then(|c| c.payload) {
                        payload
                    } else {
                        tracing::error!(
                        ecu_name = %ecu_name,
                        "No payload found in diagnostic description for ECU");
                        continue;
                    };

                let diag_data_base = match cda_database::datatypes::DiagnosticDatabase::new(
                    mdd_path.clone(),
                    ecu_payload,
                    flat_buf_settings.clone(),
                ) {
                    Ok(db) => db,
                    Err(e) => {
                        tracing::error!(
                            mdd_file = %mddfile.display(),
                            error = %e, "Failed to create database from MDD file");
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
                        tracing::error!(
                            ecu_name = %ecu_name, error = ?e,
                                "Failed to create DiagServiceManager");
                        continue;
                    }
                };

                let ecu_metadata = EcuMetadata {
                    mdd_path: mdd_path.clone(),
                    valid: true,
                };

                check_duplicate_ecu_names(
                    &database,
                    &mdd_path,
                    &ecu_name,
                    diag_service_manager,
                    ecu_metadata,
                )
                .await;

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

                file_managers
                    .write()
                    .await
                    .insert(ecu_name, FileManager::new(mdd_path, files));
            }
            Err(e) => {
                tracing::error!(
                    mdd_file = %mddfile.display(),
                    error = %e,
                    "Failed to load ecu data from file");
            }
        }
    }
}

async fn check_duplicate_ecu_names<S: SecurityPlugin>(
    database: &RwLock<LoadedEcuMap<S>>,
    mdd_path: &String,
    ecu_name: &String,
    diag_service_manager: EcuManager<S>,
    ecu_metadata: EcuMetadata,
) {
    let mut db_write = database.write().await;
    match db_write.entry(ecu_name.clone()) {
        HashMapEntry::Occupied(mut entry) => {
            let (existing_ecu, existing_meta) = entry.get_mut();

            if diag_service_manager.logical_address_eq(existing_ecu) {
                if diag_service_manager.revision() > existing_ecu.revision() {
                    tracing::warn!(
                        ecu_name = %ecu_name,
                        existing_mdd = %existing_meta.mdd_path,
                        existing_revision = %existing_ecu.revision(),
                        new_mdd = %mdd_path,
                        new_revision = %diag_service_manager.revision(),
                        "Replacing ECU with newer revision"
                    );
                    entry.insert((diag_service_manager, ecu_metadata));
                } else {
                    tracing::warn!(
                        ecu_name = %ecu_name,
                        existing_mdd = %existing_meta.mdd_path,
                        existing_revision = %existing_ecu.revision(),
                        new_mdd = %mdd_path,
                        new_revision = %diag_service_manager.revision(),
                        "Keeping existing ECU with newer or equal revision"
                    );
                }
            } else {
                tracing::error!(
                    ecu_name = %ecu_name,
                    "Duplicate ECU with different addresses. Marking as invalid."
                );
                existing_meta.valid = false;
            }
        }
        HashMapEntry::Vacant(entry) => {
            // Mark as invalid and remove later.
            // Not removing now, because there might be multiple duplicates and
            // if we would remove now, next duplicate would be added as new.
            entry.insert((diag_service_manager, ecu_metadata));
        }
    }
}

type UdsManagerType<S> =
    UdsManager<DoipDiagGateway<EcuManager<S>>, DiagServiceResponseStruct, EcuManager<S>>;

/// Creates a new UDS manager for the webserver.
// type alias does not allow specifying hasher, we set the hasher globally.
#[allow(clippy::implicit_hasher)]
#[tracing::instrument(skip_all,
    fields(
        database_count = databases.len(),
        dlt_context = dlt_ctx!("MAIN"),
    )
)]
pub fn create_uds_manager<S: SecurityPlugin>(
    gateway: DoipDiagGateway<EcuManager<S>>,
    databases: Arc<HashMap<String, RwLock<EcuManager<S>>>>,
    variant_detection_receiver: mpsc::Receiver<Vec<String>>,
) -> UdsManagerType<S> {
    UdsManager::new(gateway, databases, variant_detection_receiver)
}

/// Creates a new diagnostic gateway for the webserver.
/// # Errors
/// Returns a string error if the gateway cannot be initialized.
#[tracing::instrument(
    skip(databases, variant_detection, shutdown_signal),
    fields(
        database_count = databases.len(),
        dlt_context = dlt_ctx!("MAIN"),
    )
)]
pub async fn create_diagnostic_gateway<S: SecurityPlugin>(
    databases: Arc<DatabaseMap<S>>,
    doip_config: &DoipConfig,
    variant_detection: mpsc::Sender<Vec<String>>,
    shutdown_signal: impl Future<Output = ()> + Send + Clone + 'static,
) -> Result<DoipDiagGateway<EcuManager<S>>, DoipGatewaySetupError> {
    DoipDiagGateway::new(doip_config, databases, variant_detection, shutdown_signal).await
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

pub struct TracingGuards {
    _file: Option<TracingWorkerGuard>,
    _otel: Option<OtelGuard>,
}

/// Setup the tracing to provide logs and analytics.
/// # Errors
/// Returns a `TracingSetupError` if the tracing setup fails.
pub fn setup_tracing(config: &Configuration) -> Result<TracingGuards, TracingSetupError> {
    let tracing = cda_tracing::new();
    let mut layers = vec![];
    layers.push(cda_tracing::new_term_subscriber(&config.logging));
    #[cfg(feature = "tokio-tracing")]
    layers.push(cda_tracing::new_tokio_tracing(
        &config.logging.tokio_tracing,
    )?);
    let otel_guard = if config.logging.otel.enabled {
        println!(
            "Starting OpenTelemetry tracing with {}",
            config.logging.otel.endpoint
        );
        let (guard, metrics_layer, otel_layer) =
            cda_tracing::new_otel_subscriber(&config.logging.otel)?;
        layers.push(metrics_layer);
        layers.push(otel_layer);
        Some(guard)
    } else {
        None
    };

    let file_guard = if config.logging.log_file_config.enabled {
        let (guard, file_layer) =
            cda_tracing::new_file_subscriber(&config.logging.log_file_config)?;
        layers.push(file_layer);
        Some(guard)
    } else {
        None
    };

    #[cfg(feature = "dlt-tracing")]
    if config.logging.dlt_tracing.enabled {
        layers.push(cda_tracing::new_dlt_tracing(&config.logging.dlt_tracing)?);
    }

    cda_tracing::init_tracing(tracing.with(layers))?;
    Ok(TracingGuards {
        _file: file_guard,
        _otel: otel_guard,
    })
}
