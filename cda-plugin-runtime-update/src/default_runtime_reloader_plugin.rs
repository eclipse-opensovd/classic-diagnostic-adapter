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

use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use cda_interfaces::runtime_update_api::{
    ReloadError, RuntimeReloaderPlugin, VehicleComponentFactory, VehicleComponentPublisher,
};
use tokio::sync::{Mutex, RwLock};

/// Generic runtime-reloader plugin that prepares and publishes coherent vehicle generations.
pub struct DefaultRuntimeReloaderPlugin<Config, Uds, Gateway, Factory, Publisher>
where
    // Matches the trait impl's bounds, so the struct cannot be constructed in a
    // state where `RuntimeReloaderPlugin` does not apply.
    Config: Clone + Send + Sync + 'static,
    Factory: VehicleComponentFactory<Config, Uds, Gateway>,
    Publisher: VehicleComponentPublisher<Uds, Gateway, Factory::FileManager>,
    Uds: cda_interfaces::UdsQuery + cda_interfaces::Shutdown + Send + Sync + 'static,
    Gateway: cda_interfaces::Shutdown + Send + Sync + 'static,
{
    config: Arc<RwLock<Config>>,
    factory: Arc<Factory>,
    publisher: Arc<Publisher>,
    reload_guard: Mutex<()>,
    _components: std::marker::PhantomData<(Uds, Gateway)>,
}

impl<Config, Uds, Gateway, Factory, Publisher>
    DefaultRuntimeReloaderPlugin<Config, Uds, Gateway, Factory, Publisher>
where
    Config: Clone + Send + Sync + 'static,
    Factory: VehicleComponentFactory<Config, Uds, Gateway>,
    Publisher: VehicleComponentPublisher<Uds, Gateway, Factory::FileManager>,
    Uds: cda_interfaces::UdsQuery + cda_interfaces::Shutdown + Send + Sync + 'static,
    Gateway: cda_interfaces::Shutdown + Send + Sync + 'static,
{
    /// Creates a reloader from application-independent preparation and publication capabilities.
    #[must_use]
    pub fn new(
        config: Arc<RwLock<Config>>,
        factory: Arc<Factory>,
        publisher: Arc<Publisher>,
    ) -> Self {
        Self {
            config,
            factory,
            publisher,
            reload_guard: Mutex::new(()),
            _components: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<Config, Uds, Gateway, Factory, Publisher> RuntimeReloaderPlugin
    for DefaultRuntimeReloaderPlugin<Config, Uds, Gateway, Factory, Publisher>
where
    Config: Clone + Send + Sync + 'static,
    Factory: VehicleComponentFactory<Config, Uds, Gateway>,
    Publisher: VehicleComponentPublisher<Uds, Gateway, Factory::FileManager>,
    Uds: cda_interfaces::UdsQuery + cda_interfaces::Shutdown + Send + Sync + 'static,
    Gateway: cda_interfaces::Shutdown + Send + Sync + 'static,
{
    async fn reload_databases(&self, mdd_paths: Vec<PathBuf>) -> Result<(), ReloadError> {
        let _guard = self.reload_guard.lock().await;
        let config = self.config.read().await.clone();
        let components = self.factory.create(&config, &mdd_paths).await?;
        self.publisher.publish(components).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use cda_interfaces::{
        FunctionalDescriptionConfig, HashMap, Shutdown, file_manager::mock::MockFileManager,
        mock::MockUdsEcu, runtime_update_api::VehicleComponents,
    };

    use super::*;

    /// Minimal `Gateway`: the reloader only needs it to be shutdown-able.
    struct StubGateway;

    #[async_trait]
    impl Shutdown for StubGateway {
        async fn shutdown(&self) {}
    }

    /// Records the config it was handed, so a test can assert *which* snapshot the
    /// reloader read.
    struct RecordingFactory {
        seen_config: Mutex<Vec<String>>,
        delay: Duration,
    }

    #[async_trait]
    impl VehicleComponentFactory<String, MockUdsEcu, StubGateway> for RecordingFactory {
        type FileManager = MockFileManager;

        async fn create(
            &self,
            config: &String,
            _mdd_paths: &[PathBuf],
        ) -> Result<VehicleComponents<MockUdsEcu, StubGateway, MockFileManager>, ReloadError>
        {
            self.seen_config.lock().await.push(config.clone());
            // Long enough that a second concurrent reload would interleave here if
            // the guard did not serialize them.
            cda_interfaces::util::tokio_ext::sleep_for(self.delay).await;
            Ok(VehicleComponents {
                uds_manager: MockUdsEcu::new(),
                file_managers: HashMap::default(),
                diagnostic_gateway: StubGateway,
                functional_group_config: FunctionalDescriptionConfig::default(),
            })
        }
    }

    /// Counts publishes and observes whether two ever overlap.
    struct CountingPublisher {
        in_flight: AtomicUsize,
        max_concurrent: AtomicUsize,
        published: AtomicUsize,
    }

    #[async_trait]
    impl VehicleComponentPublisher<MockUdsEcu, StubGateway, MockFileManager> for CountingPublisher {
        async fn publish(
            &self,
            _components: VehicleComponents<MockUdsEcu, StubGateway, MockFileManager>,
        ) -> Result<(), ReloadError> {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_concurrent.fetch_max(now, Ordering::SeqCst);
            cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(20)).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            self.published.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Publisher that always rejects, to check the error reaches the caller.
    struct FailingPublisher;

    #[async_trait]
    impl VehicleComponentPublisher<MockUdsEcu, StubGateway, MockFileManager> for FailingPublisher {
        async fn publish(
            &self,
            _components: VehicleComponents<MockUdsEcu, StubGateway, MockFileManager>,
        ) -> Result<(), ReloadError> {
            Err(ReloadError::ReplacementFailure(
                "publish refused".to_owned(),
            ))
        }
    }

    fn factory(delay_ms: u64) -> Arc<RecordingFactory> {
        Arc::new(RecordingFactory {
            seen_config: Mutex::new(Vec::new()),
            delay: Duration::from_millis(delay_ms),
        })
    }

    fn publisher() -> Arc<CountingPublisher> {
        Arc::new(CountingPublisher {
            in_flight: AtomicUsize::new(0),
            max_concurrent: AtomicUsize::new(0),
            published: AtomicUsize::new(0),
        })
    }

    #[tokio::test]
    async fn reload_creates_then_publishes_a_generation() {
        let factory = factory(0);
        let publisher = publisher();
        let reloader = DefaultRuntimeReloaderPlugin::new(
            Arc::new(RwLock::new("config-v1".to_owned())),
            Arc::clone(&factory),
            Arc::clone(&publisher),
        );

        reloader
            .reload_databases(vec![PathBuf::from("ecu.mdd")])
            .await
            .expect("reload must succeed");

        assert_eq!(publisher.published.load(Ordering::SeqCst), 1);
        assert_eq!(factory.seen_config.lock().await.as_slice(), ["config-v1"]);
    }

    #[tokio::test]
    async fn concurrent_reloads_are_serialized_by_the_guard() {
        // Without `reload_guard`, two reloads would build and publish overlapping
        // component generations - the second could install components the first is
        // still swapping in.
        let factory = factory(30);
        let publisher = publisher();
        let reloader = Arc::new(DefaultRuntimeReloaderPlugin::new(
            Arc::new(RwLock::new("config-v1".to_owned())),
            Arc::clone(&factory),
            Arc::clone(&publisher),
        ));

        let first = {
            let reloader = Arc::clone(&reloader);
            tokio::spawn(async move { reloader.reload_databases(Vec::new()).await })
        };
        let second = {
            let reloader = Arc::clone(&reloader);
            tokio::spawn(async move { reloader.reload_databases(Vec::new()).await })
        };

        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();

        assert_eq!(publisher.published.load(Ordering::SeqCst), 2);
        assert_eq!(
            publisher.max_concurrent.load(Ordering::SeqCst),
            1,
            "two reloads must never publish concurrently"
        );
    }

    #[tokio::test]
    async fn each_reload_reads_the_config_snapshot_current_at_its_turn() {
        // The snapshot is taken *inside* the guard, so a config change made while an
        // earlier reload is in flight is picked up by the next one rather than
        // being read before it waits.
        let factory = factory(30);
        let publisher = publisher();
        let config = Arc::new(RwLock::new("config-v1".to_owned()));
        let reloader = Arc::new(DefaultRuntimeReloaderPlugin::new(
            Arc::clone(&config),
            Arc::clone(&factory),
            publisher,
        ));

        let first = {
            let reloader = Arc::clone(&reloader);
            tokio::spawn(async move { reloader.reload_databases(Vec::new()).await })
        };
        // Let the first reload claim the guard, then change the config.
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(10)).await;
        "config-v2".clone_into(&mut *config.write().await);

        let second = {
            let reloader = Arc::clone(&reloader);
            tokio::spawn(async move { reloader.reload_databases(Vec::new()).await })
        };

        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();

        assert_eq!(
            factory.seen_config.lock().await.as_slice(),
            ["config-v1", "config-v2"],
            "the second reload must see the config as of when it acquired the guard"
        );
    }

    #[tokio::test]
    async fn a_publish_failure_reaches_the_caller() {
        let reloader = DefaultRuntimeReloaderPlugin::new(
            Arc::new(RwLock::new("config-v1".to_owned())),
            factory(0),
            Arc::new(FailingPublisher),
        );

        assert!(matches!(
            reloader.reload_databases(Vec::new()).await,
            Err(ReloadError::ReplacementFailure(_))
        ));
    }
}
