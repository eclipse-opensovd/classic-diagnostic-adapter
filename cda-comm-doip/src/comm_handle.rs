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

//! [`CommunicationControl`] implementation for `DoIP` communication.
//!
//! [`DoipCommHandle`] owns the `DoIP` communication lifecycle: socket creation,
//! gateway discovery, connection management, and teardown.
//!
//! An `op_lock` mutex serialises concurrent `enable`/`disable`/`replace_gateway`
//! calls. All other fields are either immutable after construction or shared via
//! `Arc` for lock-free reads by middleware and health providers.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use async_trait::async_trait;
use cda_interfaces::{
    DoipComParams, EcuAddresses, EcuConnectivityHandler, GatewayInstall, HashMap, Shutdown,
    SocketProvider,
    communication_control::{CommControlError, CommState, CommunicationControl},
};
use tokio::sync::{Mutex, RwLock, mpsc};

use crate::{
    DoipDiagGateway, config::DoipConfig, create_udp_vir_socket, deferred_gateway::DeferredGateway,
    socket::DoIPUdpSocket,
};

/// Externally-facing handle for controlling `DoIP` communication.
///
/// Cheaply cloneable. Implements [`CommunicationControl`] directly - `enable`,
/// `disable`, and `replace_gateway` are methods on this struct, serialised by
/// `op_lock`. Exposes a lock-free `Arc<AtomicBool>` for fast-path middleware
/// checks and a `Arc<std::sync::RwLock<CommState>>` for precise sync state reads.
pub struct DoipCommHandle<T: EcuAddresses + DoipComParams> {
    /// Serialises enable / disable / `replace_gateway`.
    /// Held across the full async operation so concurrent callers queue up
    /// and the second caller hits the idempotency check after the first finishes.
    op_lock: Arc<Mutex<()>>,
    // Immutable config - no lock needed.
    doip_config: DoipConfig,
    ecus: Arc<HashMap<String, RwLock<T>>>,
    variant_detection: mpsc::Sender<Vec<String>>,
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    // Shared with external consumers - accessed without holding op_lock.
    /// Lock-free flag for middleware fast-path checks.
    active_flag: Arc<AtomicBool>,
    /// Precise `CommState` readable asynchronously via `CommunicationControl::state`.
    comm_state: Arc<RwLock<CommState>>,
    /// Optional gateway; `Some` while `Active`, `None` while `Disabled`.
    slot: Arc<RwLock<Option<DoipDiagGateway<T>>>>,
    /// Reserved UDP socket, bound at construction and kept for the handle's lifetime.
    socket: Arc<Mutex<DoIPUdpSocket>>,
}

impl<T: EcuAddresses + DoipComParams> Clone for DoipCommHandle<T> {
    fn clone(&self) -> Self {
        Self {
            op_lock: Arc::clone(&self.op_lock),
            doip_config: self.doip_config.clone(),
            ecus: Arc::clone(&self.ecus),
            variant_detection: self.variant_detection.clone(),
            connectivity_handler: Arc::clone(&self.connectivity_handler),
            active_flag: Arc::clone(&self.active_flag),
            comm_state: Arc::clone(&self.comm_state),
            slot: Arc::clone(&self.slot),
            socket: Arc::clone(&self.socket),
        }
    }
}

impl<T: EcuAddresses + DoipComParams> DoipCommHandle<T> {
    /// Creates a [`DeferredGateway`] that shares this handle's slot and socket.
    ///
    /// The returned gateway delegates to the inner `DoipDiagGateway` when
    /// communication is active, and returns `EcuOffline` errors when disabled.
    #[must_use]
    pub fn deferred_gateway(&self) -> DeferredGateway<T> {
        DeferredGateway::new(Arc::clone(&self.slot), Arc::clone(&self.socket))
    }

    /// Returns a live health provider derived from the shared [`CommState`].
    ///
    /// The provider reflects state changes automatically as the handle transitions -
    /// no manual `set_status()` calls are needed.
    #[must_use]
    pub fn health_provider(&self) -> crate::health::CommStateHealthProvider {
        crate::health::CommStateHealthProvider::new(Arc::clone(&self.comm_state))
    }

    /// Returns a reference to the shared gateway slot.
    ///
    /// This is primarily for advanced use cases; prefer [`deferred_gateway`](Self::deferred_gateway).
    #[must_use]
    pub fn slot(&self) -> &Arc<RwLock<Option<DoipDiagGateway<T>>>> {
        &self.slot
    }

    /// Installs a freshly-built gateway into the shared slot and optionally
    /// activates communication.
    ///
    /// This is the counterpart to [`CommunicationControl::disable`]: after
    /// `disable()` clears the slot, the caller can build a new gateway via
    /// `VehicleComponentFactory::create` (reusing the reserved UDP socket from
    /// [`SocketProvider::socket`]) and then call `replace_gateway()` to install
    /// the new gateway without going through the full `DoIP` discovery sequence.
    ///
    /// Pass `activate: true` to immediately transition to `Active` (post-update
    /// `Enabled` or `Last`-was-active). Pass `activate: false` to stage the
    /// gateway without activating; the `DeferredInitGuard` will call `enable()`
    /// on the next diagnostic request (`Deferred` or `Last`-was-inactive).
    pub async fn replace_gateway(&self, gateway: DoipDiagGateway<T>, activate: bool) {
        let _guard = self.op_lock.lock().await;

        let mut slot_guard = self.slot.write().await;
        *slot_guard = Some(gateway);
        drop(slot_guard);

        let new_state = if activate {
            CommState::Active
        } else {
            CommState::Disabled
        };
        self.set_comm_state(new_state).await;
        self.active_flag.store(activate, Ordering::Release);
    }

    /// Writes `state` to the shared `comm_state` lock.
    async fn set_comm_state(&self, state: CommState) {
        *self.comm_state.write().await = state;
    }

    /// Perform the full `DoIP` initialization sequence.
    ///
    /// Builds the gateway into the shared slot using the reserved socket.
    /// Must be called with `op_lock` held.
    async fn do_enable(&self) -> Result<(), String> {
        let gateway = DoipDiagGateway::new(
            &self.doip_config,
            Arc::clone(&self.ecus),
            self.variant_detection.clone(),
            Arc::clone(&self.connectivity_handler),
            // Shutdown signal: a future that never resolves - the handle manages
            // the gateway lifecycle via explicit disable / replace_gateway.
            std::future::pending(),
            Arc::clone(&self.socket),
        )
        .await
        .map_err(|e| format!("gateway initialization failed: {e}"))?;

        let mut slot_guard = self.slot.write().await;
        *slot_guard = Some(gateway);
        drop(slot_guard);

        Ok(())
    }

    /// Shut down the live gateway and transition to `Disabled`.
    /// Must be called with `op_lock` held.
    async fn do_disable(&self) {
        let mut slot_guard = self.slot.write().await;
        if let Some(mut gateway) = slot_guard.take() {
            gateway.shutdown().await;
        }
        drop(slot_guard);

        self.set_comm_state(CommState::Disabled).await;
        self.active_flag.store(false, Ordering::Release);
    }
}

#[async_trait]
impl<T: EcuAddresses + DoipComParams> CommunicationControl for DoipCommHandle<T> {
    async fn enable(&self) -> Result<(), CommControlError> {
        let _guard = self.op_lock.lock().await;

        if self.state().await == CommState::Active {
            return Ok(());
        }

        self.set_comm_state(CommState::Initializing).await;

        match self.do_enable().await {
            Ok(()) => {
                self.set_comm_state(CommState::Active).await;
                self.active_flag.store(true, Ordering::Release);
                Ok(())
            }
            Err(e) => {
                self.set_comm_state(CommState::Failed).await;
                self.active_flag.store(false, Ordering::Release);
                Err(CommControlError::InitFailed(e))
            }
        }
    }

    async fn disable(&self) -> Result<(), CommControlError> {
        let _guard = self.op_lock.lock().await;

        if self.state().await == CommState::Disabled {
            return Ok(());
        }

        self.do_disable().await;
        Ok(())
    }

    async fn state(&self) -> CommState {
        *self.comm_state.read().await
    }

    fn active(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.active_flag)
    }
}

#[async_trait]
impl<T, G> GatewayInstall<G> for DoipCommHandle<T>
where
    T: EcuAddresses + DoipComParams,
    G: Into<DoipDiagGateway<T>> + Send + 'static,
{
    async fn install_gateway(&self, gateway: G, activate: bool) {
        self.replace_gateway(gateway.into(), activate).await;
    }
}

impl<T: EcuAddresses + DoipComParams> SocketProvider for DoipCommHandle<T> {
    type Socket = DoIPUdpSocket;

    fn socket(&self) -> Arc<Mutex<DoIPUdpSocket>> {
        Arc::clone(&self.socket)
    }
}

// Constructors

/// Creates a [`DoipCommHandle`] implementing [`CommunicationControl`].
///
/// Binds the `DoIP` UDP socket immediately to reserve the port. The handle
/// starts in [`CommState::Disabled`] with no gateway. Call
/// [`CommunicationControl::enable`] to trigger the `DoIP` startup sequence.
///
/// # Errors
///
/// Returns [`DoipGatewaySetupError`](cda_interfaces::DoipGatewaySetupError) if
/// the UDP socket cannot be created (e.g., port already in use).
#[allow(
    clippy::implicit_hasher,
    reason = "ecus map uses the cda_interfaces::HashMap type alias with a fixed global hasher"
)]
pub fn new_doip_comm_handle<T: EcuAddresses + DoipComParams>(
    doip_config: DoipConfig,
    ecus: Arc<HashMap<String, RwLock<T>>>,
    variant_detection: mpsc::Sender<Vec<String>>,
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
) -> Result<DoipCommHandle<T>, cda_interfaces::DoipGatewaySetupError> {
    let socket = create_udp_vir_socket(&doip_config.tester_address, doip_config.gateway_port)
        .map_err(|e| cda_interfaces::DoipGatewaySetupError::SocketCreationFailed(e.to_string()))?;

    Ok(DoipCommHandle {
        op_lock: Arc::new(Mutex::new(())),
        doip_config,
        ecus,
        variant_detection,
        connectivity_handler,
        active_flag: Arc::new(AtomicBool::new(false)),
        comm_state: Arc::new(RwLock::new(CommState::Disabled)),
        slot: Arc::new(RwLock::new(None)),
        socket: Arc::new(Mutex::new(socket)),
    })
}

/// Creates a [`DoipCommHandle`] reusing an existing UDP socket.
///
/// Identical to [`new_doip_comm_handle`] except the caller provides a
/// pre-existing socket. Used by the runtime-update reload path to avoid
/// double-binding the `DoIP` UDP port: the original handle's reserved socket
/// is passed here so the new handle reuses the same bound port.
#[allow(
    clippy::implicit_hasher,
    reason = "ecus map uses the cda_interfaces::HashMap type alias with a fixed global hasher"
)]
pub fn new_doip_comm_handle_with_socket<T: EcuAddresses + DoipComParams>(
    doip_config: DoipConfig,
    ecus: Arc<HashMap<String, RwLock<T>>>,
    variant_detection: mpsc::Sender<Vec<String>>,
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    socket: Arc<Mutex<DoIPUdpSocket>>,
) -> DoipCommHandle<T> {
    DoipCommHandle {
        op_lock: Arc::new(Mutex::new(())),
        doip_config,
        ecus,
        variant_detection,
        connectivity_handler,
        active_flag: Arc::new(AtomicBool::new(false)),
        comm_state: Arc::new(RwLock::new(CommState::Disabled)),
        slot: Arc::new(RwLock::new(None)),
        socket,
    }
}
