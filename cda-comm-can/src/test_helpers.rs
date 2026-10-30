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

use cda_interfaces::EcuConnectivityHandler;

/// Connectivity handler that records the ECUs reported as replied.
#[derive(Default)]
pub(crate) struct RecordingConnectivityHandler {
    replied: std::sync::Mutex<Vec<String>>,
}

impl RecordingConnectivityHandler {
    /// The ECU names reported through `on_ecu_replied`, in order.
    pub(crate) fn replied(&self) -> Vec<String> {
        self.replied.lock().expect("lock replied").clone()
    }
}

#[async_trait::async_trait]
impl EcuConnectivityHandler for RecordingConnectivityHandler {
    async fn on_gateway_connected(&self, _ecu_names: &[String]) {}

    async fn on_gateway_disconnected(&self, _ecu_names: &[String]) {}

    async fn on_ecu_replied(&self, ecu_name: &str) {
        self.replied
            .lock()
            .expect("lock replied")
            .push(ecu_name.to_owned());
    }
}
