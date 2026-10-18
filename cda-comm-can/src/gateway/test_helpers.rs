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

use cda_interfaces::{RouteStatus, TransportProbe};
use tokio::sync::{mpsc, oneshot};

pub(super) struct ControlledProbe {
    pub(super) started: mpsc::UnboundedSender<(String, oneshot::Sender<bool>)>,
}

impl TransportProbe for ControlledProbe {
    async fn route_status(&self, _ecu_name: &str) -> RouteStatus {
        RouteStatus::ProbeRequired
    }

    async fn probe_ecu(&self, ecu_name: &str) -> bool {
        let (complete, response) = oneshot::channel();
        self.started
            .send((ecu_name.to_owned(), complete))
            .expect("record probe start");
        response.await.expect("complete probe")
    }
}
