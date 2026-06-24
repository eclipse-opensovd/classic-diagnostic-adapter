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

use std::time::Duration;

use cda_interfaces::{
    HashMap,
    TransmissionParameters,
    datatypes::{
        DataTransferMetaData,
        RetryPolicy,
    },
};
use strum::Display;
use tokio::{
    sync::watch,
    task::JoinHandle,
};

pub(crate) type EcuIdentifier = String;

#[derive(Copy, Clone, Display)]
pub(crate) enum ResetType {
    Session,
    SecurityAccess,
}

pub(crate) struct UdsParameters {
    pub(crate) timeout_default: Duration,
    pub(crate) rc_21_retry_policy: RetryPolicy,
    pub(crate) rc_21_completion_timeout: Duration,
    pub(crate) rc_21_repeat_request_time: Duration,
    pub(crate) rc_78_retry_policy: RetryPolicy,
    pub(crate) rc_78_completion_timeout: Duration,
    pub(crate) rc_78_timeout: Duration,
    pub(crate) rc_94_completion_timeout: Duration,
    pub(crate) rc_94_retry_policy: RetryPolicy,
    pub(crate) rc_94_repeat_request_time: Duration,
}

pub(crate) struct EcuDataTransfer {
    pub(crate) meta_data: DataTransferMetaData,
    pub(crate) status_receiver: watch::Receiver<bool>,
    pub(crate) task: JoinHandle<()>,
}

pub struct TesterPresentTask {
    pub type_: cda_interfaces::TesterPresentType,
    pub task: JoinHandle<()>,
}

pub(crate) struct PerGatewayInfo {
    pub(crate) uds_params: UdsParameters,
    pub(crate) transmission_params: TransmissionParameters,
    pub(crate) source_address: u16,
    pub(crate) functional_address: u16,
    pub(crate) ecus: HashMap<u16, String>,
}
