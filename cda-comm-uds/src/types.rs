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
    DiagServiceError, HashMap, TransmissionParameters,
    datatypes::{DataTransferMetaData, RetryPolicy},
};
use strum::Display;
use tokio::{sync::watch, task::JoinHandle};

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
    pub(crate) owner: String,
    pub(crate) status_receiver: watch::Receiver<bool>,
    pub(crate) task: JoinHandle<()>,
}

impl EcuDataTransfer {
    pub(crate) fn validate_exit(
        &self,
        ecu_name: &str,
        id: &str,
        owner: &str,
    ) -> Result<(), DiagServiceError> {
        if self.meta_data.id != id || self.owner != owner {
            return Err(DiagServiceError::NotFound(format!(
                "Data transfer with id {id} not found for ECU {ecu_name}"
            )));
        }

        if !matches!(
            self.meta_data.status,
            cda_interfaces::datatypes::DataTransferStatus::Aborted
                | cda_interfaces::datatypes::DataTransferStatus::Finished
        ) {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Data transfer with id {id} is currently in status {:?}, cannot exit",
                self.meta_data.status,
            )));
        }

        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use cda_interfaces::{
        DiagServiceError,
        datatypes::{DataTransferMetaData, DataTransferStatus},
    };
    use tokio::sync::watch;

    use super::EcuDataTransfer;

    fn transfer(status: DataTransferStatus) -> EcuDataTransfer {
        let (_sender, receiver) = watch::channel(false);
        EcuDataTransfer {
            meta_data: DataTransferMetaData {
                acknowledged_bytes: 0,
                blocksize: 1,
                next_block_sequence_counter: 1,
                id: "transfer-id".to_owned(),
                file_id: "file-id".to_owned(),
                status,
                error: None,
            },
            owner: "owner".to_owned(),
            status_receiver: receiver,
            task: tokio::spawn(async {}),
        }
    }

    #[tokio::test]
    async fn transfer_exit_rejects_wrong_id_or_owner() {
        let transfer = transfer(DataTransferStatus::Finished);

        assert!(matches!(
            transfer.validate_exit("ecu", "wrong-id", "owner"),
            Err(DiagServiceError::NotFound(_))
        ));
        assert!(matches!(
            transfer.validate_exit("ecu", "transfer-id", "wrong-owner"),
            Err(DiagServiceError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn transfer_exit_requires_terminal_status() {
        let transfer = transfer(DataTransferStatus::Running);

        assert!(matches!(
            transfer.validate_exit("ecu", "transfer-id", "owner"),
            Err(DiagServiceError::InvalidRequest(_))
        ));
    }

    #[tokio::test]
    async fn transfer_exit_accepts_terminal_statuses() {
        assert!(
            transfer(DataTransferStatus::Finished)
                .validate_exit("ecu", "transfer-id", "owner")
                .is_ok()
        );
        assert!(
            transfer(DataTransferStatus::Aborted)
                .validate_exit("ecu", "transfer-id", "owner")
                .is_ok()
        );
    }
}
