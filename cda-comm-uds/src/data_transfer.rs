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

use std::sync::Arc;

use async_trait::async_trait;
use cda_interfaces::{
    DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, FlashTransferStartParams,
    HashMap, UdsDataTransfer, UdsTransport,
    datatypes::{DataTransferError, DataTransferMetaData, DataTransferStatus},
    diagservices::UdsPayloadData,
    dlt_ctx, service_ids, spawn_named,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, BufReader},
    sync::{Mutex, watch},
};

use crate::{UdsManager, types::EcuDataTransfer};

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    #[tracing::instrument(
        skip(self, request, status_sender, reader),
        fields(
            ecu_name,
            transfer_length = length,
            request_name = %request.name,
            dlt_context = dlt_ctx!("UDS"))
    )]
    async fn transfer_ecu_data(
        &self,
        ecu_name: &str,
        length: u64,
        request: DiagComm,
        status_sender: watch::Sender<bool>,
        mut reader: BufReader<File>,
    ) {
        async fn set_transfer_aborted(
            ecu_name: &str,
            transfers: &Arc<Mutex<HashMap<String, EcuDataTransfer>>>,
            reason: String,
            sender: &watch::Sender<bool>,
        ) {
            if let Some(dt) = transfers.lock().await.get_mut(ecu_name) {
                dt.meta_data.status = DataTransferStatus::Aborted;
                dt.meta_data.error = Some(vec![DataTransferError { text: reason }]);
            }
            if let Err(e) = sender.send(true) {
                tracing::error!(error = ?e, "Failed to send data transfer aborted signal");
            }
        }

        let (mut buffer, mut remaining_bytes, block_size, mut next_block_sequence_counter) = {
            let mut lock = self.data_transfers.lock().await;
            let Some(transfer) = lock.get_mut(ecu_name) else {
                tracing::error!("No transfer found, cannot start data transfer");
                return;
            };
            transfer.meta_data.status = DataTransferStatus::Running;
            (
                vec![0; transfer.meta_data.blocksize],
                length,
                transfer.meta_data.blocksize,
                transfer.meta_data.next_block_sequence_counter,
            )
        };

        // we do not want to check the service on every execution, but it is checked before
        // transfer_ecu_data is called
        let skip_security_plugin_check: DynamicPlugin = Box::new(());
        while remaining_bytes > 0 {
            let Some(remaining_as_usize) = remaining_bytes.try_into().ok() else {
                set_transfer_aborted(
                    ecu_name,
                    &self.data_transfers,
                    "Remaining bytes overflowed usize".to_owned(),
                    &status_sender,
                )
                .await;
                break;
            };

            let bytes_to_read = block_size.min(remaining_as_usize);

            let Some(buffer_slice) = buffer.get_mut(..bytes_to_read) else {
                set_transfer_aborted(
                    ecu_name,
                    &self.data_transfers,
                    "Buffer slice out of bounds".to_owned(),
                    &status_sender,
                )
                .await;
                break;
            };

            if let Err(e) = reader.read_exact(buffer_slice).await {
                set_transfer_aborted(
                    ecu_name,
                    &self.data_transfers,
                    format!("Failed to read data: {e:?}"),
                    &status_sender,
                )
                .await;
                break;
            }

            let mut buf = Vec::with_capacity(
                /*block sequence counter*/ 1usize.saturating_add(bytes_to_read),
            );
            buf.push(next_block_sequence_counter);

            let Some(buffer_data) = buffer.get(..bytes_to_read) else {
                set_transfer_aborted(
                    ecu_name,
                    &self.data_transfers,
                    "Buffer slice out of bounds".to_owned(),
                    &status_sender,
                )
                .await;
                break;
            };
            buf.extend_from_slice(buffer_data);

            let uds_payload = UdsPayloadData::Raw(buf);
            let result = self
                .send(
                    ecu_name,
                    request.clone(),
                    &skip_security_plugin_check,
                    Some(uds_payload),
                    true,
                )
                .await;
            if let Err(e) = result {
                set_transfer_aborted(
                    ecu_name,
                    &self.data_transfers,
                    format!("Failed to read data: {e:?}"),
                    &status_sender,
                )
                .await;
                break;
            }

            {
                let mut lock = self.data_transfers.lock().await;
                let Some(transfer) = lock.get_mut(ecu_name) else {
                    tracing::error!("No transfer found, cannot update data transfer");
                    return;
                };

                next_block_sequence_counter = next_block_sequence_counter.wrapping_add(1);
                transfer.meta_data.next_block_sequence_counter = next_block_sequence_counter;
                transfer.meta_data.acknowledged_bytes = transfer
                    .meta_data
                    .acknowledged_bytes
                    .saturating_add(bytes_to_read as u64);

                remaining_bytes = remaining_bytes.saturating_sub(bytes_to_read as u64);
                if remaining_bytes == 0 {
                    transfer.meta_data.status = DataTransferStatus::Finished;
                    if let Err(e) = status_sender.send(true) {
                        tracing::error!(
                            error = ?e,
                            "Failed to send data transfer completion signal"
                        );
                    }
                }
            }
        }
    }
}

#[async_trait]
impl<S: EcuGateway, T: EcuManager> UdsDataTransfer for UdsManager<S, T> {
    async fn ecu_flash_transfer_start(
        &self,
        ecu_name: &str,
        func_class_name: &str,
        security_plugin: &DynamicPlugin,
        parameters: FlashTransferStartParams<'_>,
    ) -> Result<(), DiagServiceError> {
        use std::sync::atomic::Ordering;

        let FlashTransferStartParams {
            file_path,
            offset,
            length,
            owner,
            transfer_meta_data,
        } = parameters;

        if length == 0 {
            return Err(DiagServiceError::InvalidRequest(
                "Transfer length must be greater than 0".to_owned(),
            ));
        }

        // even if the data transfer job is done,
        // data_transfer_exit must be called before starting a new one
        if let Some(transfer) = self.data_transfers.lock().await.get(ecu_name) {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Transfer data already running with id {}",
                transfer.meta_data.id
            )));
        }

        let file = File::open(file_path).await.map_err(|e| {
            DiagServiceError::InvalidRequest(format!("Failed to open file '{file_path}': {e:?}"))
        })?;

        let flash_file_meta_data = file.metadata().await.map_err(|e| {
            DiagServiceError::InvalidRequest(format!("Failed to get metadata: {e:?}"))
        })?;

        let file_size = flash_file_meta_data.len();
        if file_size < offset.saturating_add(length) {
            return Err(DiagServiceError::InvalidRequest(format!(
                "File size {file_size} is too small for the requested offset {offset} and length \
                 {length}",
            )));
        }

        let mut reader = BufReader::new(file);
        reader
            .seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| {
                DiagServiceError::InvalidRequest(format!("Failed to seek to offset in file: {e:?}"))
            })?;

        let ecu = self.uds_ecu_db(ecu_name)?;
        let request = ecu
            .read()
            .await
            .lookup_service_through_func_class(func_class_name, service_ids::TRANSFER_DATA)?;

        ecu.read()
            .await
            .is_service_allowed(&request, security_plugin)
            .await?;

        let ecu_name = ecu_name.to_owned();
        let ecu_name_clone = ecu_name.clone();

        let (sender, receiver) = watch::channel::<bool>(false);

        // lock the transfers, to make sure the task only accesses the transfers once
        // we are fully initialized
        let mut transfer_lock = self.data_transfers.lock().await;
        if self.update_in_progress.load(Ordering::Acquire) {
            return Err(DiagServiceError::InvalidRequest(
                "Runtime update in progress, flash transfer blocked".to_owned(),
            ));
        }
        let uds = self.clone();
        let transfer_task = spawn_named!(&format!("flashtransfer-{ecu_name}"), async move {
            uds.transfer_ecu_data(&ecu_name, length, request, sender, reader)
                .await;
        });

        transfer_lock.insert(
            ecu_name_clone,
            EcuDataTransfer {
                meta_data: transfer_meta_data,
                owner,
                status_receiver: receiver,
                task: transfer_task,
            },
        );
        Ok(())
    }

    async fn ecu_flash_transfer_exit(
        &self,
        ecu_name: &str,
        id: &str,
        owner: &str,
    ) -> Result<(), DiagServiceError> {
        let mut lock = self.data_transfers.lock().await;
        let transfer = lock.get(ecu_name).ok_or_else(|| {
            DiagServiceError::NotFound(format!("Data transfer for ECU {ecu_name} not found"))
        })?;

        if transfer.meta_data.id != id || transfer.owner != owner {
            return Err(DiagServiceError::NotFound(format!(
                "Data transfer with id {id} not found for ECU {ecu_name}"
            )));
        }

        if !matches!(
            transfer.meta_data.status,
            DataTransferStatus::Aborted | DataTransferStatus::Finished
        ) {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Data transfer with id {id} is currently in status {:?}, cannot exit",
                transfer.meta_data.status,
            )));
        }

        // Now it is safe to remove the transfer from the map
        let mut transfer = lock.remove(ecu_name).ok_or_else(|| {
            DiagServiceError::NotFound(format!(
                "Data transfer for ECU {ecu_name} not found during exit"
            ))
        })?;

        if let Err(e) = transfer.status_receiver.changed().await {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Failed to receive data transfer exit signal: {e:?}"
            )));
        }

        transfer.task.await.map_err(|e| {
            DiagServiceError::InvalidRequest(format!("Failed to await data transfer task: {e:?}"))
        })?;

        Ok(())
    }

    async fn ecu_flash_transfer_abort(&self, ecu_name: &str) {
        if let Some(transfer) = self.data_transfers.lock().await.remove(ecu_name) {
            transfer.task.abort();
        }
    }

    async fn ecu_flash_transfer_status(
        &self,
        ecu_name: &str,
    ) -> Result<Vec<DataTransferMetaData>, DiagServiceError> {
        let meta_data = self
            .data_transfers
            .lock()
            .await
            .get(ecu_name)
            .map(|transfer| transfer.meta_data.clone())
            .ok_or_else(|| {
                DiagServiceError::NotFound(format!("No data transfer running for ECU {ecu_name}"))
            })?;

        Ok(vec![meta_data.clone()])
    }

    async fn ecu_flash_transfer_status_id(
        &self,
        ecu_name: &str,
        id: &str,
    ) -> Result<DataTransferMetaData, DiagServiceError> {
        self.ecu_flash_transfer_status(ecu_name)
            .await?
            .into_iter()
            .find(|transfer| transfer.id == id)
            .ok_or_else(|| {
                DiagServiceError::NotFound(format!(
                    "Data transfer with id {id} not found for ECU {ecu_name}"
                ))
            })
    }
}
