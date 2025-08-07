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

use axum::{
    extract::OriginalUri,
    response::{IntoResponse, Response},
};
use axum_extra::extract::Host;
use cda_interfaces::{
    UdsEcu,
    diagservices::{DiagServiceResponse, DiagServiceResponseType, UdsPayloadData},
};
use hashbrown::HashMap;

use crate::sovd::{
    error::{ApiError, ErrorWrapper, api_error_from_diag_response},
    resource_response,
};

const FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS: &str = "flash_download_upload";

async fn sovd_to_func_class_service_exec<T: UdsEcu + Send + Sync + Clone>(
    uds: &T,
    func_class: &str,
    ecu_name: &str,
    service_id: u8,
    parameters: HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, Response> {
    let params = UdsPayloadData::ParameterMap(parameters);
    let response = match uds
        .ecu_exec_service_from_function_class(ecu_name, func_class, service_id, params)
        .await
    {
        Ok(v) => v,
        Err(e) => return Err(ErrorWrapper(e.into()).into_response()),
    };

    if let DiagServiceResponseType::Negative = response.response_type() {
        return Err(api_error_from_diag_response(response).into_response());
    }

    let mapped_data = match response.into_json() {
        Ok(v) => v,
        Err(e) => {
            return Err(
                ErrorWrapper(ApiError::InternalServerError(Some(format!("{e:?}")))).into_response(),
            );
        }
    };

    Ok(mapped_data)
}

pub(crate) async fn get(Host(host): Host, OriginalUri(uri): OriginalUri) -> Response {
    resource_response(
        &host,
        &uri,
        vec![("RequestDownload", Some("requestdownload"))],
    )
}

pub(crate) mod request_download {
    use axum::{
        Json,
        extract::State,
        http::StatusCode,
        response::{IntoResponse as _, Response},
    };
    use cda_interfaces::{
        UdsEcu, diagservices::DiagServiceResponse, file_manager::FileManager, service_ids,
    };
    use sovd_interfaces::components::ecu::x::sovd2uds;

    use crate::sovd::{
        WebserverEcuState,
        x_sovd2uds_download::{FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS, sovd_to_func_class_service_exec},
    };

    pub(crate) async fn put<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
        body: Json<sovd2uds::download::request_download::put::Request>,
    ) -> Response {
        match sovd_to_func_class_service_exec::<T>(
            &uds,
            FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS,
            &ecu_name,
            service_ids::REQUEST_DOWNLOAD,
            body.parameters.clone(),
        )
        .await
        {
            Ok(mapped_data) => (
                StatusCode::OK,
                Json(sovd2uds::download::request_download::put::Response {
                    parameters: mapped_data,
                }),
            )
                .into_response(),
            Err(response) => response,
        }
    }
}

pub(crate) mod flash_transfer {
    use std::path::PathBuf;

    use axum::{
        Json,
        extract::{Path, State},
        response::{IntoResponse, Response},
    };
    use cda_interfaces::{UdsEcu, diagservices::DiagServiceResponse, file_manager::FileManager};
    use http::StatusCode;
    use sovd_interfaces::components::ecu::x::sovd2uds;
    use uuid::Uuid;

    use crate::sovd::{
        IntoSovd, WebserverEcuState,
        error::{ApiError, ErrorWrapper},
        x_sovd2uds_download::FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS,
    };

    pub(crate) async fn post<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        State(WebserverEcuState {
            ecu_name,
            uds,
            flash_data,
            ..
        }): State<WebserverEcuState<R, T, U>>,
        body: Json<sovd2uds::download::flash_transfer::post::Request>,
    ) -> Response {
        match flash_data
            .read()
            .await
            .files
            .iter()
            .find(|file| file.id == body.id)
        {
            Some(file) => {
                let id = Uuid::new_v4().to_string();
                let transfer = cda_interfaces::datatypes::DataTransferMetaData {
                    acknowledged_bytes: 0,
                    blocksize: body.blocksize,
                    next_block_sequence_counter: body.block_sequence_counter,
                    id: id.clone(),
                    file_id: body.id.clone(),
                    status: cda_interfaces::datatypes::DataTransferStatus::Queued,
                    error: None,
                };

                match uds
                    .ecu_flash_transfer_start(
                        &ecu_name,
                        FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS,
                        &flash_data
                            .read()
                            .await
                            .path
                            .as_ref()
                            .unwrap_or(&PathBuf::new())
                            .join(&file.origin_path)
                            .to_string_lossy(),
                        body.offset,
                        body.length,
                        transfer,
                    )
                    .await
                {
                    Ok(()) => (
                        StatusCode::OK,
                        Json(sovd2uds::download::flash_transfer::post::Response { id }),
                    )
                        .into_response(),
                    Err(e) => ErrorWrapper(e.into()).into_response(),
                }
            }
            None => (
                StatusCode::NOT_FOUND,
                ApiError::NotFound(Some(format!("File with id '{}' not found", body.id))),
            )
                .into_response(),
        }
    }

    pub(crate) async fn get<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        match uds.ecu_flash_transfer_status(&ecu_name).await {
            Ok(data) => (StatusCode::OK, Json(data.into_sovd())).into_response(),
            Err(e) => ErrorWrapper(e.into()).into_response(),
        }
    }

    pub(crate) mod id {
        use super::*;
        pub(crate) async fn get<
            R: DiagServiceResponse + Send + Sync,
            T: UdsEcu + Send + Sync + Clone,
            U: FileManager + Send + Sync + Clone,
        >(
            Path(id): Path<String>,
            State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
        ) -> Response {
            match uds.ecu_flash_transfer_status_id(&ecu_name, &id).await {
                Ok(data) => (StatusCode::OK, Json(data.into_sovd())).into_response(),
                Err(e) => ErrorWrapper(e.into()).into_response(),
            }
        }

        pub(crate) async fn delete<
            R: DiagServiceResponse + Send + Sync,
            T: UdsEcu + Send + Sync + Clone,
            U: FileManager + Send + Sync + Clone,
        >(
            Path(id): Path<String>,
            State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
        ) -> Response {
            match uds.ecu_flash_transfer_exit(&ecu_name, &id).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(e) => ErrorWrapper(e.into()).into_response(),
            }
        }
    }

    impl IntoSovd for cda_interfaces::datatypes::DataTransferStatus {
        type SovdType = sovd2uds::download::flash_transfer::get::DataTransferStatus;

        fn into_sovd(self) -> Self::SovdType {
            match self {
                Self::Running => Self::SovdType::Running,
                Self::Aborted => Self::SovdType::Aborted,
                Self::Finished => Self::SovdType::Finished,
                Self::Queued => Self::SovdType::Queued,
            }
        }
    }

    impl IntoSovd for cda_interfaces::datatypes::DataTransferError {
        type SovdType = sovd2uds::download::flash_transfer::get::DataTransferError;

        fn into_sovd(self) -> Self::SovdType {
            Self::SovdType { text: self.text }
        }
    }

    impl IntoSovd for cda_interfaces::datatypes::DataTransferMetaData {
        type SovdType = sovd2uds::download::flash_transfer::get::DataTransferMetaData;

        fn into_sovd(self) -> Self::SovdType {
            Self::SovdType {
                acknowledged_bytes: self.acknowledged_bytes,
                blocksize: self.blocksize,
                next_block_sequence_counter: self.next_block_sequence_counter,
                id: self.id,
                file_id: self.file_id,
                status: self.status.into_sovd(),
                error: self
                    .error
                    .map(|e| e.into_iter().map(|e| e.into_sovd()).collect()),
            }
        }
    }

    impl IntoSovd for Vec<cda_interfaces::datatypes::DataTransferMetaData> {
        type SovdType = Vec<sovd2uds::download::flash_transfer::get::DataTransferMetaData>;

        fn into_sovd(self) -> Self::SovdType {
            self.into_iter().map(|md| md.into_sovd()).collect()
        }
    }
}

pub(crate) mod transferexit {
    use axum::{
        extract::State,
        response::{IntoResponse, Response},
    };
    use cda_interfaces::{
        UdsEcu, diagservices::DiagServiceResponse, file_manager::FileManager, service_ids,
    };
    use hashbrown::HashMap;
    use http::StatusCode;

    use crate::sovd::{
        WebserverEcuState,
        x_sovd2uds_download::{FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS, sovd_to_func_class_service_exec},
    };

    pub(crate) async fn put<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        match sovd_to_func_class_service_exec::<T>(
            &uds,
            FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS,
            &ecu_name,
            service_ids::REQUEST_TRANSFER_EXIT,
            HashMap::new(),
        )
        .await
        {
            Ok(_) => StatusCode::NO_CONTENT.into_response(),
            Err(response) => response,
        }
    }
}
