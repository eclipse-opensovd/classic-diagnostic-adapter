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

pub(crate) mod single_ecu {
    use axum::{
        Json,
        extract::{Path, State},
        http::StatusCode,
        response::{IntoResponse as _, Response},
    };
    use cda_interfaces::{UdsEcu, diagservices::DiagServiceResponse, file_manager::FileManager};

    use crate::sovd::{
        IntoSovd, WebserverEcuState,
        error::{ApiError, ErrorWrapper},
    };

    pub(crate) async fn get<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        State(WebserverEcuState { uds, ecu_name, .. }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        match uds.get_components_single_ecu_jobs_info(&ecu_name).await {
            Ok(mut items) => {
                let sovd_component_data = sovd_interfaces::components::ecu::ComponentData {
                    items: items.drain(0..).map(|c| c.into_sovd()).collect(),
                };
                (StatusCode::OK, Json(sovd_component_data)).into_response()
            }
            Err(e) => ErrorWrapper(ApiError::BadRequest(e)).into_response(),
        }
    }

    pub(crate) mod name {
        use super::*;
        pub(crate) async fn get<
            R: DiagServiceResponse + Send + Sync,
            T: UdsEcu + Send + Sync + Clone,
            U: FileManager + Send + Sync + Clone,
        >(
            Path(job_name): Path<String>,
            State(WebserverEcuState { uds, ecu_name, .. }): State<WebserverEcuState<R, T, U>>,
        ) -> Response {
            uds.get_single_ecu_job(&ecu_name, &job_name)
                .await
                .map_or_else(
                    |e| ErrorWrapper(e.into()).into_response(),
                    |job| (StatusCode::OK, Json(job.into_sovd())).into_response(),
                )
        }
    }

    impl IntoSovd for cda_interfaces::datatypes::ComponentDataInfo {
        type SovdType = sovd_interfaces::components::ecu::ComponentDataInfo;

        fn into_sovd(self) -> Self::SovdType {
            Self::SovdType {
                category: self.category.clone(),
                id: self.id,
                name: self.name.clone(),
            }
        }
    }

    impl IntoSovd for cda_interfaces::datatypes::SdSdg {
        type SovdType = sovd_interfaces::components::ecu::SdSdg;

        fn into_sovd(self) -> Self::SovdType {
            match self {
                Self::Sd { value: v, si, ti } => Self::SovdType::Sd {
                    value: v,
                    si,
                    ti: ti.clone(),
                },
                Self::Sdg { caption, si, sdgs } => Self::SovdType::Sdg {
                    caption: caption.clone(),
                    si: si.clone(),
                    sdgs: sdgs.into_iter().map(|sdg| sdg.into_sovd()).collect(),
                },
            }
        }
    }

    impl IntoSovd for Vec<cda_interfaces::datatypes::SdSdg> {
        type SovdType = Vec<sovd_interfaces::components::ecu::SdSdg>;

        fn into_sovd(self) -> Self::SovdType {
            self.into_iter().map(|sdg| sdg.into_sovd()).collect()
        }
    }

    impl IntoSovd for cda_interfaces::datatypes::single_ecu::ProgCode {
        type SovdType = sovd_interfaces::components::ecu::x::single_ecu_job::ProgCode;

        fn into_sovd(self) -> Self::SovdType {
            Self::SovdType {
                code_file: self.code_file,
                encryption: self.encryption,
                syntax: self.syntax,
                revision: self.revision,
                entrypoint: self.entrypoint,
            }
        }
    }

    impl IntoSovd for cda_interfaces::datatypes::single_ecu::LongName {
        type SovdType = sovd_interfaces::components::ecu::x::single_ecu_job::LongName;

        fn into_sovd(self) -> Self::SovdType {
            Self::SovdType {
                value: self.value,
                ti: self.ti,
            }
        }
    }

    impl IntoSovd for cda_interfaces::datatypes::single_ecu::Param {
        type SovdType = sovd_interfaces::components::ecu::x::single_ecu_job::Param;

        fn into_sovd(self) -> Self::SovdType {
            Self::SovdType {
                short_name: self.short_name,
                physical_default_value: self.physical_default_value,
                semantic: self.semantic,
                long_name: self.long_name.map(|ln| ln.into_sovd()),
            }
        }
    }

    impl IntoSovd for Vec<cda_interfaces::datatypes::single_ecu::Param> {
        type SovdType = Vec<sovd_interfaces::components::ecu::x::single_ecu_job::Param>;

        fn into_sovd(self) -> Self::SovdType {
            self.into_iter().map(|p| p.into_sovd()).collect()
        }
    }

    impl IntoSovd for cda_interfaces::datatypes::single_ecu::Job {
        type SovdType = sovd_interfaces::components::ecu::x::single_ecu_job::Job;

        fn into_sovd(self) -> Self::SovdType {
            Self::SovdType {
                input_params: self.input_params.into_sovd(),
                output_params: self.output_params.into_sovd(),
                neg_output_params: self.neg_output_params.into_sovd(),
                prog_codes: self
                    .prog_codes
                    .into_iter()
                    .map(|pc| pc.into_sovd())
                    .collect(),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use sovd_interfaces::components::ecu::x::single_ecu_job::{LongName, Param};

        #[test]
        fn test_param_serialization() {
            let param_with_empty_long_name = Param {
                short_name: "TestShortName".to_string(),
                physical_default_value: None,
                semantic: None,
                long_name: Some(LongName {
                    value: None,
                    ti: None,
                }),
            };

            let param_with_long_name_has_value = Param {
                short_name: "TestShortName".to_string(),
                physical_default_value: None,
                semantic: None,
                long_name: Some(LongName {
                    value: Some("Value".to_string()),
                    ti: None,
                }),
            };

            let param_with_long_name_ti_has_value = Param {
                short_name: "TestShortName".to_string(),
                physical_default_value: None,
                semantic: None,
                long_name: Some(LongName {
                    value: None,
                    ti: Some("Value".to_string()),
                }),
            };

            let param_without_long_name = Param {
                short_name: "TestShortName".to_string(),
                physical_default_value: None,
                semantic: None,
                long_name: None,
            };

            let serialized_empty_long_name =
                serde_json::to_string(&param_with_empty_long_name).unwrap();
            let serialized_with_long_name_value =
                serde_json::to_string(&param_with_long_name_has_value).unwrap();
            let serialized_with_long_name_ti =
                serde_json::to_string(&param_with_long_name_ti_has_value).unwrap();
            let serialized_without_long_name =
                serde_json::to_string(&param_without_long_name).unwrap();

            assert_eq!(
                serialized_empty_long_name,
                r#"{"short_name":"TestShortName"}"#
            );

            assert_eq!(
                serialized_with_long_name_value,
                r#"{"short_name":"TestShortName","long_name":{"value":"Value"}}"#
            );

            assert_eq!(
                serialized_with_long_name_ti,
                r#"{"short_name":"TestShortName","long_name":{"ti":"Value"}}"#
            );

            assert_eq!(
                serialized_without_long_name,
                r#"{"short_name":"TestShortName"}"#
            );
        }
    }
}
