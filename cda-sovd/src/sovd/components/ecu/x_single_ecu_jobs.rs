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
    use aide::transform::TransformOperation;
    use axum::{
        Json,
        extract::{Path, Query, State},
        http::StatusCode,
        response::{IntoResponse as _, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{UdsEcu, diagservices::DiagServiceResponse, file_manager::FileManager};

    use crate::{
        openapi,
        sovd::{
            IntoSovd, WebserverEcuState, create_schema,
            error::{ApiError, ErrorWrapper},
        },
    };

    openapi::aide_helper::gen_path_param!(ExecutionJobPathParam job_name String);

    pub(crate) async fn get<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
        State(WebserverEcuState { uds, ecu_name, .. }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        let include_schema = query.include_schema;
        let schema = if include_schema {
            Some(create_schema!(
                sovd_interfaces::components::ecu::ComponentData
            ))
        } else {
            None
        };
        match uds.get_components_single_ecu_jobs_info(&ecu_name).await {
            Ok(mut items) => {
                let sovd_component_data = sovd_interfaces::components::ecu::ComponentData {
                    items: items
                        .drain(0..)
                        .map(crate::sovd::IntoSovd::into_sovd)
                        .collect(),
                    schema,
                };
                (StatusCode::OK, Json(sovd_component_data)).into_response()
            }
            Err(e) => ErrorWrapper {
                error: e.into(),
                include_schema,
            }
            .into_response(),
        }
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Get list of single-ecu-jobs for component")
            .response_with::<200, Json<sovd_interfaces::components::ecu::ComponentData>, _>(|res| {
                res.example(sovd_interfaces::components::ecu::ComponentData {
                    items: vec![sovd_interfaces::components::ecu::ComponentDataInfo {
                        id: "hard_reset".to_owned(),
                        name: "Hard Reset".to_owned(),
                        category: "function".to_owned(),
                    }],
                    schema: None,
                })
            })
            .with(openapi::error_bad_request)
    }

    pub(crate) mod name {
        use super::*;
        pub(crate) async fn get<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
            Path(job_name): Path<ExecutionJobPathParam>,
            WithRejection(Query(query), _): WithRejection<
                Query<sovd_interfaces::IncludeSchemaQuery>,
                ApiError,
            >,
            State(WebserverEcuState { uds, ecu_name, .. }): State<WebserverEcuState<R, T, U>>,
        ) -> Response {
            let include_schema = query.include_schema;
            let mut job = match uds
                .get_single_ecu_job(&ecu_name, &job_name)
                .await
                .map(crate::sovd::IntoSovd::into_sovd)
            {
                Ok(job) => job,
                Err(e) => {
                    return ErrorWrapper {
                        error: e.into(),
                        include_schema,
                    }
                    .into_response();
                }
            };
            if include_schema {
                job.schema = Some(create_schema!(
                    sovd_interfaces::components::ecu::x::single_ecu_job::Job
                ));
            }

            (StatusCode::OK, Json(job)).into_response()
        }

        pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
            op.description("Get single-ecu-job by name for component")
                .response_with::<
                    200,
                    Json<sovd_interfaces::components::ecu::x::single_ecu_job::Job>,
                    _>(|res| {
                        res.example(sovd_interfaces::components::ecu::x::single_ecu_job::Job {
                            input_params: vec![],
                            output_params: vec![],
                            neg_output_params: vec![],
                            prog_codes: vec![],
                            schema: None,
                        })
                    },
                )
                .with(openapi::error_not_found)
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
                    sdgs: sdgs
                        .into_iter()
                        .map(crate::sovd::IntoSovd::into_sovd)
                        .collect(),
                },
            }
        }
    }

    impl IntoSovd for Vec<cda_interfaces::datatypes::SdSdg> {
        type SovdType = Vec<sovd_interfaces::components::ecu::SdSdg>;

        fn into_sovd(self) -> Self::SovdType {
            self.into_iter()
                .map(crate::sovd::IntoSovd::into_sovd)
                .collect()
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
                long_name: self.long_name.map(crate::sovd::IntoSovd::into_sovd),
            }
        }
    }

    impl IntoSovd for Vec<cda_interfaces::datatypes::single_ecu::Param> {
        type SovdType = Vec<sovd_interfaces::components::ecu::x::single_ecu_job::Param>;

        fn into_sovd(self) -> Self::SovdType {
            self.into_iter()
                .map(crate::sovd::IntoSovd::into_sovd)
                .collect()
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
                    .map(crate::sovd::IntoSovd::into_sovd)
                    .collect(),
                schema: None,
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
