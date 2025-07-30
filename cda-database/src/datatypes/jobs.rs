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

use cda_interfaces::{DiagServiceError, STRINGS, StringId, datatypes::single_ecu};
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;
use hashbrown::HashMap;

use crate::{
    datatypes::{Id, LongName, option_str_to_string, ref_optional_none},
    proto::dataformat,
};

pub type BaseSingleEcuJobMap = HashMap<String, Id>;
pub type SingleEcuJobMap = HashMap<Id, SingleEcuJob>;

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct JobParam {
    pub short_name: StringId,
    pub long_name: Option<LongName>,
    pub physical_default_value: Option<StringId>,
    #[allow(dead_code)]
    pub dop: Id, // todo use DOP -> out of scope for POC
    pub semantic: Option<StringId>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct ProgCode {
    pub code_file: StringId,
    pub encryption: Option<StringId>,
    pub syntax: Option<StringId>,
    pub revision: StringId,
    pub entrypoint: StringId,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct SingleEcuJob {
    pub short_name: StringId,
    pub long_name: Option<StringId>,
    pub semantic: StringId,
    pub input_params: Vec<JobParam>,
    pub output_params: Vec<JobParam>,
    pub neg_output_params: Vec<JobParam>,
    pub prog_codes: Vec<ProgCode>,
}

impl From<&SingleEcuJob> for single_ecu::Job {
    fn from(value: &SingleEcuJob) -> Self {
        Self {
            input_params: value
                .input_params
                .iter()
                .map(std::convert::Into::into)
                .collect(),
            output_params: value
                .output_params
                .iter()
                .map(std::convert::Into::into)
                .collect(),
            neg_output_params: value
                .neg_output_params
                .iter()
                .map(std::convert::Into::into)
                .collect(),
            prog_codes: value
                .prog_codes
                .iter()
                .map(std::convert::Into::into)
                .collect(),
        }
    }
}

impl From<&LongName> for single_ecu::LongName {
    fn from(value: &LongName) -> Self {
        Self {
            value: value.value.and_then(|v| STRINGS.get(v)),
            ti: value.ti.and_then(|v| STRINGS.get(v)),
        }
    }
}

impl From<&JobParam> for single_ecu::Param {
    fn from(value: &JobParam) -> Self {
        Self {
            short_name: STRINGS.get(value.short_name).unwrap_or_default(),
            physical_default_value: value.physical_default_value.and_then(|v| STRINGS.get(v)),
            semantic: value.semantic.and_then(|v| STRINGS.get(v)),
            long_name: value.long_name.as_ref().map(std::convert::Into::into),
        }
    }
}

impl From<&dataformat::JobParam> for Result<JobParam, DiagServiceError> {
    fn from(param: &dataformat::JobParam) -> Self {
        Ok::<JobParam, DiagServiceError>(JobParam {
            short_name: STRINGS.get_or_insert(&param.short_name),
            long_name: param.long_name.as_ref().map(|name| LongName {
                value: option_str_to_string(name.value.as_ref()),
                ti: option_str_to_string(name.ti.as_ref()),
            }),
            physical_default_value: option_str_to_string(param.physical_default_value.as_ref()),
            dop: param
                .dop_base
                .as_ref()
                .ok_or_else(|| {
                    DiagServiceError::InvalidDatabase("Param Value has no DOP set.".to_owned())
                })?
                .r#ref
                .as_ref()
                .ok_or_else(|| ref_optional_none("Param.dopBase.ref_pb"))?
                .value,
            semantic: option_str_to_string(param.semantic.as_ref()),
        })
    }
}

impl From<&ProgCode> for single_ecu::ProgCode {
    fn from(value: &ProgCode) -> Self {
        Self {
            code_file: STRINGS.get(value.code_file).unwrap_or_default(),
            encryption: value.encryption.and_then(|v| STRINGS.get(v)),
            syntax: value.syntax.and_then(|v| STRINGS.get(v)),
            revision: STRINGS.get(value.revision).unwrap_or_default(),
            entrypoint: STRINGS.get(value.entrypoint).unwrap_or_default(),
        }
    }
}

/// Read the single ecus jobs from the proto database and convert them to the
/// internal types.
/// `SingleEcuJobMap` contains mapping from `Id` to `SingleEcuJob`.
/// The `HashMap<String, Id>` contains mapping from short name to `Id`.
pub fn get_single_ecu_jobs(
    ecu_data: &dataformat::EcuData,
) -> Result<SingleEcuJobMap, DiagServiceError> {
    fn convert_params(params: &[dataformat::JobParam]) -> Result<Vec<JobParam>, DiagServiceError> {
        params
            .iter()
            .map(std::convert::Into::into)
            .collect::<Result<Vec<JobParam>, DiagServiceError>>()
    }

    fn convert_prog_codes(
        codes: &[dataformat::ProgCode],
    ) -> Result<Vec<ProgCode>, DiagServiceError> {
        codes
            .iter()
            .map(|code| {
                Ok(ProgCode {
                    code_file: STRINGS.get_or_insert(&code.code_file),
                    encryption: option_str_to_string(code.encryption.as_ref()),
                    syntax: option_str_to_string(code.syntax.as_ref()),
                    revision: STRINGS.get_or_insert(&code.revision),
                    entrypoint: STRINGS.get_or_insert(&code.entrypoint),
                })
            })
            .collect::<Result<Vec<ProgCode>, DiagServiceError>>()
    }

    let mut single_ecu_job_lookup: HashMap<String, Id> = HashMap::new();
    let single_ecu_jobs = ecu_data
        .single_ecu_jobs
        .iter()
        .map(|job| {
            let diag_comm = job.diag_comm.as_ref().ok_or_else(|| {
                DiagServiceError::InvalidDatabase("Diag Comm not set for ecu job.".to_owned())
            })?;

            let id = job
                .id
                .as_ref()
                .ok_or_else(|| ref_optional_none("Job.id"))?
                .value;
            let name = STRINGS.get_or_insert(&diag_comm.short_name);
            single_ecu_job_lookup.insert(diag_comm.short_name.to_lowercase(), id);

            Ok((
                id,
                SingleEcuJob {
                    short_name: name,
                    long_name: diag_comm
                        .long_name
                        .as_ref()
                        .and_then(|ln| option_str_to_string(ln.value.as_ref())),
                    semantic: STRINGS.get_or_insert(&diag_comm.semantic),
                    input_params: convert_params(&job.input_params)?,
                    output_params: convert_params(&job.output_params)?,
                    neg_output_params: convert_params(&job.neg_output_params)?,
                    prog_codes: convert_prog_codes(&job.prog_codes)?,
                },
            ))
        })
        .collect::<Result<SingleEcuJobMap, DiagServiceError>>()?;
    Ok(single_ecu_jobs)
}
