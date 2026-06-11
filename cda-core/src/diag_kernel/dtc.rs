/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use cda_database::datatypes;
use cda_interfaces::{
    DiagCommType, DiagServiceError, HashMap,
    datatypes::{DtcLookup, DtcReadInformationFunction},
    service_ids,
};
use cda_plugin_security::SecurityPlugin;

use super::ecumanager::EcuManager;

impl<S: SecurityPlugin> EcuManager<S> {
    pub(crate) fn lookup_dtc_services(
        &self,
        service_types: Vec<DtcReadInformationFunction>,
    ) -> Result<HashMap<DtcReadInformationFunction, DtcLookup>, DiagServiceError> {
        self.lookup_services_by_sid(service_ids::READ_DTC_INFORMATION)?
            .into_iter()
            .filter_map(|service| {
                let (sub_function_id, _) = service.request_sub_function_id()?;
                service_types
                    .iter()
                    .find(|st| (**st as u32) == sub_function_id)
                    .map(|st| (service, st))
            })
            .map(|(service, dtc_service_type)| {
                let scope = *dtc_service_type;

                let service_short_name = service
                    .diag_comm()
                    .and_then(|dc| dc.short_name().map(ToOwned::to_owned))
                    .ok_or_else(|| {
                        DiagServiceError::InvalidDatabase("No DiagComm found".to_owned())
                    })?;

                let params: Vec<datatypes::Parameter> = service
                    .pos_responses()
                    .map(|responses| {
                        responses
                            .iter()
                            .flat_map(|r| r.params().into_iter().flatten())
                            .map(datatypes::Parameter)
                            .collect()
                    })
                    .ok_or_else(|| {
                        DiagServiceError::ParameterConversionError(
                            "No positive response found for DTC service".to_owned(),
                        )
                    })?;

                let dtcs: Vec<cda_interfaces::datatypes::DtcRecord> =
                    Self::find_dtc_dop_in_params(&params)?
                        .and_then(|dtc_dop| {
                            dtc_dop.dtcs().map(|dtcs| {
                                dtcs.iter()
                                    .map(|dtc| {
                                        let record: cda_interfaces::datatypes::DtcRecord =
                                            dtc.into();
                                        record
                                    })
                                    .collect()
                            })
                        })
                        .unwrap_or_default();

                Ok((
                    *dtc_service_type,
                    DtcLookup {
                        scope,
                        service: cda_interfaces::DiagComm {
                            name: service_short_name.clone(),
                            type_: DiagCommType::Faults,
                            lookup_name: Some(service_short_name),
                            subfunction_id: None,
                        },
                        dtcs,
                    },
                ))
            })
            .collect()
    }

    pub(crate) fn find_dtc_dop_in_params<'a>(
        params: &Vec<datatypes::Parameter<'a>>,
    ) -> Result<Option<datatypes::DtcDop<'a>>, DiagServiceError> {
        for p in params {
            let Some(value) = p.specific_data_as_value() else {
                continue;
            };
            let Some(dop) = value.dop() else { continue };

            if let Some(dtc_dop) = dop.specific_data_as_dtcdop() {
                return Ok(Some(datatypes::DtcDop(dtc_dop)));
            }

            // Recursively search in nested structures
            let nested_params = Self::extract_nested_params(&dop.into())?;
            if let Some(result) = Self::find_dtc_dop_in_params(&nested_params)? {
                return Ok(Some(result));
            }
        }
        Ok(None)
    }

    pub(crate) fn extract_nested_params<'a>(
        dop: &datatypes::DataOperation<'a>,
    ) -> Result<Vec<datatypes::Parameter<'a>>, DiagServiceError> {
        if let Some(end_of_pdu_dop) = dop.specific_data_as_end_of_pdu_field() {
            let struct_ = end_of_pdu_dop
                .field()
                .and_then(|f| f.basic_structure())
                .and_then(|s| s.specific_data_as_structure())
                .ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(
                        "EndOfPdu does not contain a struct".to_owned(),
                    )
                })?;

            return Ok(struct_
                .params()
                .map(|params| params.iter().map(datatypes::Parameter).collect())
                .unwrap_or_default());
        }

        if let Some(structure_dop) = dop.specific_data_as_structure() {
            return Ok(structure_dop
                .params()
                .map(|params| params.iter().map(datatypes::Parameter).collect())
                .unwrap_or_default());
        }

        Ok(Vec::new())
    }

    pub(crate) fn map_dtc_dop_from_uds(
        param_name: &str,
        uds_payload: &mut crate::diag_kernel::payload::Payload,
        data: &mut crate::diag_kernel::diagservices::MappedDiagServiceResponsePayload,
        dtc_dop: &datatypes::DtcDop,
        param_ctx: super::ecumanager::ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        use cda_interfaces::datatypes::DTC_CODE_BIT_LEN;

        use crate::{
            DiagDataContainerDtc,
            diag_kernel::{DiagDataValue, diagservices::DiagDataTypeContainer},
        };

        let coded_type: datatypes::DiagCodedType = dtc_dop.diag_coded_type()?;

        let (dtc_value, _size) = coded_type.decode(
            uds_payload.data()?,
            param_ctx.abs_byte_pos(),
            param_ctx.parameter.bit_position() as usize,
        )?;

        let code: u32 = DiagDataValue::new(coded_type.base_datatype(), &dtc_value)?.try_into()?;

        let record = dtc_dop
            .dtcs()
            .and_then(|dtcs| dtcs.iter().find(|dtc| dtc.trouble_code() == code))
            .ok_or(DiagServiceError::BadPayload(format!(
                "No DTC with code {code:X} found in DTC references",
            )))?;

        data.insert(
            param_name.to_owned(),
            DiagDataTypeContainer::DtcStruct(DiagDataContainerDtc {
                code,
                display_code: record.display_trouble_code().map(ToOwned::to_owned),
                fault_name: record
                    .text()
                    .and_then(|text| text.value().map(ToOwned::to_owned))
                    .unwrap_or_default(),
                severity: record.level().unwrap_or_default(),
                bit_pos: param_ctx.parameter.bit_position(),
                bit_len: DTC_CODE_BIT_LEN,
                byte_pos: u32::try_from(param_ctx.abs_byte_pos()).map_err(|_| {
                    DiagServiceError::InvalidDatabase("DTC byte position overflows u32".to_owned())
                })?,
            }),
        );
        Ok(())
    }
}
