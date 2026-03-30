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

use cda_database::datatypes::{self, DataType};
use cda_interfaces::{
    DiagComm, DiagServiceError, HashMap, HashMapExtensions,
    datatypes::{DtcField, DtcRecord},
    diagservices::{
        DiagServiceJsonResponse, DiagServiceResponse, DiagServiceResponseType, FieldParseError,
        MappedNRC,
    },
    service_ids::NEGATIVE_RESPONSE,
};

use crate::diag_kernel::{DiagDataValue, iso_14229_nrc, operations};

#[derive(Debug, Clone)]
pub struct DiagServiceResponseStruct {
    pub service: DiagComm,
    pub data: Vec<u8>,
    pub mapped_data: Option<MappedResponseData>,
    pub response_type: DiagServiceResponseType,
}

pub const DTC_CODE_BIT_LEN: u32 = 24;

#[derive(Clone, Debug)]
pub struct DiagDataContainerDtc {
    pub code: u32,
    pub display_code: Option<String>,
    pub fault_name: String,
    pub severity: u32,
    pub bit_pos: u32,
    pub bit_len: u32,
    pub byte_pos: u32,
}

#[derive(Clone, Debug)]
pub enum DiagDataTypeContainer {
    RawContainer(DiagDataTypeContainerRaw),
    Struct(HashMap<String, DiagDataTypeContainer>),
    RepeatingStruct(Vec<HashMap<String, DiagDataTypeContainer>>),
    DtcStruct(DiagDataContainerDtc),
}

#[derive(Clone, Debug)]
pub struct DiagDataTypeContainerRaw {
    pub data: Vec<u8>,
    pub bit_len: usize,
    pub data_type: DataType,
    pub compu_method: Option<datatypes::CompuMethod>,
}

pub type MappedDiagServiceResponsePayload = HashMap<String, DiagDataTypeContainer>;

#[derive(Debug, Clone)]
pub struct MappedResponseData {
    pub data: MappedDiagServiceResponsePayload,
    pub errors: Vec<FieldParseError>,
}

impl DiagServiceResponse for DiagServiceResponseStruct {
    fn service_name(&self) -> String {
        self.service.name.clone()
    }
    fn response_type(&self) -> DiagServiceResponseType {
        self.response_type
    }

    fn get_raw(&self) -> &[u8] {
        &self.data
    }

    fn into_json(self) -> Result<DiagServiceJsonResponse, DiagServiceError> {
        self.serialize_to_json()
    }

    fn as_nrc(&self) -> Result<MappedNRC, DiagServiceError> {
        let Some(MappedResponseData {
            data: mapped_data,
            errors: _,
        }) = &self.mapped_data
        else {
            return extract_nrc_from_raw_data(&self.data);
        };
        let nrc_code = mapped_data
            .get("NRC")
            .and_then(|container| match container {
                DiagDataTypeContainer::RawContainer(nrc) => {
                    let raw = u8::from_be(*nrc.data.first()?);
                    let message = match operations::uds_data_to_serializable(
                        nrc.data_type,
                        nrc.compu_method.as_ref(),
                        true,
                        &nrc.data,
                    )
                    .unwrap_or_else(|_| DiagDataValue::String("Unknown".to_owned()))
                    {
                        DiagDataValue::String(v) => v,
                        _ => "N/A".to_owned(),
                    };
                    Some((raw, message))
                }
                _ => None,
            });
        let sid = mapped_data
            .get("SIDRQ_NR")
            .and_then(|container| match container {
                DiagDataTypeContainer::RawContainer(sid) => {
                    sid.data.first().map(|&b| u8::from_be(b))
                }
                _ => None,
            });

        if let Some((code, description)) = nrc_code {
            Ok(MappedNRC {
                code: Some(code),
                description: Some(description),
                sid,
            })
        } else {
            Ok(MappedNRC {
                code: None,
                description: None,
                sid,
            })
        }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn get_dtcs(&self) -> Result<Vec<(DtcField, DtcRecord)>, DiagServiceError> {
        fn get(container: &DiagDataTypeContainer) -> Option<Vec<&DiagDataContainerDtc>> {
            match container {
                DiagDataTypeContainer::DtcStruct(dtc) => Some(vec![dtc]),
                DiagDataTypeContainer::Struct(s) => {
                    let results: Vec<_> = s
                        .values()
                        .map(|container| get(container).unwrap_or_default())
                        .collect();
                    Some(results.into_iter().flatten().collect())
                }
                DiagDataTypeContainer::RepeatingStruct(r) => {
                    let results = r
                        .iter()
                        .map(|m| {
                            m.values()
                                .map(|container| get(container).unwrap_or_default())
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();
                    Some(results.into_iter().flatten().flatten().collect())
                }
                DiagDataTypeContainer::RawContainer(_) => None,
            }
        }

        let mut dtcs = Vec::new();
        for container in self
            .mapped_data
            .as_ref()
            .ok_or_else(|| DiagServiceError::BadPayload("No mapped data available".to_owned()))?
            .data
            .values()
        {
            if let Some(container_dtcs) = get(container) {
                dtcs.extend(container_dtcs.into_iter().map(|dtc| {
                    (
                        DtcField {
                            bit_pos: dtc.bit_pos,
                            bit_len: dtc.bit_len,
                            byte_pos: dtc.byte_pos,
                        },
                        DtcRecord {
                            code: dtc.code,
                            display_code: dtc.display_code.clone(),
                            fault_name: dtc.fault_name.clone(),
                            severity: dtc.severity,
                        },
                    )
                }));
            }
        }
        Ok(dtcs)
    }
}

impl DiagServiceResponseStruct {
    /// This function tries to serialize the `DiagServiceResponse` into a SOVD style JSON.
    ///
    /// # Errors
    /// Returns `Err` in case any currently unsupported Nesting of containers or if serde
    /// internally has an error when calling serialize on the elements.
    #[tracing::instrument(skip(self), fields(service_name = %self.service.name))]
    pub fn serialize_to_json(self) -> Result<DiagServiceJsonResponse, DiagServiceError> {
        let MappedResponseData { data, mut errors } = self.get_mapped_payload()?;
        if data.is_empty() {
            return Ok(DiagServiceJsonResponse {
                data: serde_json::Value::Null,
                errors,
            });
        }

        let start = std::time::Instant::now();
        let mapped_data = data
            .iter()
            .filter_map(|(k, v)| -> Option<Result<(_, _), DiagServiceError>> {
                let mapped = match Self::map_data(v, &mut errors, &format!("/{k}")) {
                    Ok(m) => m,
                    Err(e) => {
                        if let DiagServiceError::DataError(ref error) = e {
                            errors.push(FieldParseError {
                                path: format!("/{k}"),
                                error: error.clone(),
                            });
                            return None;
                        }
                        return Some(Err(e));
                    }
                };
                Some(Ok((k.clone(), mapped)))
            })
            .collect::<Result<HashMap<_, _>, DiagServiceError>>()
            .and_then(|mapped| {
                serde_json::to_value(&mapped)
                    .map_err(|e| DiagServiceError::ParameterConversionError(e.to_string()))
            })
            .map(|data| DiagServiceJsonResponse { data, errors });
        let end = std::time::Instant::now();

        tracing::debug!(
            mapping_duration = ?{end.saturating_duration_since(start)},
            "JSON mapping completed");
        mapped_data
    }

    fn get_mapped_payload(self) -> Result<MappedResponseData, DiagServiceError> {
        match self.mapped_data {
            Some(mapped_data) => Ok(mapped_data),
            None => Err(DiagServiceError::BadPayload(
                "Raw payload cannot be serialized to JSON".to_owned(),
            )),
        }
    }
    fn map_data(
        data: &DiagDataTypeContainer,
        errors: &mut Vec<FieldParseError>,
        path: &str,
    ) -> Result<DiagDataValue, DiagServiceError> {
        fn create_struct(
            hash_map: &HashMap<String, DiagDataTypeContainer>,
            inner_mapped: &mut HashMap<String, DiagDataValue>,
            errors: &mut Vec<FieldParseError>,
            path: &str,
        ) -> Result<(), DiagServiceError> {
            for (k, v) in hash_map {
                let val = match v {
                    DiagDataTypeContainer::RawContainer(raw) => {
                        operations::uds_data_to_serializable(
                            raw.data_type,
                            raw.compu_method.as_ref(),
                            false,
                            &raw.data,
                        )?
                    }
                    DiagDataTypeContainer::Struct(s) => {
                        let mut nested_mapped = HashMap::new();
                        match create_struct(
                            s,
                            &mut nested_mapped,
                            errors,
                            format!("{path}/{k}").as_str(),
                        ) {
                            Ok(()) => DiagDataValue::Struct(nested_mapped),
                            Err(e) => {
                                if let DiagServiceError::DataError(ref error) = e {
                                    errors.push(FieldParseError {
                                        path: format!("{path}/{k}"),
                                        error: error.clone(),
                                    });
                                    DiagDataValue::Struct(HashMap::default())
                                } else {
                                    return Err(e);
                                }
                            }
                        }
                    }
                    DiagDataTypeContainer::RepeatingStruct(vec) => {
                        let mut nested_vec = Vec::new();
                        for inner_hash_map in vec {
                            let mut inner_mapped = HashMap::new();
                            match create_struct(
                                inner_hash_map,
                                &mut inner_mapped,
                                errors,
                                format!("{path}/{k}").as_str(),
                            ) {
                                Ok(()) => nested_vec.push(inner_mapped),
                                Err(e) => {
                                    if let DiagServiceError::DataError(ref error) = e {
                                        errors.push(FieldParseError {
                                            path: format!("{path}/{k}"),
                                            error: error.clone(),
                                        });
                                    } else {
                                        return Err(e);
                                    }
                                }
                            }
                        }
                        DiagDataValue::RepeatingStruct(nested_vec)
                    }
                    DiagDataTypeContainer::DtcStruct(dtc) => create_dtc(dtc),
                };
                inner_mapped.insert(k.clone(), val);
            }
            Ok(())
        }

        fn create_dtc(dtc: &DiagDataContainerDtc) -> DiagDataValue {
            let mut map = HashMap::new();
            map.insert("code".to_owned(), DiagDataValue::UInt32(dtc.code));
            if let Some(display_code) = &dtc.display_code {
                map.insert(
                    "display_code".to_owned(),
                    DiagDataValue::String(display_code.clone()),
                );
            }
            map.insert(
                "fault_name".to_owned(),
                DiagDataValue::String(dtc.fault_name.clone()),
            );
            map.insert("severity".to_owned(), DiagDataValue::UInt32(dtc.severity));
            DiagDataValue::Struct(map)
        }

        match data {
            DiagDataTypeContainer::RawContainer(raw) => Ok(operations::uds_data_to_serializable(
                raw.data_type,
                raw.compu_method.as_ref(),
                false,
                &raw.data,
            )?),
            DiagDataTypeContainer::Struct(hash_map) => {
                let mut mapped = HashMap::new();
                create_struct(hash_map, &mut mapped, errors, path)?;
                Ok(DiagDataValue::Struct(mapped))
            }
            DiagDataTypeContainer::RepeatingStruct(vec) => {
                let mut mapped = Vec::new();
                for hash_map in vec {
                    let mut inner_mapped = HashMap::new();
                    create_struct(hash_map, &mut inner_mapped, errors, path)?;
                    mapped.push(inner_mapped);
                }
                Ok(DiagDataValue::RepeatingStruct(mapped))
            }
            DiagDataTypeContainer::DtcStruct(dtc) => Ok(create_dtc(dtc)),
        }
    }
}

fn extract_nrc_from_raw_data(data: &[u8]) -> Result<MappedNRC, DiagServiceError> {
    let (Some(&first_byte), Some(&sid_byte), Some(&nrc_byte)) =
        (data.first(), data.get(1), data.get(2))
    else {
        return Err(DiagServiceError::UnexpectedResponse(Some(format!(
            "Negative response data is too short: expected 3 bytes, got {} bytes",
            data.len()
        ))));
    };
    if first_byte != NEGATIVE_RESPONSE {
        return Err(DiagServiceError::UnexpectedResponse(Some(
            format_args!(
                "First byte is not NEGATIVE_RESPONSE: expected 0x7F, got {first_byte:#04X}",
            )
            .to_string(),
        )));
    }
    if data.len() > 3 {
        return Err(DiagServiceError::UnexpectedResponse(Some(
            "Negative response data has extra bytes".to_string(),
        )));
    }
    Ok(MappedNRC {
        code: Some(nrc_byte),
        description: Some(iso_14229_nrc::get_nrc_code(nrc_byte).to_string()),
        sid: Some(sid_byte),
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_nrc_from_raw_data_valid() {
        let data = vec![0x7F, 0x22, 0x33];
        let result = extract_nrc_from_raw_data(&data).unwrap();
        assert_eq!(result.code, Some(0x33));
        assert_eq!(result.sid, Some(0x22));
        assert_eq!(
            result.description,
            Some("Security Access Denied".to_string())
        );
    }
    #[test]
    fn test_extract_nrc_from_raw_data_too_short() {
        // Test with data that's too short
        let data = vec![0x7F, 0x22];
        assert!(matches!(
            extract_nrc_from_raw_data(&data),
            Err(DiagServiceError::UnexpectedResponse(Some(msg))) if msg.contains("too short")));

        assert!(matches!(
            extract_nrc_from_raw_data(&[]),
            Err(DiagServiceError::UnexpectedResponse(Some(msg))) if msg.contains("too short")));
    }

    #[test]
    fn test_extract_nrc_from_raw_data_not_negative_response() {
        // Test with data that doesn't start with 0x7F
        let data = vec![0x62, 0x22, 0x33];
        assert!(matches!(
            extract_nrc_from_raw_data(&data),
            Err(DiagServiceError::UnexpectedResponse(Some(msg))) if msg.contains("not NEGATIVE_RESPONSE")));
    }
    #[test]
    fn test_extract_nrc_from_raw_data_with_extra_bytes() {
        // Test with extra bytes after the NRC (should NOT work now)
        let data = vec![0x7F, 0x22, 0x33, 0x44, 0x55];
        assert!(matches!(
            extract_nrc_from_raw_data(&data),
            Err(DiagServiceError::UnexpectedResponse(Some(msg))) if msg.contains("extra bytes")));
    }
}
