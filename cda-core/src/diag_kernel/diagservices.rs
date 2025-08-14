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

use std::time::Instant;

use cda_database::datatypes::{CompuMethod, DataType};
use cda_interfaces::{
    DiagComm, DiagServiceError,
    diagservices::{DiagServiceResponse, DiagServiceResponseType, MappedNRC},
};
use hashbrown::HashMap;

use crate::diag_kernel::{DiagDataValue, operations};

#[derive(Debug)]
pub struct DiagServiceResponseStruct {
    pub service: DiagComm,
    pub data: Vec<u8>,
    pub mapped_data: Option<MappedDiagServiceResponsePayload>,
    pub response_type: DiagServiceResponseType,
}

#[derive(Debug)]
pub enum DiagDataTypeContainer {
    RawContainer(DiagDataTypeContainerRaw),
    Struct(HashMap<String, DiagDataTypeContainer>),
    RepeatingStruct(Vec<HashMap<String, DiagDataTypeContainer>>),
}

#[derive(Debug)]
pub struct DiagDataTypeContainerRaw {
    pub data: Vec<u8>,
    pub bit_len: usize,
    pub data_type: DataType,
    pub compu_method: Option<CompuMethod>,
}

pub type MappedDiagServiceResponsePayload = HashMap<String, DiagDataTypeContainer>;

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

    fn into_json(self) -> Result<serde_json::Value, cda_interfaces::DiagServiceError> {
        self.serialize_to_json()
    }

    fn as_nrc(&self) -> Result<MappedNRC, String> {
        let Some(mapped_data) = &self.mapped_data else {
            return Err("Unexpected negative response from ECU".to_owned());
        };
        let nrc_code = mapped_data
            .get("NRC")
            .and_then(|container| match container {
                DiagDataTypeContainer::RawContainer(nrc) => {
                    let raw = u8::from_be(nrc.data[0]);
                    let message = match operations::uds_data_to_serializable(
                        nrc.data_type,
                        nrc.compu_method.as_ref(),
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
                DiagDataTypeContainer::RawContainer(sid) => Some(u8::from_be(sid.data[0])),
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
}

impl DiagServiceResponseStruct {
    /// This function tries to serialize the `DiagServiceResponse` into a SOVD style JSON.
    ///
    /// # Errors
    /// Returns `Err` in case any currently unsupported Nesting of containers or if serde
    /// internally has an error when calling serialize on the elements.
    pub fn serialize_to_json(self) -> Result<serde_json::Value, DiagServiceError> {
        let data = self.get_mapped_payload()?;
        if data.is_empty() {
            return Ok(serde_json::Value::Null);
        }
        let start = Instant::now();
        let mapped_data = data
            .iter()
            .map(|(k, v)| -> Result<(_, _), DiagServiceError> {
                Ok((k.clone(), Self::map_data(v)?))
            })
            .collect::<Result<HashMap<_, _>, DiagServiceError>>()
            .and_then(|mapped| {
                serde_json::to_value(&mapped)
                    .map_err(|e| DiagServiceError::ParameterConversionError(e.to_string()))
            });
        let end = Instant::now();
        log::debug!(target: "serialize_to_json", "Mapped data to JSON in {:?}", end - start);
        mapped_data
    }

    fn get_mapped_payload(self) -> Result<MappedDiagServiceResponsePayload, DiagServiceError> {
        match self.mapped_data {
            Some(mapped_data) => Ok(mapped_data),
            None => Err(DiagServiceError::BadPayload(
                "Raw payload cannot be serialized to JSON".to_owned(),
            )),
        }
    }
    fn map_data(data: &DiagDataTypeContainer) -> Result<DiagDataValue, DiagServiceError> {
        fn create_struct(
            hash_map: &HashMap<String, DiagDataTypeContainer>,
            inner_mapped: &mut HashMap<String, DiagDataValue>,
        ) -> Result<(), DiagServiceError> {
            for (k, v) in hash_map {
                let val = match v {
                    DiagDataTypeContainer::RawContainer(raw) => {
                        operations::uds_data_to_serializable(
                            raw.data_type,
                            raw.compu_method.as_ref(),
                            &raw.data,
                        )?
                    }
                    DiagDataTypeContainer::Struct(s) => {
                        let mut nested_mapped = HashMap::new();
                        create_struct(s, &mut nested_mapped)?;
                        DiagDataValue::Struct(nested_mapped)
                    }
                    DiagDataTypeContainer::RepeatingStruct(vec) => {
                        let mut nested_vec = Vec::new();
                        for inner_hash_map in vec {
                            let mut inner_mapped = HashMap::new();
                            create_struct(inner_hash_map, &mut inner_mapped)?;
                            nested_vec.push(inner_mapped);
                        }
                        DiagDataValue::RepeatingStruct(nested_vec)
                    }
                };
                inner_mapped.insert(k.clone(), val);
            }
            Ok(())
        }

        match data {
            DiagDataTypeContainer::RawContainer(raw) => Ok(operations::uds_data_to_serializable(
                raw.data_type,
                raw.compu_method.as_ref(),
                &raw.data,
            )?),
            DiagDataTypeContainer::Struct(hash_map) => {
                let mut mapped = HashMap::new();
                create_struct(hash_map, &mut mapped)?;
                Ok(DiagDataValue::Struct(mapped))
            }
            DiagDataTypeContainer::RepeatingStruct(vec) => {
                let mut mapped = Vec::new();
                for hash_map in vec {
                    let mut inner_mapped = HashMap::new();
                    create_struct(hash_map, &mut inner_mapped)?;
                    mapped.push(inner_mapped);
                }
                Ok(DiagDataValue::RepeatingStruct(mapped))
            }
        }
    }
}
