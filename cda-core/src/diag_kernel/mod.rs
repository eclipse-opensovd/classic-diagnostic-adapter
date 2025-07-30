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

use cda_interfaces::{Protocol, STRINGS};
use hashbrown::HashMap;
use serde::{Serialize, Serializer};

pub(crate) mod diagservices;
pub(crate) mod ecumanager;
mod iso_14229_nrc;
mod operations;
mod payload;
mod variant_detection;

#[derive(Debug)]
pub enum DiagDataValue {
    Int32(i32),
    UInt32(u32),
    Float32(f32),
    String(String),
    ByteField(Vec<u8>),
    Float64(f64),
    Struct(HashMap<String, DiagDataValue>),
    RepeatingStruct(Vec<HashMap<String, DiagDataValue>>),
}

#[derive(Clone)]
pub struct Variant {
    pub name: String,
    pub(crate) id: u32,
}

#[must_use]
pub fn into_db_protocol(val: Protocol) -> cda_database::datatypes::Protocol {
    cda_database::datatypes::Protocol {
        short_name: STRINGS.get_or_insert(val.value()),
    }
}

impl Serialize for DiagDataValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            DiagDataValue::Int32(v) => v.serialize(serializer),
            DiagDataValue::UInt32(v) => v.serialize(serializer),
            DiagDataValue::Float32(v) => v.serialize(serializer),
            DiagDataValue::String(v) => v.serialize(serializer),
            DiagDataValue::ByteField(v) => {
                let byte_string = v
                    .iter()
                    .map(|&b| format!("{b:#04X}"))
                    .collect::<Vec<String>>()
                    .join(" ");
                byte_string.serialize(serializer)
            }
            DiagDataValue::Float64(v) => v.serialize(serializer),
            DiagDataValue::Struct(v) => v.serialize(serializer),
            DiagDataValue::RepeatingStruct(v) => v.serialize(serializer),
        }
    }
}
