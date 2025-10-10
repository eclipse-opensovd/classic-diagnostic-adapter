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

use serde::Serialize;
use strum::{Display, EnumString};

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct Mode<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub translation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<T>,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}

#[derive(Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum ModeType {
    Session,
    Security,
}

pub type Query = crate::IncludeSchemaQuery;

pub mod get {
    use super::*;
    use crate::Items;

    pub type Response = Items<Mode<()>>;
}

pub mod put {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, schemars::JsonSchema)]
    pub struct ModeKey {
        #[serde(rename = "Send_Key")]
        pub send_key: String,
    }

    #[derive(Debug, Deserialize, schemars::JsonSchema)]
    #[schemars(rename = "UpdateModesRequest")]
    pub struct Request {
        pub value: String,
        /// Defines after how many seconds the
        /// mode expires and should therefore
        /// be automatically reset to the mode’s
        // default value
        // It's optional although strictly speaking it should be required
        // when following the sovd standard.
        // todo (strict-mode): if strict mode is enabled, this should be required
        pub mode_expiration: Option<u64>,

        #[serde(rename = "Key")]
        pub key: Option<ModeKey>,
    }

    #[derive(Debug, Serialize, schemars::JsonSchema)]
    #[schemars(rename = "UpdateModesResponse")]
    pub struct Response<T> {
        pub id: String,
        pub value: T,
        #[schemars(skip)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub schema: Option<schemars::Schema>,
    }
}
