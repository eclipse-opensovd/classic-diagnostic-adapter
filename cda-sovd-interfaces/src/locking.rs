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

use serde::{Deserialize, Serialize};

use crate::Items;

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Lock {
    pub id: String,

    /// If true, the SOVD client which performed the request owns the
    /// lock. The value is always false if the entity is not locked
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owned: Option<bool>,
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(rename = "CreateLockRequest")]
pub struct Request {
    pub lock_expiration: u64,
}

impl From<Request> for chrono::DateTime<chrono::Utc> {
    fn from(value: Request) -> Self {
        chrono::Utc::now()
            .checked_add_signed(chrono::TimeDelta::seconds(
                value.lock_expiration.try_into().unwrap_or(i64::MAX),
            ))
            .unwrap_or(chrono::Utc::now())
    }
}

pub mod get {
    use super::{Items, Lock};

    pub type Response = Items<Lock>;
}

pub mod id {
    use super::{Deserialize, Serialize};
    pub mod get {
        use super::{Deserialize, Serialize};
        #[derive(Serialize, Deserialize, schemars::JsonSchema)]
        #[schemars(rename = "LockResponse")]
        pub struct Response {
            pub lock_expiration: String,
        }
    }
}

pub mod post_put {
    use super::Lock;
    pub type Response = Lock;
}
