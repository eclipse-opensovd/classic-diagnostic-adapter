/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
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

//! `functions/functionalgroups/{fg}`: a functional group.

use http::Method;
use sovd_interfaces::{Items, common::operations::OperationCollectionItem};

use self::operations::{FunctionalGroupExecution, FunctionalGroupSyncExecution};
use crate::client::{
    Request, Response, Result, SovdTestClient, child,
    components::{modes::ModeHandle, operations::Operation},
    locks::{LockHandle, Locks},
};

pub(crate) mod operations;

/// A functional group.
#[derive(Clone)]
pub(crate) struct FunctionalGroup<'a> {
    client: &'a SovdTestClient,
    path: String,
}

impl<'a> FunctionalGroup<'a> {
    pub(crate) fn new(client: &'a SovdTestClient, path: String) -> Self {
        Self { client, path }
    }

    /// Lists the operations.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn operations(&self) -> Result<Response<Items<OperationCollectionItem>>> {
        self.request(Method::GET, "operations").send_json().await
    }

    /// The operation `id`.
    pub(crate) fn operation(
        &self,
        id: &str,
    ) -> Operation<'a, FunctionalGroupSyncExecution, FunctionalGroupExecution> {
        Operation::new(self.client, child(&self.path, &format!("operations/{id}")))
    }

    /// The mode `id`, e.g. [`sovd_interfaces::common::modes::SESSION_ID`].
    pub(crate) fn mode(&self, id: &str) -> ModeHandle<'a> {
        ModeHandle::new(self.client, child(&self.path, &format!("modes/{id}")))
    }

    /// The locks of the functional group.
    pub(crate) fn locks(&self) -> Locks<'a> {
        Locks::new(self.client, child(&self.path, "locks"))
    }

    /// The lock `id` of the functional group.
    pub(crate) fn lock(&self, id: &str) -> LockHandle<'a> {
        self.locks().lock(id)
    }

    /// A request with `method` to the sub-resource `path` of the functional
    /// group, for requests without a typed method.
    pub(crate) fn request(&self, method: Method, path: &str) -> Request<'a> {
        self.client.request(method, child(&self.path, path))
    }
}
