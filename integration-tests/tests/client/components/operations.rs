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

//! `components/{ecu}/operations`: the operations of a component and their
//! executions. Functional groups have operations of the same shape
//! (`functions/functionalgroups/{fg}/operations`), with other result types.

use std::marker::PhantomData;

use cda_sovd::VendorErrorCode;
use http::{Method, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use sovd_interfaces::{
    Items,
    common::operations::{OperationCollectionItem, OperationDeleteQuery, OperationIdItem},
    components::ecu::{
        ServicesSdgs,
        operations::{AsyncGetByIdResponse, AsyncPostResponse, service::executions},
    },
};

use crate::client::{Error, Request, Response, Result, SovdTestClient, child};

/// An execution of an operation of a component, as the CDA reports it.
pub(crate) type Execution = AsyncGetByIdResponse<VendorErrorCode>;

/// The result of a synchronous execution of an operation of a component.
pub(crate) type SyncExecution = executions::Response<VendorErrorCode>;

/// An asynchronous execution as the CDA reports it right after starting it.
/// The parameters of components and functional groups differ in shape, so
/// they are left as JSON.
pub(crate) type StartedExecution = AsyncPostResponse<serde_json::Value, VendorErrorCode>;

/// An operation of an entity. `S` is the response of a synchronous execution,
/// `E` the state of an execution, which differ between components and
/// functional groups.
pub(crate) struct Operation<'a, S = SyncExecution, E = Execution> {
    client: &'a SovdTestClient,
    path: String,
    types: PhantomData<(S, E)>,
}

impl<S, E> Clone for Operation<'_, S, E> {
    fn clone(&self) -> Self {
        Self {
            client: self.client,
            path: self.path.clone(),
            types: PhantomData,
        }
    }
}

impl<'a, S: DeserializeOwned, E: DeserializeOwned> Operation<'a, S, E> {
    pub(crate) fn new(client: &'a SovdTestClient, path: String) -> Self {
        Self {
            client,
            path,
            types: PhantomData,
        }
    }

    /// Reads the description of the operation, as the only item of a
    /// collection.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn get(&self) -> Result<Response<Items<OperationCollectionItem>>> {
        self.client
            .request(Method::GET, self.path.clone())
            .send_json()
            .await
    }

    /// Reads the special data groups of the operation
    /// (`x-sovd2uds-includesdgs`).
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn sdgs(&self) -> Result<Response<ServicesSdgs>> {
        self.client
            .request(Method::GET, self.path.clone())
            .query("x-sovd2uds-includesdgs", "true")
            .send_json()
            .await
    }

    /// Starts an execution with `request`, e.g. a
    /// `sovd_interfaces::components::ecu::operations::service::executions::Request`.
    ///
    /// # Errors
    /// See [`Request::send`], or [`Error::InvalidResponse`] if the CDA answers
    /// other than `200 OK`, `202 Accepted` or `204 No Content`.
    pub(crate) async fn start(
        &self,
        request: &impl Serialize,
    ) -> Result<Response<ExecutionStart<S>>> {
        let response = self
            .executions_request(Method::POST)
            .json(request)
            .send()
            .await?;
        match response.status() {
            StatusCode::OK => Ok(response.json::<S>()?.map(ExecutionStart::Completed)),
            StatusCode::ACCEPTED => Ok(response
                .json::<StartedExecution>()?
                .map(ExecutionStart::Started)),
            StatusCode::NO_CONTENT => Ok(response.map(|_| ExecutionStart::NoContent)),
            status => Err(Error::InvalidResponse {
                url: response.url().to_owned(),
                message: format!("unexpected status {status} for a started execution"),
                body: response.text().map(ToOwned::to_owned),
            }),
        }
    }

    /// Lists the executions.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn executions(&self) -> Result<Response<Items<OperationIdItem>>> {
        self.executions_request(Method::GET).send_json().await
    }

    /// The execution `id`.
    pub(crate) fn execution(&self, id: &str) -> ExecutionHandle<'a, E> {
        ExecutionHandle {
            client: self.client,
            path: child(&self.path, &format!("executions/{id}")),
            types: PhantomData,
        }
    }

    /// A request with `method` to the executions, for requests without a
    /// typed method, e.g. with invalid bodies.
    pub(crate) fn executions_request(&self, method: Method) -> Request<'a> {
        self.client.request(method, child(&self.path, "executions"))
    }
}

/// How an execution started by [`Operation::start`] ran.
#[derive(Debug)]
pub(crate) enum ExecutionStart<S> {
    /// It ran synchronously (`200 OK`), with this result.
    Completed(S),
    /// It runs asynchronously (`202 Accepted`).
    Started(StartedExecution),
    /// It ran synchronously without a result (`204 No Content`).
    NoContent,
}

impl<S: std::fmt::Debug> ExecutionStart<S> {
    /// The result of a synchronous execution.
    ///
    /// # Panics
    /// If the execution runs asynchronously.
    pub(crate) fn completed(self) -> S {
        match self {
            Self::Completed(result) => result,
            Self::Started(execution) => {
                panic!("expected a synchronous execution, got {execution:?}")
            }
            Self::NoContent => panic!("expected a synchronous execution with a result"),
        }
    }

    /// The asynchronously running execution.
    ///
    /// # Panics
    /// If the execution ran synchronously.
    pub(crate) fn started(self) -> StartedExecution {
        match self {
            Self::Started(execution) => execution,
            Self::Completed(result) => {
                panic!("expected an asynchronous execution, got {result:?}")
            }
            Self::NoContent => panic!("expected an asynchronous execution, got 204 No Content"),
        }
    }
}

/// An execution of an operation.
pub(crate) struct ExecutionHandle<'a, E = Execution> {
    client: &'a SovdTestClient,
    path: String,
    types: PhantomData<E>,
}

impl<'a, E: DeserializeOwned> ExecutionHandle<'a, E> {
    /// Reads the state of the execution.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn get(&self) -> Result<Response<E>> {
        self.request(Method::GET).send_json().await
    }

    /// Stops and removes the execution. Returns its final state if the CDA
    /// reports one.
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn delete(&self) -> Result<Response<Option<E>>> {
        self.request(Method::DELETE).send_json_opt().await
    }

    /// Like [`Self::delete`], with the query parameters `query`, e.g. to
    /// remove the execution even if the ECU fails to stop it
    /// (`x-sovd2uds-force`).
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn delete_with(
        &self,
        query: &OperationDeleteQuery,
    ) -> Result<Response<Option<E>>> {
        self.request(Method::DELETE)
            .query_params(query)
            .send_json_opt()
            .await
    }

    /// A request with `method` to the execution, for requests without a typed
    /// method, e.g. with query parameters.
    pub(crate) fn request(&self, method: Method) -> Request<'a> {
        self.client.request(method, self.path.clone())
    }
}
