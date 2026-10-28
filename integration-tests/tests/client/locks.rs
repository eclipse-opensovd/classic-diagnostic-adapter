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

//! `locks`: the locks of the vehicle. Components and functional groups have
//! locks of the same shape (`components/{ecu}/locks`,
//! `functions/functionalgroups/{fg}/locks`).

use std::time::Duration;

use http::Method;
use serde::Serialize;
use serde_json::Map;
use sovd_interfaces::locking;

use crate::client::{Request, Response, Result, SovdTestClient, child};

/// A collection of locks: of the vehicle, a component or a functional group.
#[derive(Clone)]
pub(crate) struct Locks<'a> {
    client: &'a SovdTestClient,
    path: String,
}

impl<'a> Locks<'a> {
    pub(crate) fn new(client: &'a SovdTestClient, path: String) -> Self {
        Self { client, path }
    }

    /// The path of the collection, relative to `/vehicle/v15/`.
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    /// Lists the locks.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn list(&self) -> Result<Response<locking::get::Response>> {
        self.client
            .request(Method::GET, self.path.clone())
            .send_json()
            .await
    }

    /// Creates a lock that expires after `expiration`.
    ///
    /// # Errors
    /// See [`Self::create_with`].
    pub(crate) async fn create(&self, expiration: Duration) -> Result<Response<Lock>> {
        self.create_with(&locking::Request {
            lock_expiration: expiration.as_secs(),
            break_lock: false,
            x_sovd2uds_isexclusive: None,
            metadata: Map::new(),
        })
        .await
    }

    /// Creates a lock with the request body `request`, e.g. a
    /// [`locking::Request`], or JSON to test invalid requests. The CDA answers
    /// `201 Created` with the `Location` of a new lock, and `200 OK` if it
    /// extended a lock the client holds already.
    ///
    /// # Errors
    /// Returns [`Error::Api`](super::Error::Api) if the CDA refuses the lock.
    pub(crate) async fn create_with(&self, request: &impl Serialize) -> Result<Response<Lock>> {
        let response = self
            .client
            .request(Method::POST, self.path.clone())
            .json(request)
            .send_json::<locking::post_put::Response>()
            .await?;
        let client = self.client.clone();
        let path = &self.path;
        Ok(response.map(|info| Lock {
            client,
            path: child(path, &info.id),
            info,
        }))
    }

    /// The lock `id` of this collection, also one this client does not own.
    pub(crate) fn lock(&self, id: &str) -> LockHandle<'a> {
        LockHandle {
            client: self.client,
            path: child(&self.path, id),
        }
    }
}

/// A lock, reached by its id, e.g. one of another client.
#[derive(Clone)]
pub(crate) struct LockHandle<'a> {
    client: &'a SovdTestClient,
    path: String,
}

impl LockHandle<'_> {
    /// The path of the lock, as the `Location` of its creation:
    /// `/vehicle/v15/{path}`.
    pub(crate) fn absolute_path(&self) -> String {
        format!("/vehicle/v15/{}", self.path)
    }

    /// Reads the lock.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn get(&self) -> Result<Response<locking::id::get::Response>> {
        self.client
            .request(Method::GET, self.path.clone())
            .send_json()
            .await
    }

    /// Sets the expiration of the lock to `expiration` from now.
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn update(&self, expiration: Duration) -> Result<Response<()>> {
        self.update_with(&locking::UpdateRequest {
            lock_expiration: expiration.as_secs(),
        })
        .await
    }

    /// Updates the lock with the request body `request`, e.g. JSON to test
    /// invalid requests.
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn update_with(&self, request: &impl Serialize) -> Result<Response<()>> {
        self.client
            .request(Method::PUT, self.path.clone())
            .json(request)
            .send_empty()
            .await
    }

    /// Deletes the lock.
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn delete(&self) -> Result<Response<()>> {
        self.request(Method::DELETE).send_empty().await
    }

    /// A request with `method` to the lock, for requests without a typed
    /// method.
    pub(crate) fn request(&self, method: Method) -> Request<'_> {
        self.client.request(method, self.path.clone())
    }
}

/// A lock created by [`Locks::create`], owned by the client that created it.
///
/// Not released when dropped: a lock does not outlive the test, as every
/// lease of a test environment starts a new CDA. [`Lock::release`] releases it
/// and returns the response, for tests that go on without it.
#[derive(Debug)]
pub(crate) struct Lock {
    client: SovdTestClient,
    path: String,
    info: locking::Lock,
}

impl Lock {
    /// The id of the lock.
    pub(crate) fn id(&self) -> &str {
        &self.info.id
    }

    /// The lock as the CDA created it.
    pub(crate) fn info(&self) -> &locking::Lock {
        &self.info
    }

    /// The lock, reached with the client that created it.
    pub(crate) fn handle(&self) -> LockHandle<'_> {
        LockHandle {
            client: &self.client,
            path: self.path.clone(),
        }
    }

    /// Releases the lock.
    ///
    /// # Errors
    /// See [`LockHandle::delete`].
    pub(crate) async fn release(self) -> Result<Response<()>> {
        self.handle().delete().await
    }
}
