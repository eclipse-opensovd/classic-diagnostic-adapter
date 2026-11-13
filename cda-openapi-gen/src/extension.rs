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

//! [[ dimpl~openapi-gen-extension-points, OEM extension points ]]

use aide::openapi::{OpenApi, PathItem};
use cda_core::{OfflineServiceInfo, VariantInfo};
use cda_database::datatypes::{DiagLayer, DiagService, SingleEcuJob};

use crate::GeneratorError;

/// Context passed to [`ServiceFilter`]s.
#[derive(Debug, Clone, Copy)]
pub struct FilterContext<'a> {
    /// Name of the ECU as contained in the MDD.
    pub ecu_name: &'a str,
    /// The variant the document is generated for.
    pub variant: &'a VariantInfo,
}

/// Context passed to [`PathContributor`]s and [`DocumentPostProcessor`]s.
#[derive(Debug, Clone, Copy)]
pub struct GenContext<'a> {
    /// Name of the ECU as contained in the MDD.
    pub ecu_name: &'a str,
    /// The variant the document is generated for.
    pub variant: &'a VariantInfo,
    /// Path all ECU resources are located under, e.g. `/vehicle/v15/components/myecu`.
    pub ecu_base_path: &'a str,
    /// Diag layers of the variant followed by the ones of its parent refs, i.e.
    /// read access to the complete ECU description of the variant.
    pub diag_layers: &'a [DiagLayer<'a>],
}

/// A resource of the ECU generated from the MDD, together with the MDD
/// objects it was generated from.
///
/// The MDD objects give read access to the complete ECU description, e.g. the
/// request and response parameters, their DOPs, SDGs and the audience.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Endpoint<'a> {
    /// `{ecu_base_path}/data/{id}` and its sub paths. Contains the read (0x22) and,
    /// if present, write (0x2E) services.
    Data {
        id: &'a str,
        services: &'a [DiagService<'a>],
    },
    /// `{ecu_base_path}/configurations/{id}` and its sub paths. Contains the read
    /// (0x22) and write (0x2E) services.
    Configuration {
        id: &'a str,
        services: &'a [DiagService<'a>],
    },
    /// `{ecu_base_path}/operations/{id}` and its sub paths. Contains all
    /// `RoutineControl` (0x31) services with the same routine name.
    Operation {
        id: &'a str,
        services: &'a [DiagService<'a>],
    },
    /// `{ecu_base_path}/x-single-ecu-jobs/{id}`.
    SingleEcuJob {
        id: &'a str,
        job: &'a SingleEcuJob<'a>,
    },
}

impl Endpoint<'_> {
    /// Id of the resource, i.e. the path segment below its collection.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Data { id, .. }
            | Self::Configuration { id, .. }
            | Self::Operation { id, .. }
            | Self::SingleEcuJob { id, .. } => id,
        }
    }
}

/// Context passed to [`EndpointDecorator`]s.
#[derive(Debug, Clone, Copy)]
pub struct EndpointContext<'a> {
    /// Context of the document being generated.
    pub generation: GenContext<'a>,
    /// The resource the path belongs to.
    pub endpoint: Endpoint<'a>,
}

/// Modifies the paths generated from the MDD, with access to the diagnostic
/// services they were generated from, e.g. to add descriptions or vendor
/// extensions to the data endpoints.
///
/// Called for every path of a resource generated from the MDD (a resource can
/// have more than one, e.g. `/data/{id}` and `/data/{id}/docs`), before the
/// [`PathContributor`]s. Generic paths (modes, faults, locks, flash, ...) are not
/// passed; use a [`DocumentPostProcessor`] and [`GenContext::diag_layers`] for them.
pub trait EndpointDecorator: Send + Sync {
    /// # Errors
    /// Implementations return [`GeneratorError::Extension`] to abort the generation.
    fn decorate(
        &self,
        ctx: &EndpointContext<'_>,
        path: &str,
        item: &mut PathItem,
    ) -> Result<(), GeneratorError>;
}

/// Decides whether a diagnostic service is part of the generated document.
///
/// All registered filters must include a service for it to be generated.
pub trait ServiceFilter: Send + Sync {
    fn include(&self, ctx: &FilterContext<'_>, service: &OfflineServiceInfo) -> bool;
}

impl<F> ServiceFilter for F
where
    F: Fn(&FilterContext<'_>, &OfflineServiceInfo) -> bool + Send + Sync,
{
    fn include(&self, ctx: &FilterContext<'_>, service: &OfflineServiceInfo) -> bool {
        self(ctx, service)
    }
}

/// Adds additional paths (or components) to the generated document, e.g. OEM
/// specific routes registered on the CDA runtime.
///
/// Called after the paths generated from the MDD were added.
pub trait PathContributor: Send + Sync {
    /// # Errors
    /// Implementations return [`GeneratorError::Extension`] to abort the generation.
    fn contribute(&self, ctx: &GenContext<'_>, api: &mut OpenApi) -> Result<(), GeneratorError>;
}

/// Transforms the final document, e.g. to set servers, security schemes or
/// vendor extensions.
///
/// Called in registration order after all [`PathContributor`]s. The schemas of
/// the generated paths are still inline at this point; they are moved into
/// `components/schemas` after the last post processor.
pub trait DocumentPostProcessor: Send + Sync {
    /// # Errors
    /// Implementations return [`GeneratorError::Extension`] to abort the generation.
    fn process(&self, ctx: &GenContext<'_>, api: &mut OpenApi) -> Result<(), GeneratorError>;
}
