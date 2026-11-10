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

use aide::openapi::OpenApi;
use cda_core::{OfflineServiceInfo, VariantInfo};

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
/// Called in registration order after all [`PathContributor`]s.
pub trait DocumentPostProcessor: Send + Sync {
    /// # Errors
    /// Implementations return [`GeneratorError::Extension`] to abort the generation.
    fn process(&self, ctx: &GenContext<'_>, api: &mut OpenApi) -> Result<(), GeneratorError>;
}
