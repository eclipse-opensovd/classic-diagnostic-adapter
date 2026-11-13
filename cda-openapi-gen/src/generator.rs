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

use std::path::PathBuf;

use aide::openapi::{OpenApi, PathItem, ReferenceOr, Server};
use cda_core::{EcuManager, OfflineEndpointKind, OfflineServiceInfo, VariantInfo};
use cda_database::datatypes::DiagService;
use cda_interfaces::{EcuManager as _, HashMap};
use cda_plugin_security::DefaultSecurityPluginData;
use cda_sovd::docs;
use indexmap::IndexMap;
use opensovd_cda_lib::config::configfile::Configuration;

use crate::{
    AudienceFilter, GeneratorError,
    extension::{
        DocumentPostProcessor, Endpoint, EndpointContext, EndpointDecorator, FilterContext,
        GenContext, PathContributor, ServiceFilter,
    },
    skeleton::EcuRoutes,
    template,
};

/// The security plugin is not used offline, see `dsgn~openapi-gen-no-security-plugin`.
type OfflineEcuManager = EcuManager<DefaultSecurityPluginData>;

/// Which variants of the ECU documents are generated for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariantSelection {
    /// Only the base variant.
    Base,
    /// Every variant in the MDD, including the base variant.
    All,
    /// The variants with the given short names.
    Named(Vec<String>),
}

/// Input of a generation run.
#[derive(Debug, Clone)]
pub struct GenerationOptions {
    /// Path to the MDD file of the ECU.
    pub mdd_path: PathBuf,
    /// Variants to generate a document for.
    pub variants: VariantSelection,
    /// Audiences the services are filtered by. Not used if the default filter
    /// was replaced via [`GeneratorBuilder::with_service_filter`].
    pub audiences: AudienceFilter,
    /// Server URL added to the document, if any.
    pub server_url: Option<String>,
    /// CDA configuration, defines e.g. the database naming convention.
    pub config: Configuration,
    /// Detail of the fault environment data schema.
    pub fault_schemas: crate::FaultSchemaDetail,
}

/// A generated document for one variant.
#[derive(Debug, Clone)]
pub struct GeneratedDocument {
    pub ecu_name: String,
    pub variant: VariantInfo,
    pub document: OpenApi,
}

impl GeneratedDocument {
    /// Default file name: `<ecu>_<variant>.openapi.json`.
    #[must_use]
    pub fn file_name(&self) -> String {
        format!("{}_{}.openapi.json", self.ecu_name, self.variant.name)
    }
}

/// Builder for a [`Generator`], see the crate documentation.
#[derive(Default)]
pub struct GeneratorBuilder {
    replaced_filter: Option<Box<dyn ServiceFilter>>,
    filters: Vec<Box<dyn ServiceFilter>>,
    decorators: Vec<Box<dyn EndpointDecorator>>,
    path_contributors: Vec<Box<dyn PathContributor>>,
    post_processors: Vec<Box<dyn DocumentPostProcessor>>,
}

impl GeneratorBuilder {
    /// Replaces the default [`AudienceFilter`].
    #[must_use]
    pub fn with_service_filter(mut self, filter: impl ServiceFilter + 'static) -> Self {
        self.replaced_filter = Some(Box::new(filter));
        self
    }

    /// Adds a filter, which must include a service in addition to the default
    /// (or replaced) filter.
    #[must_use]
    pub fn add_service_filter(mut self, filter: impl ServiceFilter + 'static) -> Self {
        self.filters.push(Box::new(filter));
        self
    }

    /// Adds an [`EndpointDecorator`]. Decorators are called in registration order.
    #[must_use]
    pub fn add_endpoint_decorator(mut self, decorator: impl EndpointDecorator + 'static) -> Self {
        self.decorators.push(Box::new(decorator));
        self
    }

    /// Adds a [`PathContributor`].
    #[must_use]
    pub fn add_path_contributor(mut self, contributor: impl PathContributor + 'static) -> Self {
        self.path_contributors.push(Box::new(contributor));
        self
    }

    /// Adds a [`DocumentPostProcessor`].
    #[must_use]
    pub fn add_post_processor(mut self, processor: impl DocumentPostProcessor + 'static) -> Self {
        self.post_processors.push(Box::new(processor));
        self
    }

    #[must_use]
    pub fn build(self) -> Generator {
        Generator {
            replaced_filter: self.replaced_filter,
            filters: self.filters,
            decorators: self.decorators,
            path_contributors: self.path_contributors,
            post_processors: self.post_processors,
        }
    }
}

/// [[ dimpl~openapi-gen-document, Generates one document per variant ]]
///
/// The standalone `OpenAPI` generator.
pub struct Generator {
    replaced_filter: Option<Box<dyn ServiceFilter>>,
    filters: Vec<Box<dyn ServiceFilter>>,
    decorators: Vec<Box<dyn EndpointDecorator>>,
    path_contributors: Vec<Box<dyn PathContributor>>,
    post_processors: Vec<Box<dyn DocumentPostProcessor>>,
}

impl Default for Generator {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl Generator {
    #[must_use]
    pub fn builder() -> GeneratorBuilder {
        GeneratorBuilder::default()
    }

    /// Returns the variants contained in the MDD.
    ///
    /// # Errors
    /// Returns an error if the MDD cannot be loaded.
    pub fn list_variants(
        mdd_path: &std::path::Path,
        config: &Configuration,
    ) -> Result<(String, Vec<VariantInfo>), GeneratorError> {
        let (ecu_name, ecu) = load(mdd_path, config)?;
        Ok((ecu_name, ecu.variants()))
    }

    /// Generates one document per selected variant.
    ///
    /// # Errors
    /// Returns an error if the MDD cannot be loaded, a requested variant does
    /// not exist or an extension fails.
    pub async fn generate(
        &self,
        options: &GenerationOptions,
    ) -> Result<Vec<GeneratedDocument>, GeneratorError> {
        let (ecu_name, ecu) = load(&options.mdd_path, &options.config)?;
        let variants = resolve_variants(&ecu_name, ecu.variants(), &options.variants)?;

        // The generic routes do not depend on the variant. The route setup takes
        // ownership of an ECU manager, so a second instance is loaded for it.
        let (_, skeleton_ecu) = load(&options.mdd_path, &options.config)?;
        let skeleton =
            crate::skeleton::ecu_route_paths(&ecu_name, skeleton_ecu, &options.config).await?;

        let mut documents = Vec::with_capacity(variants.len());
        for variant in variants {
            ecu.select_variant_offline(&variant.name)
                .await
                .map_err(|e| GeneratorError::Variant(e.to_string()))?;
            let document = self
                .generate_variant(&ecu, &ecu_name, &variant, &skeleton, options)
                .await?;
            documents.push(GeneratedDocument {
                ecu_name: ecu_name.clone(),
                variant,
                document,
            });
        }
        Ok(documents)
    }

    async fn generate_variant(
        &self,
        ecu: &OfflineEcuManager,
        ecu_name: &str,
        variant: &VariantInfo,
        skeleton: &EcuRoutes,
        options: &GenerationOptions,
    ) -> Result<OpenApi, GeneratorError> {
        let filter_ctx = FilterContext { ecu_name, variant };
        let visible = |service: &OfflineServiceInfo| {
            let primary = match &self.replaced_filter {
                Some(filter) => filter.include(&filter_ctx, service),
                None => options.audiences.include(&filter_ctx, service),
            };
            primary && self.filters.iter().all(|f| f.include(&filter_ctx, service))
        };

        let base_path = format!("/vehicle/v15/components/{}", ecu_name.to_lowercase());
        let diag_layers = ecu.offline_diag_layers();
        let ctx = GenContext {
            ecu_name,
            variant,
            ecu_base_path: &base_path,
            diag_layers: &diag_layers,
        };
        let mut paths: IndexMap<String, PathItem> = skeleton
            .api
            .paths
            .iter()
            .flat_map(|p| p.paths.iter())
            .filter_map(|(path, item)| match item {
                ReferenceOr::Item(item) => Some((path.clone(), item.clone())),
                ReferenceOr::Reference { .. } => None,
            })
            .collect();

        paths.extend(
            self.resource_paths(ecu, &ctx, &visible, &skeleton.templates)
                .await?,
        );

        let mut api = docs::build_openapi_doc(&format!("{ecu_name} ({})", variant.name), paths);
        api.components.clone_from(&skeleton.api.components);
        if options.fault_schemas == crate::FaultSchemaDetail::Full {
            let schemas = crate::faults::environment_data_schemas(ecu).await;
            crate::faults::apply(&mut api, &base_path, &schemas)?;
        }
        api.info.version = ecu.revision();
        api.info.extensions.insert(
            "x-sovd-ecu".to_owned(),
            serde_json::Value::String(ecu_name.to_owned()),
        );
        api.info.extensions.insert(
            "x-sovd-ecu-variant".to_owned(),
            serde_json::Value::String(variant.name.clone()),
        );
        if let Some(url) = &options.server_url {
            api.servers = vec![Server {
                url: url.clone(),
                ..Default::default()
            }];
        }

        for contributor in &self.path_contributors {
            contributor.contribute(&ctx, &mut api)?;
        }
        for processor in &self.post_processors {
            processor.process(&ctx, &mut api)?;
        }
        crate::schemas::share_schemas(&mut api)?;
        Ok(api)
    }

    /// Concrete paths of all resources defined by the MDD (data, configurations,
    /// operations, single ECU jobs) that pass the service filters.
    async fn resource_paths(
        &self,
        ecu: &OfflineEcuManager,
        ctx: &GenContext<'_>,
        visible: &dyn Fn(&OfflineServiceInfo) -> bool,
        templates: &IndexMap<String, PathItem>,
    ) -> Result<IndexMap<String, PathItem>, GeneratorError> {
        let base_path = ctx.ecu_base_path;
        let mut paths = IndexMap::new();
        let mut data = ecu.offline_data_info(visible);
        data.sort_by(|a, b| a.id.cmp(&b.id));
        let data_services = ecu.offline_endpoint_services(OfflineEndpointKind::Data, visible);
        for info in &data {
            let meta = docs::data::data_docs_meta(ecu, &info.id).await;
            let mut resource =
                docs::data::build_path_items(&format!("{base_path}/data/{}", info.id), &meta);
            add_instantiated(
                &mut resource,
                base_path,
                templates,
                "/data/{service}",
                "service",
                &info.id,
                &[],
            );
            let endpoint = Endpoint::Data {
                id: &info.id,
                services: services_of(&data_services, &info.id),
            };
            self.decorate(ctx, endpoint, &mut resource)?;
            paths.extend(resource);
        }

        let configurations = ecu.offline_configurations_info(visible);
        let configuration_services =
            ecu.offline_endpoint_services(OfflineEndpointKind::Configuration, visible);
        for info in &configurations {
            let meta = docs::data::data_docs_meta(ecu, &info.id).await;
            let mut resource = docs::data::build_path_items(
                &format!("{base_path}/configurations/{}", info.id),
                &meta,
            );
            add_instantiated(
                &mut resource,
                base_path,
                templates,
                "/configurations/{service}",
                "service",
                &info.id,
                &[],
            );
            let endpoint = Endpoint::Configuration {
                id: &info.id,
                services: services_of(&configuration_services, &info.id),
            };
            self.decorate(ctx, endpoint, &mut resource)?;
            paths.extend(resource);
        }

        let mut operations = ecu.offline_operations_info(visible);
        operations.sort_by(|a, b| a.id.cmp(&b.id));
        let operation_services =
            ecu.offline_endpoint_services(OfflineEndpointKind::Operation, visible);
        for info in &operations {
            let meta = docs::operations::operation_docs_meta(ecu, info).await;
            let mut resource = docs::operations::build_path_items(
                &format!("{base_path}/operations/{}", info.id),
                &meta,
            );
            // The executions are described by the builder, including the request and
            // response schemas of the operation.
            add_instantiated(
                &mut resource,
                base_path,
                templates,
                "/operations/{service}",
                "service",
                &info.id,
                &["/operations/{service}/executions"],
            );
            let endpoint = Endpoint::Operation {
                id: &info.id,
                services: services_of(&operation_services, &info.id),
            };
            self.decorate(ctx, endpoint, &mut resource)?;
            paths.extend(resource);
        }

        for (id, job) in &ecu.offline_single_ecu_jobs(visible) {
            let mut resource = IndexMap::new();
            add_instantiated(
                &mut resource,
                base_path,
                templates,
                "/x-single-ecu-jobs/{job_name}",
                "job_name",
                id,
                &[],
            );
            self.decorate(ctx, Endpoint::SingleEcuJob { id, job }, &mut resource)?;
            paths.extend(resource);
        }

        Ok(paths)
    }

    fn decorate(
        &self,
        generation: &GenContext<'_>,
        endpoint: Endpoint<'_>,
        resource: &mut IndexMap<String, PathItem>,
    ) -> Result<(), GeneratorError> {
        let ctx = EndpointContext {
            generation: *generation,
            endpoint,
        };
        for decorator in &self.decorators {
            for (path, item) in resource.iter_mut() {
                decorator.decorate(&ctx, path, item)?;
            }
        }
        Ok(())
    }
}

/// Adds the instantiated `templates` below `prefix` to `resource`, without
/// replacing paths already created by a builder.
fn add_instantiated(
    resource: &mut IndexMap<String, PathItem>,
    base_path: &str,
    templates: &IndexMap<String, PathItem>,
    prefix: &str,
    placeholder: &str,
    id: &str,
    skip: &[&str],
) {
    for (path, item) in template::instantiate(templates, prefix, placeholder, id, skip) {
        resource.entry(format!("{base_path}{path}")).or_insert(item);
    }
}

fn services_of<'a, 'b>(
    services: &'a HashMap<String, Vec<DiagService<'b>>>,
    id: &str,
) -> &'a [DiagService<'b>] {
    services.get(id).map_or(&[], Vec::as_slice)
}

fn load(
    mdd_path: &std::path::Path,
    config: &Configuration,
) -> Result<(String, OfflineEcuManager), GeneratorError> {
    Ok(opensovd_cda_lib::mdd::load_ecu_manager_offline::<
        DefaultSecurityPluginData,
    >(mdd_path, config)?)
}

/// [[ dimpl~openapi-gen-variant-selection, Variant selection ]]
fn resolve_variants(
    ecu_name: &str,
    available: Vec<VariantInfo>,
    selection: &VariantSelection,
) -> Result<Vec<VariantInfo>, GeneratorError> {
    let names = || {
        available
            .iter()
            .map(|v| v.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    match selection {
        VariantSelection::All => Ok(available),
        VariantSelection::Base => {
            let base = available.iter().find(|v| v.is_base_variant).cloned();
            base.map(|v| vec![v]).ok_or_else(|| {
                GeneratorError::Variant(format!("ECU '{ecu_name}' has no base variant"))
            })
        }
        VariantSelection::Named(requested) => requested
            .iter()
            .map(|name| {
                available
                    .iter()
                    .find(|v| &v.name == name)
                    .cloned()
                    .ok_or_else(|| {
                        GeneratorError::Variant(format!(
                            "Variant '{name}' not found in ECU '{ecu_name}', available variants: \
                             [{}]",
                            names()
                        ))
                    })
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn variants() -> Vec<VariantInfo> {
        vec![
            VariantInfo {
                name: "Base".to_owned(),
                is_base_variant: true,
            },
            VariantInfo {
                name: "V1".to_owned(),
                is_base_variant: false,
            },
        ]
    }

    #[test]
    fn resolves_base_all_and_named() {
        let base = resolve_variants("E", variants(), &VariantSelection::Base).expect("base");
        assert_eq!(base.len(), 1);
        assert_eq!(base.first().map(|v| v.name.as_str()), Some("Base"));

        let all = resolve_variants("E", variants(), &VariantSelection::All).expect("all");
        assert_eq!(all.len(), 2);

        let named = resolve_variants(
            "E",
            variants(),
            &VariantSelection::Named(vec!["V1".to_owned()]),
        )
        .expect("named");
        assert_eq!(named.first().map(|v| v.name.as_str()), Some("V1"));
    }

    #[test]
    fn unknown_variant_lists_available() {
        let err = resolve_variants(
            "E",
            variants(),
            &VariantSelection::Named(vec!["Nope".to_owned()]),
        )
        .expect_err("must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("Nope") && msg.contains("Base") && msg.contains("V1"),
            "{msg}"
        );
    }
}
