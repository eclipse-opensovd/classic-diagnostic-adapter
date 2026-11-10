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

use aide::openapi::{OpenApi, PathItem, Server};
use cda_core::{EcuManager, OfflineServiceInfo, VariantInfo};
use cda_interfaces::EcuManager as _;
use cda_plugin_security::DefaultSecurityPluginData;
use cda_sovd::docs;
use indexmap::IndexMap;
use opensovd_cda_lib::config::configfile::Configuration;

use crate::{
    AudienceFilter, GeneratorError,
    extension::{DocumentPostProcessor, FilterContext, GenContext, PathContributor, ServiceFilter},
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

        let mut documents = Vec::with_capacity(variants.len());
        for variant in variants {
            ecu.select_variant_offline(&variant.name)
                .await
                .map_err(|e| GeneratorError::Variant(e.to_string()))?;
            let document = self
                .generate_variant(&ecu, &ecu_name, &variant, options)
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
        let mut paths: IndexMap<String, PathItem> = IndexMap::new();

        let mut data = ecu.offline_data_info(&visible);
        data.sort_by(|a, b| a.id.cmp(&b.id));
        for info in &data {
            let meta = docs::data::data_docs_meta(ecu, &info.id).await;
            paths.extend(docs::data::build_path_items(
                &format!("{base_path}/data/{}", info.id),
                &meta,
            ));
        }

        let configurations = ecu.offline_configurations_info(&visible);
        for info in &configurations {
            let meta = docs::data::data_docs_meta(ecu, &info.id).await;
            paths.extend(docs::data::build_path_items(
                &format!("{base_path}/configurations/{}", info.id),
                &meta,
            ));
        }

        let mut operations = ecu.offline_operations_info(&visible);
        operations.sort_by(|a, b| a.id.cmp(&b.id));
        for info in &operations {
            let meta = docs::operations::operation_docs_meta(ecu, info).await;
            paths.extend(docs::operations::build_path_items(
                &format!("{base_path}/operations/{}", info.id),
                &meta,
            ));
        }

        let mut api = docs::build_openapi_doc(&format!("{ecu_name} ({})", variant.name), paths);
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

        let ctx = GenContext {
            ecu_name,
            variant,
            ecu_base_path: &base_path,
        };
        for contributor in &self.path_contributors {
            contributor.contribute(&ctx, &mut api)?;
        }
        for processor in &self.post_processors {
            processor.process(&ctx, &mut api)?;
        }
        Ok(api)
    }
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
