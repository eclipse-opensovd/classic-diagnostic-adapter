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

//! [[ dimpl~openapi-gen-cli, Command line interface ]]

use std::{path::PathBuf, process::ExitCode};

use clap::Parser;
use opensovd_cda_lib::config::{configfile::Configuration, default_config, load_config};

use crate::{
    AudienceFilter, FaultSchemaDetail, GeneratedDocument, GenerationOptions, Generator,
    GeneratorError, StandardAudience, VariantSelection,
};

/// Generates the SOVD `OpenAPI` document(s) of a single ECU from its MDD file.
///
/// One document is written per selected variant, named `<ecu>_<variant>.openapi.json`.
#[derive(Debug, Clone, Parser)]
#[command(name = "cda-openapi-gen", version, about, long_about = None)]
pub struct CliArgs {
    /// MDD file of the ECU.
    #[arg(long, short = 'm', value_name = "FILE")]
    pub mdd: PathBuf,

    /// CDA configuration file. Defines e.g. the database naming convention, so the
    /// document matches what the CDA serves. Defaults are used if not given.
    #[arg(long, short = 'c', value_name = "FILE", env = "CDA_CONFIG_FILE")]
    pub config: Option<PathBuf>,

    /// Variant to generate a document for, can be repeated. Defaults to the base variant.
    #[arg(long = "variant", value_name = "NAME", conflicts_with = "all_variants")]
    pub variants: Vec<String>,

    /// Generate a document for every variant in the MDD.
    #[arg(long)]
    pub all_variants: bool,

    /// Standard ODX audience to include, can be repeated. Without any audience
    /// (standard or additional) all services are included.
    #[arg(long = "audience", value_enum, value_name = "AUDIENCE")]
    pub audiences: Vec<StandardAudience>,

    /// Additional ODX audience (short name) to include, can be repeated.
    #[arg(long = "additional-audience", value_name = "NAME")]
    pub additional_audiences: Vec<String>,

    /// Directory the documents are written to.
    #[arg(long, short = 'd', value_name = "DIR", default_value = ".")]
    pub output_dir: PathBuf,

    /// Output file, only allowed if exactly one document is generated.
    #[arg(long, short = 'o', value_name = "FILE", conflicts_with = "output_dir")]
    pub output: Option<PathBuf>,

    /// Server URL written into the documents, e.g. `http://localhost:20002`.
    #[arg(long, value_name = "URL")]
    pub server_url: Option<String>,

    /// Detail of the fault environment data (snapshots, extended data records) in
    /// `GET /faults/{id}`. `generic` omits the data types of the MDD, e.g. if the
    /// documents get too large.
    #[arg(long, value_enum, value_name = "DETAIL", default_value_t)]
    pub fault_schemas: FaultSchemaDetail,

    /// Write indented JSON instead of compact JSON.
    #[arg(long)]
    pub pretty: bool,

    /// Only print the variants contained in the MDD and exit.
    #[arg(long)]
    pub list_variants: bool,
}

impl CliArgs {
    /// Converts the arguments into [`GenerationOptions`].
    ///
    /// # Errors
    /// Returns an error if the configuration file cannot be loaded.
    pub fn to_options(&self) -> Result<GenerationOptions, GeneratorError> {
        Ok(GenerationOptions {
            mdd_path: self.mdd.clone(),
            variants: match (self.all_variants, self.variants.is_empty()) {
                (true, _) => VariantSelection::All,
                (false, true) => VariantSelection::Base,
                (false, false) => VariantSelection::Named(self.variants.clone()),
            },
            audiences: AudienceFilter::new(
                self.audiences.clone(),
                self.additional_audiences.clone(),
            ),
            server_url: self.server_url.clone(),
            config: self.load_config()?,
            fault_schemas: self.fault_schemas,
        })
    }

    fn load_config(&self) -> Result<Configuration, GeneratorError> {
        self.config.as_ref().map_or_else(
            || Ok(default_config()),
            |path| load_config(path).map_err(GeneratorError::Config),
        )
    }
}

impl Generator {
    /// Parses the command line and runs the generator.
    #[must_use]
    pub fn run_from_cli(&self) -> ExitCode {
        let args = CliArgs::parse();
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("Failed to create runtime: {e}");
                return ExitCode::FAILURE;
            }
        };
        match runtime.block_on(self.run(&args)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        }
    }

    /// Runs the generator with already parsed arguments and writes the documents.
    ///
    /// # Errors
    /// Returns an error if loading, generating or writing fails.
    pub async fn run(&self, args: &CliArgs) -> Result<(), GeneratorError> {
        let options = args.to_options()?;
        if args.list_variants {
            let (ecu_name, variants) = Self::list_variants(&options.mdd_path, &options.config)?;
            println!("{ecu_name}");
            for v in variants {
                let base = if v.is_base_variant { " (base)" } else { "" };
                println!("  {}{base}", v.name);
            }
            return Ok(());
        }

        let documents = self.generate(&options).await?;
        match (&args.output, documents.as_slice()) {
            (Some(file), [doc]) => write_document(doc, file, args.pretty),
            (Some(_), docs) => Err(GeneratorError::Output(format!(
                "--output requires exactly one document, but {} were generated; use --output-dir",
                docs.len()
            ))),
            (None, docs) => {
                std::fs::create_dir_all(&args.output_dir).map_err(|e| {
                    GeneratorError::Output(format!(
                        "Cannot create {}: {e}",
                        args.output_dir.display()
                    ))
                })?;
                docs.iter().try_for_each(|doc| {
                    write_document(doc, &args.output_dir.join(doc.file_name()), args.pretty)
                })
            }
        }
    }
}

fn write_document(
    doc: &GeneratedDocument,
    path: &std::path::Path,
    pretty: bool,
) -> Result<(), GeneratorError> {
    let json = if pretty {
        serde_json::to_string_pretty(&doc.document)
    } else {
        serde_json::to_string(&doc.document)
    }
    .map_err(|e| GeneratorError::Output(format!("Cannot serialize document: {e}")))?;
    std::fs::write(path, json)
        .map_err(|e| GeneratorError::Output(format!("Cannot write {}: {e}", path.display())))?;
    eprintln!("Written {}", path.display());
    Ok(())
}
