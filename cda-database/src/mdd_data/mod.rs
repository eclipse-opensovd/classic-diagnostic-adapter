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

use std::{io::Read, time::Instant};

use cda_interfaces::{
    datatypes::FlatbBufConfig,
    file_manager::{Chunk, ChunkMetaData, ChunkType, MddError},
};
use flatbuffers::VerifierOptions;
use hashbrown::HashMap;
use prost::Message;

use crate::{
    flatbuf::diagnostic_description::dataformat,
    proto::{fileformat, fileformat::chunk::DataType as ChunkDataType},
};

pub mod files;

// "MDD version 0      \u0000";
const FILE_MAGIC_HEX_STR: &str = "4d44442076657273696f6e203020202020202000";

fn file_magic_bytes() -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in (0..FILE_MAGIC_HEX_STR.len()).step_by(2) {
        let byte = u8::from_str_radix(&FILE_MAGIC_HEX_STR[i..i + 2], 16).unwrap();
        bytes.push(byte);
    }
    bytes
}

#[derive(Debug)]
pub struct ProtoLoadConfig {
    pub load_data: bool,
    pub type_: ChunkType,
    /// if set only the given name will be read
    pub name: Option<String>,
}

impl From<&ChunkType> for ChunkDataType {
    fn from(chunk_type: &ChunkType) -> Self {
        match chunk_type {
            ChunkType::DiagnosticDescription => ChunkDataType::DiagnosticDescription,
            ChunkType::JarFile => ChunkDataType::JarFile,
            ChunkType::JarFilePartial => ChunkDataType::JarFilePartial,
            ChunkType::EmbeddedFile => ChunkDataType::EmbeddedFile,
            ChunkType::VendorSpecific => ChunkDataType::VendorSpecific,
        }
    }
}

/// Read the chunk data from the MDD file if it has not been loaded yet.
/// # Errors
/// Returns an error if the chunk data cannot be loaded, such as if the MDD file is not found,
/// also returns the error from `load_chunk_data` if the chunk data cannot be read
/// or parsed correctly.
#[tracing::instrument(
    skip(chunk),
    fields(mdd_file, chunk_name = %chunk.meta_data.name)
)]
pub fn load_chunk<'a>(chunk: &'a mut Chunk, mdd_file: &str) -> Result<&'a Vec<u8>, MddError> {
    if chunk.payload.is_none() {
        tracing::debug!("Loading data from file");
        let chunk_data = load_chunk_data(mdd_file, chunk)?;
        chunk.payload = Some(chunk_data);
    }
    chunk
        .payload
        .as_ref()
        .ok_or_else(|| MddError::Io("Failed to load chunk data".to_owned()))
}

/// Load the ECU data from the given MDD file.
/// # Errors
/// See `load_proto_data` for details on possible errors.
pub fn load_ecudata(mdd_file: &str) -> Result<(String, Vec<u8>), MddError> {
    load_proto_data(
        mdd_file,
        &[ProtoLoadConfig {
            type_: ChunkType::DiagnosticDescription,
            load_data: true,
            name: None,
        }],
    )
    .and_then(|(name, data)| {
        data.into_iter()
            .next()
            .and_then(|(_, chunks)| {
                chunks.into_iter().next().map(|c| {
                    let payload = c.payload.ok_or_else(|| {
                        MddError::MissingData("No diagnostic payload found in MDD file".to_owned())
                    })?;
                    Ok((name, payload))
                })
            })
            .transpose()
    })?
    .ok_or_else(|| {
        MddError::MissingData(format!(
            "No diagnostic description found in MDD file: {mdd_file}",
        ))
    })
}

/// Load the data for a chunk from the mdd file.
/// # Errors
/// See `load_proto_data` for details on possible errors.
fn load_chunk_data(mdd_file: &str, chunk: &Chunk) -> Result<Vec<u8>, MddError> {
    load_proto_data(
        mdd_file,
        &[ProtoLoadConfig {
            load_data: true,
            type_: chunk.meta_data.type_.clone(),
            name: Some(chunk.meta_data.name.clone()),
        }],
    )
    .and_then(|(_, mut data)| {
        data.remove(&chunk.meta_data.type_)
            .and_then(|d| d.into_iter().next())
            .and_then(|p| p.payload)
            .ok_or_else(|| {
                MddError::MissingData(format!(
                    "Chunk data with name {} found in MDD file",
                    chunk.meta_data.name
                ))
            })
    })
}

/// Load proto buf data from a given mdd file, while filtering by the specified `data_type`.
/// # Errors
/// Will return an error if:
/// * Reading the file fails.
/// * The magic bytes do not match the expected format.
/// * Parsing the MDD file fails.
/// * Decompressing the data fails.
#[tracing::instrument(
    fields(
        mdd_file,
        config_count = load_info.len()
    )
)]
pub fn load_proto_data(
    mdd_file: &str,
    load_info: &[ProtoLoadConfig],
) -> Result<(String, HashMap<ChunkType, Vec<Chunk>>), MddError> {
    tracing::trace!("Loading ECU data from file");
    let start = Instant::now();
    let mut filein = std::fs::File::open(mdd_file)
        .map_err(|e| MddError::Io(format!("Failed to open mdd file: {e}")))?;
    let magic = file_magic_bytes();
    for b in magic {
        let mut buf = [0; 1];
        filein.read_exact(&mut buf).map_err(|e| {
            MddError::Parsing(format!("Failed to read magic byte from mdd file: {e}"))
        })?;
        if buf[0] != b {
            return Err(MddError::Parsing(
                "Invalid file format: Magic Byte mismatch".to_owned(),
            ));
        }
    }
    let mut filebuf = Vec::new();
    filein
        .read_to_end(&mut filebuf)
        .map_err(|e| MddError::Io(format!("Failed to read file: {e}")))?;
    let proto_file = fileformat::MddFile::decode(&mut std::io::Cursor::new(filebuf))
        .map_err(|e| MddError::Parsing(format!("Failed to parse MDD file: {e}")))?;

    let proto_data: HashMap<ChunkType, Vec<Chunk>> = load_info
        .iter()
        .map(|chunk_info| {
            let chunks: Vec<Chunk> = proto_file
                .chunks
                .iter()
                .filter_map(|proto_chunk| {
                    if ChunkDataType::try_from(proto_chunk.r#type) == Ok((&chunk_info.type_).into())
                        && chunk_info
                            .name
                            .as_ref()
                            .is_none_or(|name| Some(name) == proto_chunk.name.as_ref())
                    {
                        let data = if chunk_info.load_data {
                            let Some(proto_chunk_data) = &proto_chunk.data else {
                                return None;
                            };
                            let decompressor =
                                xz2::stream::Stream::new_lzma_decoder(u64::MAX).ok()?;
                            let mut decoder = xz2::bufread::XzDecoder::new_stream(
                                std::io::BufReader::new(proto_chunk_data.as_slice()),
                                decompressor,
                            );

                            let mut decoded = Vec::new();
                            decoder.read_to_end(&mut decoded).ok()?;

                            Some(decoded)
                        } else {
                            None
                        };

                        Some(Chunk {
                            payload: data,
                            meta_data: ChunkMetaData {
                                type_: chunk_info.type_.clone(),
                                name: proto_chunk
                                    .name
                                    .as_ref()
                                    .map_or(String::new(), std::clone::Clone::clone),
                                uncompressed_size: proto_chunk
                                    .uncompressed_size
                                    .unwrap_or_default(),
                                content_type: proto_chunk.mime_type.clone(),
                            },
                        })
                    } else {
                        None
                    }
                })
                .collect();
            (chunk_info.type_.clone(), chunks)
        })
        .collect();

    let end = Instant::now();

    tracing::trace!(
        ecu_name = %proto_file.ecu_name,
        duration = ?end.saturating_duration_since(start),
        chunks_loaded = proto_data.len(),
        "Loaded ECU data"
    );
    Ok((proto_file.ecu_name.clone(), proto_data))
}

pub(crate) fn read_ecudata<'a>(
    bytes: &'a [u8],
    flatbuf_config: &FlatbBufConfig,
) -> Result<dataformat::EcuData<'a>, String> {
    let start = Instant::now();
    let ecu_data = if flatbuf_config.verify {
        dataformat::root_as_ecu_data_with_opts(
            &VerifierOptions {
                max_depth: flatbuf_config.max_depth,
                max_tables: flatbuf_config.max_tables,
                max_apparent_size: flatbuf_config.max_apparent_size,
                ignore_missing_null_terminator: flatbuf_config.ignore_missing_null_terminator,
            },
            bytes,
        )
        .map_err(|e| format!("Failed to parse ECU data: {e}"))
    } else {
        Ok(unsafe {
            // unsafe but around 10x faster.
            // can be used when previously verified and trusted data is loaded.
            dataformat::root_as_ecu_data_unchecked(bytes)
        })
    };

    let end = Instant::now();
    tracing::trace!(
        duration = ?end.saturating_duration_since(start),
        ecu_name = %ecu_data.as_ref()
            .ok().and_then(dataformat::EcuData::ecu_name).unwrap_or("unknown"),
        "Parsed flatbuff data"
    );
    ecu_data
}
