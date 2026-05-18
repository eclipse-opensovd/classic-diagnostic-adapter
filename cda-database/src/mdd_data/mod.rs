/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::{io::Read, time::Instant};

use bytes::Bytes;
use cda_interfaces::{
    HashMap,
    datatypes::FlatbBufConfig,
    dlt_ctx,
    file_manager::{Chunk, ChunkMetaData, ChunkType, MddError},
};
use flatbuffers::VerifierOptions;
use prost::Message;
use sha2::Digest;

use crate::{
    flatbuf::diagnostic_description::dataformat,
    proto::{fileformat, fileformat::chunk::DataType as ChunkDataType},
};

pub mod files;

// "MDD version 0      \u0000";
const FILE_MAGIC_HEX_STR: &str = "4d44442076657273696f6e203020202020202000";
const FILE_MAGIC_BYTES_LEN: usize = FILE_MAGIC_HEX_STR.len() / 2;

// Allowed because constant functions cannot functions like .get() are not allowed in const fn.
// However, as we would call panic! on a failure anyway it does not make a difference here.
#[allow(clippy::indexing_slicing)]
#[allow(clippy::arithmetic_side_effects)]
const fn file_magic_bytes() -> [u8; FILE_MAGIC_BYTES_LEN] {
    let string_bytes = FILE_MAGIC_HEX_STR.as_bytes();
    let mut bytes = [0u8; FILE_MAGIC_BYTES_LEN];
    let mut count = 0;
    while count < bytes.len() {
        let i = count * 2;
        let str_b = [string_bytes[i], string_bytes[i + 1]];
        let Ok(hex_str) = str::from_utf8(&str_b) else {
            panic!("Non UTF-8 bytes in FILE_MAGIC_HEX_STR")
        };
        let Ok(b) = u8::from_str_radix(hex_str, 16) else {
            panic!("Invalid hex value in FILE_MAGIC_HEX_STR")
        };
        bytes[count] = b;
        count += 1;
    }
    bytes
}

/// Decompress chunk data based on the compression algorithm.
///
/// # Errors
/// Returns an error if the compression algorithm is unsupported or if
/// LZMA decompression fails.
fn decompress_chunk_data(
    data: Bytes,
    compression_algorithm: Option<&str>,
    chunk_name: &str,
) -> Result<Bytes, MddError> {
    match compression_algorithm.map(str::to_lowercase).as_deref() {
        Some("lzma") => {
            let decompressor = xz2::stream::Stream::new_lzma_decoder(u64::MAX)
                .map_err(|e| MddError::Io(format!("Failed to create LZMA decoder: {e}")))?;
            let mut decoder = xz2::bufread::XzDecoder::new_stream(
                std::io::BufReader::new(data.as_ref()),
                decompressor,
            );
            let mut decoded = Vec::new();
            decoder
                .read_to_end(&mut decoded)
                .map_err(|e| MddError::Io(format!("Failed to decompress chunk data: {e}")))?;
            Ok(Bytes::from(decoded))
        }
        None => Ok(data),
        Some(algorithm) => Err(MddError::Parsing(format!(
            "Unsupported compression algorithm '{algorithm}' for chunk '{chunk_name}'"
        ))),
    }
}

/// Memory-map an MDD file, validate its magic bytes, and decode the protobuf.
///
/// Returns the decoded `MddFile` backed by zero-copy `Bytes` sub-slices of
/// the memory-mapped region.
///
/// # Errors
/// Returns an error if the file cannot be opened, memory-mapped, has invalid
/// magic bytes, or cannot be parsed as a protobuf.
fn mmap_and_decode_mdd(mdd_path: &str) -> Result<fileformat::MddFile, MddError> {
    let mdd_file = std::fs::File::open(mdd_path)
        .map_err(|e| MddError::Io(format!("Failed to open MDD file '{mdd_path}': {e}")))?;

    // SAFETY: The file is opened read-only, and we only hold a shared reference to the mapping.
    // The caller must ensure the file is not modified or truncated while mapped.
    let mmap = unsafe { memmap2::Mmap::map(&mdd_file) }
        .map_err(|e| MddError::Io(format!("Failed to mmap MDD file '{mdd_path}': {e}")))?;

    #[cfg(unix)]
    // Hint to the kernel, that the access pattern is random, so no read-ahead is needed.
    if let Err(e) = mmap.advise(memmap2::Advice::Random) {
        tracing::warn!(error = %e, "Failed to set mmap advice, memory usage might be higher");
    }

    let magic_slice = mmap
        .get(..FILE_MAGIC_BYTES_LEN)
        .ok_or_else(|| MddError::Parsing("Invalid file format: file too small".to_owned()))?;
    if *magic_slice != file_magic_bytes() {
        return Err(MddError::Parsing(
            "Invalid file format: Magic Byte mismatch".to_owned(),
        ));
    }

    // Wrap the mmap as `Bytes` so that prost decoding produces zero-copy
    // sub-slices for `bytes` fields instead of heap-allocated `Vec<u8>`.
    // The resulting `Bytes` sub-slices keep the mmap alive via refcount.
    let mmap_bytes = Bytes::from_owner(mmap);
    let payload = mmap_bytes.slice(FILE_MAGIC_BYTES_LEN..);
    fileformat::MddFile::decode(payload)
        .map_err(|e| MddError::Parsing(format!("Failed to parse MDD file: {e}")))
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
            ChunkType::CodeFile => ChunkDataType::CodeFile,
            ChunkType::CodeFilePartial => ChunkDataType::CodeFilePartial,
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
    fields(
        mdd_file,
        chunk_name = %chunk.meta_data.name,
        dlt_context = dlt_ctx!("DB"),
    )
)]
pub fn load_chunk<'a>(chunk: &'a mut Chunk, mdd_file: &str) -> Result<&'a Bytes, MddError> {
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
pub fn load_ecudata(mdd_file: &str) -> Result<(String, Bytes), MddError> {
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
fn load_chunk_data(mdd_file: &str, chunk: &Chunk) -> Result<Bytes, MddError> {
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
    mdd_file_path: &str,
    load_info: &[ProtoLoadConfig],
) -> Result<(String, HashMap<ChunkType, Vec<Chunk>>), MddError> {
    tracing::trace!("Loading ECU data from file");
    let start = Instant::now();
    let mdd_file = mmap_and_decode_mdd(mdd_file_path)?;

    let proto_data: HashMap<ChunkType, Vec<Chunk>> = load_info
        .iter()
        .map(|chunk_info| {
            let chunks: Vec<Chunk> = mdd_file
                .chunks
                .iter()
                .filter(|proto_chunk| {
                    ChunkDataType::try_from(proto_chunk.r#type) == Ok((&chunk_info.type_).into())
                        && chunk_info
                            .name
                            .as_ref()
                            .is_none_or(|name| Some(name) == proto_chunk.name.as_ref())
                })
                .map(|proto_chunk| {
                    let data = if chunk_info.load_data {
                        let Some(proto_chunk_data) = &proto_chunk.data else {
                            return Ok(None);
                        };

                        Some(decompress_chunk_data(
                            proto_chunk_data.clone(),
                            proto_chunk.compression_algorithm.as_deref(),
                            proto_chunk.name.as_deref().unwrap_or("unknown"),
                        )?)
                    } else {
                        None
                    };

                    Ok(Some(Chunk {
                        payload: data,
                        meta_data: ChunkMetaData {
                            type_: chunk_info.type_.clone(),
                            name: proto_chunk
                                .name
                                .as_ref()
                                .map_or(String::new(), std::clone::Clone::clone),
                            uncompressed_size: proto_chunk.uncompressed_size.unwrap_or_default(),
                            content_type: proto_chunk.mime_type.clone(),
                        },
                    }))
                })
                .filter_map(Result::transpose)
                .collect::<Result<Vec<_>, MddError>>()?;
            Ok((chunk_info.type_.clone(), chunks))
        })
        .collect::<Result<HashMap<_, _>, MddError>>()?;

    let end = Instant::now();

    tracing::trace!(
        ecu_name = %mdd_file.ecu_name,
        duration = ?end.saturating_duration_since(start),
        chunks_loaded = proto_data.len(),
        "Loaded ECU data"
    );
    Ok((mdd_file.ecu_name.clone(), proto_data))
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

/// Rewrite the MDD file with  uncompressed data, if it is not already uncompressed.
/// If the chunks are already uncompressed this is a no-op and returns
/// `Ok(false)`. Otherwise, the chunk is decompressed, written back into
/// the protobuf, and the file is replaced atomically (write-to-tmp + rename).
///
/// Returns `Ok(true)` when the file was rewritten.
///
/// # Errors
/// Returns an error if the file cannot be read, parsed, decompressed, or
/// written back.
pub fn update_mdd_uncompressed(mdd_path: &str) -> Result<bool, MddError> {
    // Use mmap + zero-copy decode to check whether any chunks are
    // compressed.  This avoids heap-allocating the file contents on the
    // common path (already decompressed) the mmap is dropped and the kernel
    // reclaims the pages with zero RSS residue.
    let needs_decompression = {
        let proto_file = mmap_and_decode_mdd(mdd_path)?;
        proto_file
            .chunks
            .iter()
            .any(|c| c.compression_algorithm.is_some())
    };

    if !needs_decompression {
        return Ok(false);
    }

    // At least one chunk is compressed - read into heap, decompress,
    // and rewrite. This path only runs once per MDD file.
    let data = std::fs::read(mdd_path)
        .map_err(|e| MddError::Io(format!("Failed to read MDD file '{mdd_path}': {e}")))?;

    let payload = data
        .get(FILE_MAGIC_BYTES_LEN..)
        .ok_or_else(|| MddError::Parsing("Invalid file format: no data after magic".to_owned()))?;
    let mut proto_file = fileformat::MddFile::decode(payload)
        .map_err(|e| MddError::Parsing(format!("Failed to parse MDD file: {e}")))?;

    for chunk in &mut proto_file.chunks {
        let Some(chunk_data) = chunk.data.take() else {
            continue;
        };

        let chunk_name = chunk.name.as_deref().unwrap_or("unknown");
        let decompressed = decompress_chunk_data(
            chunk_data,
            chunk.compression_algorithm.as_deref(),
            chunk_name,
        )?;
        chunk.data = Some(decompressed);
        chunk.compression_algorithm = None;
        chunk.uncompressed_size = None;
    }

    // Compute expected SHA-512 digests of the decompressed chunk data
    // *before* encoding so we can verify the written file.
    let expected_hashes: Vec<Option<[u8; 64]>> = proto_file
        .chunks
        .iter()
        .map(|c| c.data.as_ref().map(|d| sha2::Sha512::digest(d).into()))
        .collect();

    let mut out = Vec::with_capacity(FILE_MAGIC_BYTES_LEN.saturating_add(proto_file.encoded_len()));
    out.extend_from_slice(&file_magic_bytes());
    proto_file
        .encode(&mut out)
        .map_err(|e| MddError::Io(format!("Failed to encode updated MDD: {e}")))?;

    // Atomic write: temp file + rename.
    let tmp_path = format!("{mdd_path}.tmp");
    std::fs::write(&tmp_path, &out).map_err(|e| {
        MddError::Io(format!(
            "Failed to write temporary MDD file '{tmp_path}': {e}"
        ))
    })?;

    verify_mdd_chunk_checksums(&tmp_path, &expected_hashes).inspect_err(|_| {
        if let Err(e) = std::fs::remove_file(&tmp_path) {
            tracing::error!(
                error = %e,
                filename = %tmp_path,
                "Failed to remove temporary MDD file after checksum verification failure"
            );
        }
    })?;

    std::fs::rename(&tmp_path, mdd_path).map_err(|e| {
        // Clean up the temp file on rename failure.
        if let Err(e) = std::fs::remove_file(&tmp_path) {
            tracing::error!(
                error = %e,
                filename = %tmp_path,
                "Failed to remove temporary MDD file after rename failure"
            );
        }
        MddError::Io(format!(
            "Failed to rename temporary MDD file to '{mdd_path}': {e}"
        ))
    })?;

    tracing::info!(
        mdd_file = %mdd_path,
        "Rewrote MDD file with uncompressed chunk data"
    );

    Ok(true)
}

/// Read back a written MDD temp file, re-parse the protobuf and compare the
/// SHA-512 digest of every chunk's `data` field against the `expected_hashes`.
///
/// # Errors
/// On checksum mismatch an error is returned. The caller is responsible for cleaning up
/// the temp file.
fn verify_mdd_chunk_checksums(
    mdd_file_path: &str,
    expected_hashes: &[Option<[u8; 64]>],
) -> Result<(), MddError> {
    let mdd_file = mmap_and_decode_mdd(mdd_file_path)?;
    if mdd_file.chunks.len() != expected_hashes.len() {
        return Err(MddError::Parsing(format!(
            "Verification failed: chunk count mismatch (expected {}, got {})",
            expected_hashes.len(),
            mdd_file.chunks.len()
        )));
    }

    for (i, (chunk, expected)) in mdd_file.chunks.iter().zip(expected_hashes).enumerate() {
        let actual: Option<[u8; 64]> = chunk.data.as_ref().map(|d| sha2::Sha512::digest(d).into());
        if actual != *expected {
            return Err(MddError::Parsing(format!(
                "Verification failed: SHA-512 mismatch for chunk {i} in '{mdd_file_path}'"
            )));
        }
    }

    Ok(())
}
