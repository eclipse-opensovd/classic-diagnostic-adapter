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
    mdd_file: &str,
    load_info: &[ProtoLoadConfig],
) -> Result<(String, HashMap<ChunkType, Vec<Chunk>>), MddError> {
    tracing::trace!("Loading ECU data from file");
    let start = Instant::now();
    let filein = std::fs::File::open(mdd_file)
        .map_err(|e| MddError::Io(format!("Failed to open mdd file: {e}")))?;

    // SAFETY: The file is opened read-only and we only hold a shared reference to the mapping.
    // The caller must ensure the file is not modified or truncated while mapped.
    let mmap = unsafe { memmap2::Mmap::map(&filein) }
        .map_err(|e| MddError::Io(format!("Failed to memory-map mdd file: {e}")))?;

    // Hint: file will be read sequentially for protobuf decode, enables aggressive read-ahead.
    if let Err(e) = mmap.advise(memmap2::Advice::Sequential) {
        tracing::debug!(error = %e, "Failed to set mmap advice");
    }

    // Capture pointer and length before consuming the mmap.
    let mmap_ptr = mmap.as_ptr();
    let mmap_len = mmap.len();

    let magic = file_magic_bytes();
    let magic_slice = mmap
        .get(..FILE_MAGIC_BYTES_LEN)
        .ok_or_else(|| MddError::Parsing("Invalid file format: file too small".to_owned()))?;
    if *magic_slice != magic {
        return Err(MddError::Parsing(
            "Invalid file format: Magic Byte mismatch".to_owned(),
        ));
    }

    // Wrap the mmap as `Bytes` so that prost decoding produces zero-copy
    // sub-slices for `bytes` fields instead of heap-allocated `Vec<u8>`.
    // The resulting `Bytes` sub-slices keep the mmap alive via refcount.
    let mmap_bytes = Bytes::from_owner(mmap);
    let payload = mmap_bytes.slice(FILE_MAGIC_BYTES_LEN..);
    let proto_file = fileformat::MddFile::decode(payload)
        .map_err(|e| MddError::Parsing(format!("Failed to parse MDD file: {e}")))?;

    // After protobuf decode: future access will be sparse/random (FlatBuffers vtable lookups).
    // Change madvise hint to MADV_RANDOM to disable wasteful read-ahead.
    #[cfg(unix)]
    unsafe {
        let _ = libc::madvise(mmap_ptr as *mut libc::c_void, mmap_len, libc::MADV_RANDOM);
    }

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

                            if proto_chunk.compression_algorithm.is_some() {
                                // Compressed chunk: LZMA decompress.
                                let decompressor =
                                    xz2::stream::Stream::new_lzma_decoder(u64::MAX).ok()?;
                                let mut decoder = xz2::bufread::XzDecoder::new_stream(
                                    std::io::BufReader::new(proto_chunk_data.as_ref()),
                                    decompressor,
                                );

                                let mut decoded = Vec::new();
                                decoder.read_to_end(&mut decoded).ok()?;
                                Some(Bytes::from(decoded))
                            } else {
                                // Already uncompressed: cheap refcount clone
                                // (zero-copy sub-slice of the mmap).
                                Some(proto_chunk_data.clone())
                            }
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

/// Rewrite the MDD file with the `DiagnosticDescription` chunk data stored
/// **uncompressed** (`compression_algorithm = None`).
///
/// If the DD chunk is already uncompressed this is a no-op and returns
/// `Ok(false)`.  Otherwise the chunk is LZMA-decompressed, written back into
/// the protobuf, and the file is replaced atomically (write-to-tmp + rename).
///
/// Returns `Ok(true)` when the file was rewritten.
///
/// # Errors
/// Returns an error if the file cannot be read, parsed, decompressed, or
/// written back.
pub fn update_mdd_uncompressed(mdd_path: &str) -> Result<bool, MddError> {
    let data = std::fs::read(mdd_path)
        .map_err(|e| MddError::Io(format!("Failed to read MDD file '{mdd_path}': {e}")))?;

    let magic = file_magic_bytes();
    let magic_slice = data
        .get(..FILE_MAGIC_BYTES_LEN)
        .ok_or_else(|| MddError::Parsing("Invalid file format: file too small".to_owned()))?;
    if *magic_slice != magic {
        return Err(MddError::Parsing(
            "Invalid file format: Magic Byte mismatch".to_owned(),
        ));
    }
    let payload = data
        .get(FILE_MAGIC_BYTES_LEN..)
        .ok_or_else(|| MddError::Parsing("Invalid file format: no data after magic".to_owned()))?;
    let mut proto_file = fileformat::MddFile::decode(payload)
        .map_err(|e| MddError::Parsing(format!("Failed to parse MDD file: {e}")))?;

    let mut modified = false;
    for chunk in &mut proto_file.chunks {
        if chunk.compression_algorithm.is_none() {
            continue;
        }
        let Some(compressed_data) = chunk.data.take() else {
            continue;
        };

        let decompressor = xz2::stream::Stream::new_lzma_decoder(u64::MAX)
            .map_err(|e| MddError::Io(format!("Failed to create LZMA decoder: {e}")))?;
        let mut decoder = xz2::bufread::XzDecoder::new_stream(
            std::io::BufReader::new(compressed_data.as_ref()),
            decompressor,
        );
        let mut decoded = Vec::new();
        decoder
            .read_to_end(&mut decoded)
            .map_err(|e| MddError::Io(format!("Failed to decompress chunk data: {e}")))?;

        chunk.data = Some(Bytes::from(decoded));
        chunk.compression_algorithm = None;
        chunk.uncompressed_size = None;
        modified = true;
    }

    if modified {
        // Compute expected SHA-256 digests of the decompressed chunk data
        // *before* encoding so we can verify the written file.
        let expected_hashes: Vec<Option<[u8; 32]>> = proto_file
            .chunks
            .iter()
            .map(|c| c.data.as_ref().map(|d| sha2::Sha256::digest(d).into()))
            .collect();

        let mut out =
            Vec::with_capacity(FILE_MAGIC_BYTES_LEN.saturating_add(proto_file.encoded_len()));
        out.extend_from_slice(&magic);
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

        // Verify the written file: re-parse and check SHA-256 of each chunk.
        verify_written_mdd(&tmp_path, &expected_hashes)?;

        std::fs::rename(&tmp_path, mdd_path).map_err(|e| {
            // Clean up the temp file on rename failure.
            let _ = std::fs::remove_file(&tmp_path);
            MddError::Io(format!(
                "Failed to rename temporary MDD file to '{mdd_path}': {e}"
            ))
        })?;

        tracing::info!(
            mdd_file = %mdd_path,
            "Rewrote MDD file with uncompressed chunk data"
        );
    }

    Ok(modified)
}

/// Read back a written MDD temp file, re-parse the protobuf and compare the
/// SHA-256 digest of every chunk's `data` field against the `expected_hashes`.
///
/// On mismatch the temp file is deleted and an error is returned.
fn verify_written_mdd(
    tmp_path: &str,
    expected_hashes: &[Option<[u8; 32]>],
) -> Result<(), MddError> {
    let written = std::fs::read(tmp_path).map_err(|e| {
        MddError::Io(format!(
            "Failed to re-read temporary MDD file '{tmp_path}' for verification: {e}"
        ))
    })?;

    let payload = written.get(FILE_MAGIC_BYTES_LEN..).ok_or_else(|| {
        let _ = std::fs::remove_file(tmp_path);
        MddError::Parsing("Verification failed: temp file too small".to_owned())
    })?;

    let parsed = fileformat::MddFile::decode(payload).map_err(|e| {
        let _ = std::fs::remove_file(tmp_path);
        MddError::Parsing(format!(
            "Verification failed: could not re-parse temp MDD file: {e}"
        ))
    })?;

    if parsed.chunks.len() != expected_hashes.len() {
        let _ = std::fs::remove_file(tmp_path);
        return Err(MddError::Parsing(format!(
            "Verification failed: chunk count mismatch (expected {}, got {})",
            expected_hashes.len(),
            parsed.chunks.len()
        )));
    }

    for (i, (chunk, expected)) in parsed.chunks.iter().zip(expected_hashes).enumerate() {
        let actual: Option<[u8; 32]> = chunk.data.as_ref().map(|d| sha2::Sha256::digest(d).into());
        if actual != *expected {
            let _ = std::fs::remove_file(tmp_path);
            return Err(MddError::Parsing(format!(
                "Verification failed: SHA-256 mismatch for chunk {i} in '{tmp_path}'"
            )));
        }
    }

    Ok(())
}
