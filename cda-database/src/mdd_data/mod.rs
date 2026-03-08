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

use std::{
    fmt::Write,
    io::Read,
    path::{Path, PathBuf},
    time::Instant,
};

use cda_interfaces::{
    HashMap,
    datatypes::FlatbBufConfig,
    dlt_ctx,
    file_manager::{Chunk, ChunkMetaData, ChunkType, MddError},
};
use flatbuffers::VerifierOptions;
use prost::Message;
use sha2::{Digest, Sha512};

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
    let filein = std::fs::File::open(mdd_file)
        .map_err(|e| MddError::Io(format!("Failed to open mdd file: {e}")))?;

    // SAFETY: The file is opened read-only and we only hold a shared reference to the mapping.
    // The caller must ensure the file is not modified or truncated while mapped.
    let mmap = unsafe { memmap2::Mmap::map(&filein) }
        .map_err(|e| MddError::Io(format!("Failed to memory-map mdd file: {e}")))?;

    // Hint to the OS: MDD file access is sequential (read once front-to-back for
    // protobuf decoding), so enable aggressive read-ahead.
    #[cfg(unix)]
    if let Err(e) = mmap.advise(memmap2::Advice::Sequential) {
        tracing::warn!(error = %e, "Failed to set MADV_SEQUENTIAL on MDD mmap");
    }

    let magic = file_magic_bytes();
    let magic_slice = mmap
        .get(..FILE_MAGIC_BYTES_LEN)
        .ok_or_else(|| MddError::Parsing("Invalid file format: file too small".to_owned()))?;
    if *magic_slice != magic {
        return Err(MddError::Parsing(
            "Invalid file format: Magic Byte mismatch".to_owned(),
        ));
    }
    let payload = mmap
        .get(FILE_MAGIC_BYTES_LEN..)
        .ok_or_else(|| MddError::Parsing("Invalid file format: no data after magic".to_owned()))?;
    let proto_file = fileformat::MddFile::decode(payload)
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

/// Read the per-chunk signatures for the `DiagnosticDescription` chunk from
/// an MDD file **without** decompressing any chunk data.
///
/// Returns `(ecu_name, signatures)` where `signatures` is the list of
/// [`fileformat::Signature`] entries attached to the first DD chunk.
///
/// # Errors
/// Returns an error if the MDD file cannot be opened, read, or
/// decoded as a valid protobuf `MDDFile`.
pub fn read_mdd_signatures(
    mdd_path: &str,
) -> Result<(String, Vec<fileformat::Signature>), MddError> {
    let data = std::fs::read(mdd_path)
        .map_err(|e| MddError::Io(format!("Failed to read mdd file: {e}")))?;

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
    let proto_file = fileformat::MddFile::decode(payload)
        .map_err(|e| MddError::Parsing(format!("Failed to parse MDD file: {e}")))?;

    let signatures = proto_file
        .chunks
        .iter()
        .find(|c| ChunkDataType::try_from(c.r#type) == Ok(ChunkDataType::DiagnosticDescription))
        .map(|c| c.signatures.clone())
        .unwrap_or_default();

    Ok((proto_file.ecu_name.clone(), signatures))
}

/// Validate an existing sidecar file against the MDD chunk signatures.
///
/// Computes a SHA-512 digest of the sidecar file content and compares it
/// against the first signature whose algorithm is `sha512_uncompressed`.
///
/// Returns `Ok(true)` when the sidecar matches, `Ok(false)` when it does not
/// (or no usable signature is available), and `Err` on I/O failures.
///
/// # Errors
/// Returns an error if the sidecar file cannot be read.
pub fn validate_sidecar(
    sidecar: &Path,
    signatures: &[fileformat::Signature],
) -> Result<bool, MddError> {
    if signatures.is_empty() {
        tracing::warn!(
            sidecar = %sidecar.display(),
            "No signatures on DD chunk; cannot validate sidecar"
        );
        return Ok(false);
    }

    let expected = signatures
        .iter()
        .find(|s| s.algorithm.eq_ignore_ascii_case("sha512_uncompressed"));
    let Some(expected) = expected else {
        let algos: Vec<&str> = signatures.iter().map(|s| s.algorithm.as_str()).collect();
        tracing::warn!(
            sidecar = %sidecar.display(),
            algorithms = ?algos,
            "No sha512_uncompressed signature found on DD chunk; cannot validate sidecar"
        );
        return Ok(false);
    };

    let content = std::fs::read(sidecar).map_err(|e| {
        MddError::Io(format!(
            "Failed to read sidecar file '{}' for validation: {e}",
            sidecar.display()
        ))
    })?;

    let computed = Sha512::digest(&content);

    if computed[..] == expected.signature[..] {
        tracing::debug!(
            sidecar = %sidecar.display(),
            "Sidecar SHA-512 matches MDD signature"
        );
        Ok(true)
    } else {
        tracing::info!(
            sidecar = %sidecar.display(),
            expected = expected.signature.iter()
                .fold(String::new(), |mut s, b| { let _ = write!(s, "{b:02x}"); s }),
            computed = computed.iter()
                .fold(String::new(), |mut s, b| {let _ = write!(s, "{b:02x}"); s }),
            "Sidecar SHA-512 mismatch; sidecar will be re-created"
        );
        Ok(false)
    }
}

/// Compute the sidecar `FlatBuffers` file path for a given MDD file.
///
/// The sidecar file has the same stem as the `.mdd` file with a `.fb` extension.
/// When `sidecar_dir` is `Some`, the file is placed in that directory;
/// otherwise it is placed next to the `.mdd` file.
#[must_use]
pub fn sidecar_path(mdd_path: &str, sidecar_dir: Option<&str>) -> PathBuf {
    let mdd = Path::new(mdd_path);
    let stem = mdd.file_stem().unwrap_or_default();
    let dir = match sidecar_dir {
        Some(dir) => PathBuf::from(dir),
        None => mdd.parent().unwrap_or(Path::new(".")).to_path_buf(),
    };
    dir.join(format!("{}.fb", stem.to_string_lossy()))
}

/// Ensure a sidecar `FlatBuffers` file exists **and is valid** for the given
/// MDD file.
///
/// When the sidecar already exists the `DiagnosticDescription` chunk's SHA-256
/// signature (from the MDD proto) is compared against a hash of the sidecar
/// contents. If the signature is missing or does not match, the sidecar is
/// re-created from decompressed MDD data.
///
/// Returns `(ecu_name, sidecar_path)`.
///
/// # Errors
/// Returns an error if the MDD file cannot be read, decompressed, or the
/// sidecar file cannot be written.
pub fn ensure_sidecar(
    mdd_path: &str,
    sidecar_dir: Option<&str>,
) -> Result<(String, PathBuf), MddError> {
    let sidecar = sidecar_path(mdd_path, sidecar_dir);

    if sidecar.exists() {
        let (ecu_name, signatures) = read_mdd_signatures(mdd_path)?;

        match validate_sidecar(&sidecar, &signatures) {
            Ok(true) => {
                tracing::debug!(
                    sidecar = %sidecar.display(),
                    "Sidecar validated against MDD signature, skipping decompression"
                );
                return Ok((ecu_name, sidecar));
            }
            Ok(false) => {
                tracing::info!(
                    sidecar = %sidecar.display(),
                    "Sidecar signature mismatch or missing; re-creating from MDD"
                );
            }
            Err(e) => {
                tracing::warn!(
                    sidecar = %sidecar.display(),
                    error = %e,
                    "Failed to validate sidecar; re-creating from MDD"
                );
            }
        }
    }

    // Sidecar does not exist or is stale — decompress and create it.
    let (ecu_name, ecu_data) = load_ecudata(mdd_path)?;
    write_sidecar(&sidecar, &ecu_data)?;
    Ok((ecu_name, sidecar))
}

/// Write a sidecar `FlatBuffers` file atomically (write-to-tmp + rename).
///
/// Creates parent directories if they do not exist.
///
/// # Errors
/// Returns an error if the directory cannot be created or the file cannot be written.
pub fn write_sidecar(sidecar: &Path, data: &[u8]) -> Result<(), MddError> {
    if let Some(parent) = sidecar.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            MddError::Io(format!(
                "Failed to create sidecar directory '{}': {e}",
                parent.display()
            ))
        })?;
    }

    // Write atomically: temp file + rename to avoid partial/corrupt sidecars.
    let tmp_path = sidecar.with_extension("fb.tmp");
    std::fs::write(&tmp_path, data).map_err(|e| {
        MddError::Io(format!(
            "Failed to write sidecar temp file '{}': {e}",
            tmp_path.display()
        ))
    })?;
    std::fs::rename(&tmp_path, sidecar).map_err(|e| {
        MddError::Io(format!(
            "Failed to rename sidecar temp file to '{}': {e}",
            sidecar.display()
        ))
    })?;

    tracing::info!(
        sidecar = %sidecar.display(),
        size_bytes = data.len(),
        "Created sidecar FlatBuffers file from MDD"
    );
    Ok(())
}
