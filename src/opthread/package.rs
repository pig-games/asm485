// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Binary CPU package (`*.opcpu`) container support for hierarchy chunks.
//!
//! This module currently implements read/write for:
//! - `FAMS` (family descriptors)
//! - `CPUS` (cpu descriptors)
//! - `DIAL` (dialect descriptors)
//! - `REGS` (scoped register descriptors)
//! - `FORM` (scoped form descriptors)
//! - `TABL` (scoped VM instruction program descriptors)

use std::collections::HashMap;

use crate::opthread::hierarchy::{
    CpuDescriptor, DialectDescriptor, FamilyDescriptor, HierarchyError, HierarchyPackage,
    ScopedFormDescriptor, ScopedOwner, ScopedRegisterDescriptor,
};

pub const OPCPU_MAGIC: [u8; 4] = *b"OPCP";
pub const OPCPU_VERSION_V1: u16 = 0x0001;
pub const OPCPU_ENDIAN_MARKER: u16 = 0x1234;

const HEADER_SIZE: usize = 12;
const TOC_ENTRY_SIZE: usize = 12;

const CHUNK_FAMS: [u8; 4] = *b"FAMS";
const CHUNK_CPUS: [u8; 4] = *b"CPUS";
const CHUNK_DIAL: [u8; 4] = *b"DIAL";
const CHUNK_REGS: [u8; 4] = *b"REGS";
const CHUNK_FORM: [u8; 4] = *b"FORM";
const CHUNK_TABL: [u8; 4] = *b"TABL";
const CHUNK_MSEL: [u8; 4] = *b"MSEL";

/// Scoped VM program descriptor for one mnemonic + mode-key encode template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmProgramDescriptor {
    pub owner: ScopedOwner,
    pub mnemonic: String,
    pub mode_key: String,
    pub program: Vec<u8>,
}

/// Scoped mode selector descriptor for Expr/family-operand to VM mode candidate mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModeSelectorDescriptor {
    pub owner: ScopedOwner,
    pub mnemonic: String,
    pub shape_key: String,
    pub mode_key: String,
    pub operand_plan: String,
    pub priority: u16,
    pub unstable_widen: bool,
    pub width_rank: u8,
}

/// Decoded hierarchy-chunk payload set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HierarchyChunks {
    pub families: Vec<FamilyDescriptor>,
    pub cpus: Vec<CpuDescriptor>,
    pub dialects: Vec<DialectDescriptor>,
    pub registers: Vec<ScopedRegisterDescriptor>,
    pub forms: Vec<ScopedFormDescriptor>,
    pub tables: Vec<VmProgramDescriptor>,
    pub selectors: Vec<ModeSelectorDescriptor>,
}

/// Deterministic package codec errors for malformed container/schema data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpcpuCodecError {
    InvalidMagic {
        found: [u8; 4],
    },
    UnsupportedVersion {
        found: u16,
    },
    InvalidEndiannessMarker {
        found: u16,
    },
    UnexpectedEof {
        context: String,
    },
    DuplicateChunk {
        chunk: String,
    },
    MissingRequiredChunk {
        chunk: String,
    },
    ChunkOutOfBounds {
        chunk: String,
        offset: u32,
        length: u32,
        file_len: usize,
    },
    CountOutOfRange {
        context: String,
    },
    InvalidChunkFormat {
        chunk: String,
        detail: String,
    },
    InvalidUtf8 {
        chunk: String,
    },
    Hierarchy(HierarchyError),
}

impl OpcpuCodecError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidMagic { .. } => "OPC001",
            Self::UnsupportedVersion { .. } => "OPC002",
            Self::InvalidEndiannessMarker { .. } => "OPC003",
            Self::UnexpectedEof { .. } => "OPC004",
            Self::DuplicateChunk { .. } => "OPC005",
            Self::MissingRequiredChunk { .. } => "OPC006",
            Self::ChunkOutOfBounds { .. } => "OPC007",
            Self::CountOutOfRange { .. } => "OPC008",
            Self::InvalidChunkFormat { .. } => "OPC009",
            Self::InvalidUtf8 { .. } => "OPC010",
            Self::Hierarchy(_) => "OPC011",
        }
    }
}

impl std::fmt::Display for OpcpuCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic { found } => write!(
                f,
                "[{}] invalid package magic: found {:?}",
                self.code(),
                found
            ),
            Self::UnsupportedVersion { found } => write!(
                f,
                "[{}] unsupported package version: {}",
                self.code(),
                found
            ),
            Self::InvalidEndiannessMarker { found } => write!(
                f,
                "[{}] invalid endianness marker: 0x{:04X}",
                self.code(),
                found
            ),
            Self::UnexpectedEof { context } => {
                write!(f, "[{}] unexpected end of file: {}", self.code(), context)
            }
            Self::DuplicateChunk { chunk } => {
                write!(f, "[{}] duplicate chunk '{}'", self.code(), chunk)
            }
            Self::MissingRequiredChunk { chunk } => {
                write!(f, "[{}] missing required chunk '{}'", self.code(), chunk)
            }
            Self::ChunkOutOfBounds {
                chunk,
                offset,
                length,
                file_len,
            } => write!(
                f,
                "[{}] chunk '{}' out of bounds (offset={}, length={}, file_len={})",
                self.code(),
                chunk,
                offset,
                length,
                file_len
            ),
            Self::CountOutOfRange { context } => {
                write!(f, "[{}] count out of range: {}", self.code(), context)
            }
            Self::InvalidChunkFormat { chunk, detail } => write!(
                f,
                "[{}] invalid chunk '{}' format: {}",
                self.code(),
                chunk,
                detail
            ),
            Self::InvalidUtf8 { chunk } => {
                write!(f, "[{}] invalid UTF-8 in chunk '{}'", self.code(), chunk)
            }
            Self::Hierarchy(err) => {
                write!(f, "[{}] hierarchy validation error: {}", self.code(), err)
            }
        }
    }
}

impl std::error::Error for OpcpuCodecError {}

impl From<HierarchyError> for OpcpuCodecError {
    fn from(value: HierarchyError) -> Self {
        Self::Hierarchy(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TocEntry {
    offset: u32,
    length: u32,
}

pub fn encode_hierarchy_chunks(
    families: &[FamilyDescriptor],
    cpus: &[CpuDescriptor],
    dialects: &[DialectDescriptor],
    registers: &[ScopedRegisterDescriptor],
    forms: &[ScopedFormDescriptor],
    tables: &[VmProgramDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    encode_hierarchy_chunks_full(families, cpus, dialects, registers, forms, tables, &[])
}

pub fn encode_hierarchy_chunks_full(
    families: &[FamilyDescriptor],
    cpus: &[CpuDescriptor],
    dialects: &[DialectDescriptor],
    registers: &[ScopedRegisterDescriptor],
    forms: &[ScopedFormDescriptor],
    tables: &[VmProgramDescriptor],
    selectors: &[ModeSelectorDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    // Validate cross references and compatibility before encoding.
    HierarchyPackage::new(families.to_vec(), cpus.to_vec(), dialects.to_vec())?;

    let mut fams = families.to_vec();
    let mut cpus = cpus.to_vec();
    let mut dials = dialects.to_vec();
    let mut regs = registers.to_vec();
    let mut forms = forms.to_vec();
    let mut tables = tables.to_vec();
    let mut selectors = selectors.to_vec();
    canonicalize_hierarchy_metadata(
        &mut fams,
        &mut cpus,
        &mut dials,
        &mut regs,
        &mut forms,
        &mut tables,
        &mut selectors,
    );

    let chunks = vec![
        (CHUNK_FAMS, encode_fams_chunk(&fams)?),
        (CHUNK_CPUS, encode_cpus_chunk(&cpus)?),
        (CHUNK_DIAL, encode_dial_chunk(&dials)?),
        (CHUNK_REGS, encode_regs_chunk(&regs)?),
        (CHUNK_FORM, encode_form_chunk(&forms)?),
        (CHUNK_TABL, encode_tabl_chunk(&tables)?),
        (CHUNK_MSEL, encode_msel_chunk(&selectors)?),
    ];

    encode_container(&chunks)
}

pub(crate) fn canonicalize_hierarchy_metadata(
    families: &mut [FamilyDescriptor],
    cpus: &mut [CpuDescriptor],
    dialects: &mut [DialectDescriptor],
    registers: &mut Vec<ScopedRegisterDescriptor>,
    forms: &mut Vec<ScopedFormDescriptor>,
    tables: &mut Vec<VmProgramDescriptor>,
    selectors: &mut Vec<ModeSelectorDescriptor>,
) {
    families.sort_by_key(|entry| entry.id.to_ascii_lowercase());
    cpus.sort_by_key(|entry| entry.id.to_ascii_lowercase());

    for entry in dialects.iter_mut() {
        if let Some(allow) = entry.cpu_allow_list.as_mut() {
            allow.sort_by_key(|cpu| cpu.to_ascii_lowercase());
            allow.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        }
    }
    dialects.sort_by_key(|entry| {
        (
            entry.family_id.to_ascii_lowercase(),
            entry.id.to_ascii_lowercase(),
        )
    });

    for entry in registers.iter_mut() {
        match &mut entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                *id = id.to_ascii_lowercase();
            }
        }
        entry.id = entry.id.to_ascii_lowercase();
    }
    registers.sort_by_key(|entry| {
        let owner_kind = match entry.owner {
            ScopedOwner::Family(_) => 0u8,
            ScopedOwner::Cpu(_) => 1u8,
            ScopedOwner::Dialect(_) => 2u8,
        };
        let owner_id = match &entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                id.to_ascii_lowercase()
            }
        };
        (owner_kind, owner_id, entry.id.to_ascii_lowercase())
    });
    registers.dedup_by(|left, right| {
        left.id == right.id
            && match (&left.owner, &right.owner) {
                (ScopedOwner::Family(left), ScopedOwner::Family(right)) => left == right,
                (ScopedOwner::Cpu(left), ScopedOwner::Cpu(right)) => left == right,
                (ScopedOwner::Dialect(left), ScopedOwner::Dialect(right)) => left == right,
                _ => false,
            }
    });

    for entry in forms.iter_mut() {
        match &mut entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                *id = id.to_ascii_lowercase();
            }
        }
        entry.mnemonic = entry.mnemonic.to_ascii_lowercase();
    }
    forms.sort_by_key(|entry| {
        let owner_kind = match entry.owner {
            ScopedOwner::Family(_) => 0u8,
            ScopedOwner::Cpu(_) => 1u8,
            ScopedOwner::Dialect(_) => 2u8,
        };
        let owner_id = match &entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                id.to_ascii_lowercase()
            }
        };
        (owner_kind, owner_id, entry.mnemonic.to_ascii_lowercase())
    });
    forms.dedup_by(|left, right| {
        left.mnemonic == right.mnemonic
            && match (&left.owner, &right.owner) {
                (ScopedOwner::Family(left), ScopedOwner::Family(right)) => left == right,
                (ScopedOwner::Cpu(left), ScopedOwner::Cpu(right)) => left == right,
                (ScopedOwner::Dialect(left), ScopedOwner::Dialect(right)) => left == right,
                _ => false,
            }
    });

    for entry in tables.iter_mut() {
        match &mut entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                *id = id.to_ascii_lowercase();
            }
        }
        entry.mnemonic = entry.mnemonic.to_ascii_lowercase();
        entry.mode_key = entry.mode_key.to_ascii_lowercase();
    }
    tables.sort_by_key(|entry| {
        let owner_kind = match entry.owner {
            ScopedOwner::Family(_) => 0u8,
            ScopedOwner::Cpu(_) => 1u8,
            ScopedOwner::Dialect(_) => 2u8,
        };
        let owner_id = match &entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                id.to_ascii_lowercase()
            }
        };
        (
            owner_kind,
            owner_id,
            entry.mnemonic.to_ascii_lowercase(),
            entry.mode_key.to_ascii_lowercase(),
        )
    });
    tables.dedup_by(|left, right| {
        left.mnemonic == right.mnemonic
            && left.mode_key == right.mode_key
            && match (&left.owner, &right.owner) {
                (ScopedOwner::Family(left), ScopedOwner::Family(right)) => left == right,
                (ScopedOwner::Cpu(left), ScopedOwner::Cpu(right)) => left == right,
                (ScopedOwner::Dialect(left), ScopedOwner::Dialect(right)) => left == right,
                _ => false,
            }
    });

    for entry in selectors.iter_mut() {
        match &mut entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                *id = id.to_ascii_lowercase();
            }
        }
        entry.mnemonic = entry.mnemonic.to_ascii_lowercase();
        entry.shape_key = entry.shape_key.to_ascii_lowercase();
        entry.mode_key = entry.mode_key.to_ascii_lowercase();
        entry.operand_plan = entry.operand_plan.to_ascii_lowercase();
    }
    selectors.sort_by_key(|entry| {
        let owner_kind = match entry.owner {
            ScopedOwner::Family(_) => 0u8,
            ScopedOwner::Cpu(_) => 1u8,
            ScopedOwner::Dialect(_) => 2u8,
        };
        let owner_id = match &entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                id.to_ascii_lowercase()
            }
        };
        (
            owner_kind,
            owner_id,
            entry.mnemonic.to_ascii_lowercase(),
            entry.shape_key.to_ascii_lowercase(),
            entry.priority,
            entry.mode_key.to_ascii_lowercase(),
        )
    });
    selectors.dedup_by(|left, right| {
        left.priority == right.priority
            && left.mnemonic == right.mnemonic
            && left.shape_key == right.shape_key
            && left.mode_key == right.mode_key
            && left.operand_plan == right.operand_plan
            && left.unstable_widen == right.unstable_widen
            && left.width_rank == right.width_rank
            && match (&left.owner, &right.owner) {
                (ScopedOwner::Family(left), ScopedOwner::Family(right)) => left == right,
                (ScopedOwner::Cpu(left), ScopedOwner::Cpu(right)) => left == right,
                (ScopedOwner::Dialect(left), ScopedOwner::Dialect(right)) => left == right,
                _ => false,
            }
    });
}

pub fn decode_hierarchy_chunks(bytes: &[u8]) -> Result<HierarchyChunks, OpcpuCodecError> {
    let toc = parse_toc(bytes)?;
    let fams_bytes = slice_for_chunk(bytes, &toc, CHUNK_FAMS)?;
    let cpus_bytes = slice_for_chunk(bytes, &toc, CHUNK_CPUS)?;
    let dial_bytes = slice_for_chunk(bytes, &toc, CHUNK_DIAL)?;
    let regs_bytes = slice_for_chunk(bytes, &toc, CHUNK_REGS)?;
    let form_bytes = slice_for_chunk(bytes, &toc, CHUNK_FORM)?;
    let tabl_bytes = slice_for_chunk(bytes, &toc, CHUNK_TABL)?;
    let msel_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_MSEL)?;

    Ok(HierarchyChunks {
        families: decode_fams_chunk(fams_bytes)?,
        cpus: decode_cpus_chunk(cpus_bytes)?,
        dialects: decode_dial_chunk(dial_bytes)?,
        registers: decode_regs_chunk(regs_bytes)?,
        forms: decode_form_chunk(form_bytes)?,
        tables: decode_tabl_chunk(tabl_bytes)?,
        selectors: match msel_bytes {
            Some(payload) => decode_msel_chunk(payload)?,
            None => Vec::new(),
        },
    })
}

pub fn load_hierarchy_package(bytes: &[u8]) -> Result<HierarchyPackage, OpcpuCodecError> {
    let decoded = decode_hierarchy_chunks(bytes)?;
    HierarchyPackage::new(decoded.families, decoded.cpus, decoded.dialects).map_err(Into::into)
}

fn encode_container(chunks: &[([u8; 4], Vec<u8>)]) -> Result<Vec<u8>, OpcpuCodecError> {
    let toc_count = u16::try_from(chunks.len()).map_err(|_| OpcpuCodecError::CountOutOfRange {
        context: "TOC entry count exceeds u16".to_string(),
    })?;

    let header_and_toc_len = HEADER_SIZE
        .checked_add(chunks.len().checked_mul(TOC_ENTRY_SIZE).ok_or_else(|| {
            OpcpuCodecError::CountOutOfRange {
                context: "TOC byte size overflow".to_string(),
            }
        })?)
        .ok_or_else(|| OpcpuCodecError::CountOutOfRange {
            context: "header size overflow".to_string(),
        })?;

    let mut toc_entries = Vec::with_capacity(chunks.len());
    let mut next_offset =
        u32::try_from(header_and_toc_len).map_err(|_| OpcpuCodecError::CountOutOfRange {
            context: "container header offset exceeds u32".to_string(),
        })?;

    for (tag, payload) in chunks {
        let length =
            u32::try_from(payload.len()).map_err(|_| OpcpuCodecError::CountOutOfRange {
                context: format!("chunk '{}' length exceeds u32", chunk_name(tag)),
            })?;
        toc_entries.push((
            *tag,
            TocEntry {
                offset: next_offset,
                length,
            },
        ));
        next_offset =
            next_offset
                .checked_add(length)
                .ok_or_else(|| OpcpuCodecError::CountOutOfRange {
                    context: "container size exceeds u32".to_string(),
                })?;
    }

    let mut out = Vec::new();
    out.extend_from_slice(&OPCPU_MAGIC);
    out.extend_from_slice(&OPCPU_VERSION_V1.to_le_bytes());
    out.extend_from_slice(&OPCPU_ENDIAN_MARKER.to_le_bytes());
    out.extend_from_slice(&toc_count.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());

    for (tag, entry) in &toc_entries {
        out.extend_from_slice(tag);
        out.extend_from_slice(&entry.offset.to_le_bytes());
        out.extend_from_slice(&entry.length.to_le_bytes());
    }

    for (_, payload) in chunks {
        out.extend_from_slice(payload);
    }

    Ok(out)
}

fn parse_toc(bytes: &[u8]) -> Result<HashMap<[u8; 4], TocEntry>, OpcpuCodecError> {
    if bytes.len() < HEADER_SIZE {
        return Err(OpcpuCodecError::UnexpectedEof {
            context: "container header".to_string(),
        });
    }

    let found_magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if found_magic != OPCPU_MAGIC {
        return Err(OpcpuCodecError::InvalidMagic { found: found_magic });
    }

    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != OPCPU_VERSION_V1 {
        return Err(OpcpuCodecError::UnsupportedVersion { found: version });
    }

    let marker = u16::from_le_bytes([bytes[6], bytes[7]]);
    if marker != OPCPU_ENDIAN_MARKER {
        return Err(OpcpuCodecError::InvalidEndiannessMarker { found: marker });
    }

    let toc_count = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
    let toc_bytes = toc_count
        .checked_mul(TOC_ENTRY_SIZE)
        .and_then(|size| HEADER_SIZE.checked_add(size))
        .ok_or_else(|| OpcpuCodecError::CountOutOfRange {
            context: "TOC length overflow".to_string(),
        })?;

    if bytes.len() < toc_bytes {
        return Err(OpcpuCodecError::UnexpectedEof {
            context: "TOC entries".to_string(),
        });
    }

    let mut toc = HashMap::new();
    for idx in 0..toc_count {
        let start = HEADER_SIZE + idx * TOC_ENTRY_SIZE;
        let tag = [
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ];
        let offset = u32::from_le_bytes([
            bytes[start + 4],
            bytes[start + 5],
            bytes[start + 6],
            bytes[start + 7],
        ]);
        let length = u32::from_le_bytes([
            bytes[start + 8],
            bytes[start + 9],
            bytes[start + 10],
            bytes[start + 11],
        ]);

        if toc.contains_key(&tag) {
            return Err(OpcpuCodecError::DuplicateChunk {
                chunk: chunk_name(&tag),
            });
        }

        let start_usize =
            usize::try_from(offset).map_err(|_| OpcpuCodecError::ChunkOutOfBounds {
                chunk: chunk_name(&tag),
                offset,
                length,
                file_len: bytes.len(),
            })?;
        let len_usize = usize::try_from(length).map_err(|_| OpcpuCodecError::ChunkOutOfBounds {
            chunk: chunk_name(&tag),
            offset,
            length,
            file_len: bytes.len(),
        })?;
        let end = start_usize.checked_add(len_usize).ok_or_else(|| {
            OpcpuCodecError::ChunkOutOfBounds {
                chunk: chunk_name(&tag),
                offset,
                length,
                file_len: bytes.len(),
            }
        })?;
        if end > bytes.len() {
            return Err(OpcpuCodecError::ChunkOutOfBounds {
                chunk: chunk_name(&tag),
                offset,
                length,
                file_len: bytes.len(),
            });
        }

        toc.insert(tag, TocEntry { offset, length });
    }

    Ok(toc)
}

fn slice_for_chunk<'a>(
    bytes: &'a [u8],
    toc: &HashMap<[u8; 4], TocEntry>,
    tag: [u8; 4],
) -> Result<&'a [u8], OpcpuCodecError> {
    let entry = toc
        .get(&tag)
        .ok_or_else(|| OpcpuCodecError::MissingRequiredChunk {
            chunk: chunk_name(&tag),
        })?;
    let start = usize::try_from(entry.offset).map_err(|_| OpcpuCodecError::ChunkOutOfBounds {
        chunk: chunk_name(&tag),
        offset: entry.offset,
        length: entry.length,
        file_len: bytes.len(),
    })?;
    let len = usize::try_from(entry.length).map_err(|_| OpcpuCodecError::ChunkOutOfBounds {
        chunk: chunk_name(&tag),
        offset: entry.offset,
        length: entry.length,
        file_len: bytes.len(),
    })?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| OpcpuCodecError::ChunkOutOfBounds {
            chunk: chunk_name(&tag),
            offset: entry.offset,
            length: entry.length,
            file_len: bytes.len(),
        })?;
    bytes
        .get(start..end)
        .ok_or_else(|| OpcpuCodecError::ChunkOutOfBounds {
            chunk: chunk_name(&tag),
            offset: entry.offset,
            length: entry.length,
            file_len: bytes.len(),
        })
}

fn slice_for_chunk_optional<'a>(
    bytes: &'a [u8],
    toc: &HashMap<[u8; 4], TocEntry>,
    tag: [u8; 4],
) -> Result<Option<&'a [u8]>, OpcpuCodecError> {
    let Some(entry) = toc.get(&tag) else {
        return Ok(None);
    };
    let start = usize::try_from(entry.offset).map_err(|_| OpcpuCodecError::ChunkOutOfBounds {
        chunk: chunk_name(&tag),
        offset: entry.offset,
        length: entry.length,
        file_len: bytes.len(),
    })?;
    let len = usize::try_from(entry.length).map_err(|_| OpcpuCodecError::ChunkOutOfBounds {
        chunk: chunk_name(&tag),
        offset: entry.offset,
        length: entry.length,
        file_len: bytes.len(),
    })?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| OpcpuCodecError::ChunkOutOfBounds {
            chunk: chunk_name(&tag),
            offset: entry.offset,
            length: entry.length,
            file_len: bytes.len(),
        })?;
    bytes
        .get(start..end)
        .map(Some)
        .ok_or_else(|| OpcpuCodecError::ChunkOutOfBounds {
            chunk: chunk_name(&tag),
            offset: entry.offset,
            length: entry.length,
            file_len: bytes.len(),
        })
}

fn encode_fams_chunk(families: &[FamilyDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(families.len(), "FAMS count")?);
    for family in families {
        write_string(&mut out, "FAMS", &family.id)?;
        write_string(&mut out, "FAMS", &family.canonical_dialect)?;
    }
    Ok(out)
}

fn decode_fams_chunk(bytes: &[u8]) -> Result<Vec<FamilyDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "FAMS");
    let count = cur.read_u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(FamilyDescriptor {
            id: cur.read_string()?,
            canonical_dialect: cur.read_string()?,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_cpus_chunk(cpus: &[CpuDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(cpus.len(), "CPUS count")?);
    for cpu in cpus {
        write_string(&mut out, "CPUS", &cpu.id)?;
        write_string(&mut out, "CPUS", &cpu.family_id)?;
        match cpu.default_dialect.as_deref() {
            Some(default_dialect) => {
                out.push(1);
                write_string(&mut out, "CPUS", default_dialect)?;
            }
            None => out.push(0),
        }
    }
    Ok(out)
}

fn decode_cpus_chunk(bytes: &[u8]) -> Result<Vec<CpuDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "CPUS");
    let count = cur.read_u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let id = cur.read_string()?;
        let family_id = cur.read_string()?;
        let has_default = cur.read_u8()?;
        let default_dialect = match has_default {
            0 => None,
            1 => Some(cur.read_string()?),
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "CPUS".to_string(),
                    detail: format!("invalid bool flag for default_dialect: {}", other),
                });
            }
        };
        entries.push(CpuDescriptor {
            id,
            family_id,
            default_dialect,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_dial_chunk(dialects: &[DialectDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(dialects.len(), "DIAL count")?);
    for dialect in dialects {
        write_string(&mut out, "DIAL", &dialect.id)?;
        write_string(&mut out, "DIAL", &dialect.family_id)?;
        match dialect.cpu_allow_list.as_deref() {
            Some(allow_list) => {
                out.push(1);
                write_u32(
                    &mut out,
                    u32_count(allow_list.len(), "DIAL allow-list count")?,
                );
                for cpu_id in allow_list {
                    write_string(&mut out, "DIAL", cpu_id)?;
                }
            }
            None => out.push(0),
        }
    }
    Ok(out)
}

fn decode_dial_chunk(bytes: &[u8]) -> Result<Vec<DialectDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "DIAL");
    let count = cur.read_u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let id = cur.read_string()?;
        let family_id = cur.read_string()?;
        let has_allow_list = cur.read_u8()?;
        let cpu_allow_list = match has_allow_list {
            0 => None,
            1 => {
                let allow_count = cur.read_u32()? as usize;
                let mut allow = Vec::with_capacity(allow_count);
                for _ in 0..allow_count {
                    allow.push(cur.read_string()?);
                }
                Some(allow)
            }
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "DIAL".to_string(),
                    detail: format!("invalid bool flag for cpu_allow_list: {}", other),
                });
            }
        };
        entries.push(DialectDescriptor {
            id,
            family_id,
            cpu_allow_list,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_regs_chunk(registers: &[ScopedRegisterDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(registers.len(), "REGS count")?);
    for register in registers {
        let (owner_tag, owner_id) = match &register.owner {
            ScopedOwner::Family(id) => (0u8, id.as_str()),
            ScopedOwner::Cpu(id) => (1u8, id.as_str()),
            ScopedOwner::Dialect(id) => (2u8, id.as_str()),
        };
        out.push(owner_tag);
        write_string(&mut out, "REGS", owner_id)?;
        write_string(&mut out, "REGS", &register.id)?;
    }
    Ok(out)
}

fn decode_regs_chunk(bytes: &[u8]) -> Result<Vec<ScopedRegisterDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "REGS");
    let count = cur.read_u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner_tag = cur.read_u8()?;
        let owner_id = cur.read_string()?;
        let id = cur.read_string()?;
        let owner = match owner_tag {
            0 => ScopedOwner::Family(owner_id),
            1 => ScopedOwner::Cpu(owner_id),
            2 => ScopedOwner::Dialect(owner_id),
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "REGS".to_string(),
                    detail: format!("invalid owner tag: {}", other),
                });
            }
        };
        entries.push(ScopedRegisterDescriptor { owner, id });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_form_chunk(forms: &[ScopedFormDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(forms.len(), "FORM count")?);
    for form in forms {
        let (owner_tag, owner_id) = match &form.owner {
            ScopedOwner::Family(id) => (0u8, id.as_str()),
            ScopedOwner::Cpu(id) => (1u8, id.as_str()),
            ScopedOwner::Dialect(id) => (2u8, id.as_str()),
        };
        out.push(owner_tag);
        write_string(&mut out, "FORM", owner_id)?;
        write_string(&mut out, "FORM", &form.mnemonic)?;
    }
    Ok(out)
}

fn decode_form_chunk(bytes: &[u8]) -> Result<Vec<ScopedFormDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "FORM");
    let count = cur.read_u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner_tag = cur.read_u8()?;
        let owner_id = cur.read_string()?;
        let mnemonic = cur.read_string()?;
        let owner = match owner_tag {
            0 => ScopedOwner::Family(owner_id),
            1 => ScopedOwner::Cpu(owner_id),
            2 => ScopedOwner::Dialect(owner_id),
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "FORM".to_string(),
                    detail: format!("invalid owner tag: {}", other),
                });
            }
        };
        entries.push(ScopedFormDescriptor { owner, mnemonic });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_tabl_chunk(tables: &[VmProgramDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(tables.len(), "TABL count")?);
    for entry in tables {
        let (owner_tag, owner_id) = match &entry.owner {
            ScopedOwner::Family(id) => (0u8, id.as_str()),
            ScopedOwner::Cpu(id) => (1u8, id.as_str()),
            ScopedOwner::Dialect(id) => (2u8, id.as_str()),
        };
        out.push(owner_tag);
        write_string(&mut out, "TABL", owner_id)?;
        write_string(&mut out, "TABL", &entry.mnemonic)?;
        write_string(&mut out, "TABL", &entry.mode_key)?;
        write_u32(
            &mut out,
            u32_count(entry.program.len(), "TABL program byte length")?,
        );
        out.extend_from_slice(&entry.program);
    }
    Ok(out)
}

fn decode_tabl_chunk(bytes: &[u8]) -> Result<Vec<VmProgramDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "TABL");
    let count = cur.read_u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner_tag = cur.read_u8()?;
        let owner_id = cur.read_string()?;
        let mnemonic = cur.read_string()?;
        let mode_key = cur.read_string()?;
        let byte_count = cur.read_u32()? as usize;
        let program = cur.read_exact(byte_count, "program bytes")?.to_vec();
        let owner = match owner_tag {
            0 => ScopedOwner::Family(owner_id),
            1 => ScopedOwner::Cpu(owner_id),
            2 => ScopedOwner::Dialect(owner_id),
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "TABL".to_string(),
                    detail: format!("invalid owner tag: {}", other),
                });
            }
        };
        entries.push(VmProgramDescriptor {
            owner,
            mnemonic,
            mode_key,
            program,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_msel_chunk(selectors: &[ModeSelectorDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(selectors.len(), "MSEL count")?);
    for entry in selectors {
        let (owner_tag, owner_id) = match &entry.owner {
            ScopedOwner::Family(id) => (0u8, id.as_str()),
            ScopedOwner::Cpu(id) => (1u8, id.as_str()),
            ScopedOwner::Dialect(id) => (2u8, id.as_str()),
        };
        out.push(owner_tag);
        write_string(&mut out, "MSEL", owner_id)?;
        write_string(&mut out, "MSEL", &entry.mnemonic)?;
        write_string(&mut out, "MSEL", &entry.shape_key)?;
        write_string(&mut out, "MSEL", &entry.mode_key)?;
        write_string(&mut out, "MSEL", &entry.operand_plan)?;
        out.extend_from_slice(&entry.priority.to_le_bytes());
        out.push(u8::from(entry.unstable_widen));
        out.push(entry.width_rank);
    }
    Ok(out)
}

fn decode_msel_chunk(bytes: &[u8]) -> Result<Vec<ModeSelectorDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "MSEL");
    let count = cur.read_u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner_tag = cur.read_u8()?;
        let owner_id = cur.read_string()?;
        let mnemonic = cur.read_string()?;
        let shape_key = cur.read_string()?;
        let mode_key = cur.read_string()?;
        let operand_plan = cur.read_string()?;
        let priority_bytes = cur.read_exact(2, "priority")?;
        let priority = u16::from_le_bytes([priority_bytes[0], priority_bytes[1]]);
        let unstable_widen = match cur.read_u8()? {
            0 => false,
            1 => true,
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "MSEL".to_string(),
                    detail: format!("invalid bool flag for unstable_widen: {}", other),
                });
            }
        };
        let width_rank = cur.read_u8()?;
        let owner = match owner_tag {
            0 => ScopedOwner::Family(owner_id),
            1 => ScopedOwner::Cpu(owner_id),
            2 => ScopedOwner::Dialect(owner_id),
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "MSEL".to_string(),
                    detail: format!("invalid owner tag: {}", other),
                });
            }
        };
        entries.push(ModeSelectorDescriptor {
            owner,
            mnemonic,
            shape_key,
            mode_key,
            operand_plan,
            priority,
            unstable_widen,
            width_rank,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_string(out: &mut Vec<u8>, chunk: &str, value: &str) -> Result<(), OpcpuCodecError> {
    let len = u32::try_from(value.len()).map_err(|_| OpcpuCodecError::CountOutOfRange {
        context: format!("{} string length exceeds u32", chunk),
    })?;
    write_u32(out, len);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn u32_count(count: usize, context: &str) -> Result<u32, OpcpuCodecError> {
    u32::try_from(count).map_err(|_| OpcpuCodecError::CountOutOfRange {
        context: context.to_string(),
    })
}

fn chunk_name(tag: &[u8; 4]) -> String {
    std::str::from_utf8(tag)
        .map(|value| value.to_string())
        .unwrap_or_else(|_| format!("{:02X?}", tag))
}

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
    chunk: &'static str,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8], chunk: &'static str) -> Self {
        Self {
            bytes,
            pos: 0,
            chunk,
        }
    }

    fn read_u8(&mut self) -> Result<u8, OpcpuCodecError> {
        let slice = self.read_exact(1, "u8")?;
        Ok(slice[0])
    }

    fn read_u32(&mut self) -> Result<u32, OpcpuCodecError> {
        let slice = self.read_exact(4, "u32")?;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    fn read_string(&mut self) -> Result<String, OpcpuCodecError> {
        let len = self.read_u32()? as usize;
        let bytes = self.read_exact(len, "string bytes")?;
        String::from_utf8(bytes.to_vec()).map_err(|_| OpcpuCodecError::InvalidUtf8 {
            chunk: self.chunk.to_string(),
        })
    }

    fn read_exact(&mut self, len: usize, detail: &str) -> Result<&'a [u8], OpcpuCodecError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| OpcpuCodecError::InvalidChunkFormat {
                chunk: self.chunk.to_string(),
                detail: format!("{} overflow", detail),
            })?;
        if end > self.bytes.len() {
            return Err(OpcpuCodecError::UnexpectedEof {
                context: format!("chunk {} {}", self.chunk, detail),
            });
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn finish(&self) -> Result<(), OpcpuCodecError> {
        if self.pos != self.bytes.len() {
            return Err(OpcpuCodecError::InvalidChunkFormat {
                chunk: self.chunk.to_string(),
                detail: "trailing bytes".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_families() -> Vec<FamilyDescriptor> {
        vec![
            FamilyDescriptor {
                id: "mos6502".to_string(),
                canonical_dialect: "mos".to_string(),
            },
            FamilyDescriptor {
                id: "intel8080".to_string(),
                canonical_dialect: "intel".to_string(),
            },
        ]
    }

    fn sample_cpus() -> Vec<CpuDescriptor> {
        vec![
            CpuDescriptor {
                id: "z80".to_string(),
                family_id: "intel8080".to_string(),
                default_dialect: Some("zilog".to_string()),
            },
            CpuDescriptor {
                id: "8085".to_string(),
                family_id: "intel8080".to_string(),
                default_dialect: Some("intel".to_string()),
            },
            CpuDescriptor {
                id: "6502".to_string(),
                family_id: "mos6502".to_string(),
                default_dialect: Some("mos".to_string()),
            },
        ]
    }

    fn sample_dialects() -> Vec<DialectDescriptor> {
        vec![
            DialectDescriptor {
                id: "mos".to_string(),
                family_id: "mos6502".to_string(),
                cpu_allow_list: None,
            },
            DialectDescriptor {
                id: "intel".to_string(),
                family_id: "intel8080".to_string(),
                cpu_allow_list: None,
            },
            DialectDescriptor {
                id: "zilog".to_string(),
                family_id: "intel8080".to_string(),
                cpu_allow_list: Some(vec!["z80".to_string(), "Z80".to_string()]),
            },
        ]
    }

    fn sample_registers() -> Vec<ScopedRegisterDescriptor> {
        vec![
            ScopedRegisterDescriptor {
                owner: ScopedOwner::Family("intel8080".to_string()),
                id: "A".to_string(),
            },
            ScopedRegisterDescriptor {
                owner: ScopedOwner::Family("intel8080".to_string()),
                id: "HL".to_string(),
            },
            ScopedRegisterDescriptor {
                owner: ScopedOwner::Cpu("z80".to_string()),
                id: "IX".to_string(),
            },
            ScopedRegisterDescriptor {
                owner: ScopedOwner::Cpu("z80".to_string()),
                id: "ix".to_string(),
            },
        ]
    }

    fn sample_forms() -> Vec<ScopedFormDescriptor> {
        vec![
            ScopedFormDescriptor {
                owner: ScopedOwner::Family("intel8080".to_string()),
                mnemonic: "mov".to_string(),
            },
            ScopedFormDescriptor {
                owner: ScopedOwner::Family("intel8080".to_string()),
                mnemonic: "MOV".to_string(),
            },
            ScopedFormDescriptor {
                owner: ScopedOwner::Cpu("z80".to_string()),
                mnemonic: "djnz".to_string(),
            },
            ScopedFormDescriptor {
                owner: ScopedOwner::Dialect("zilog".to_string()),
                mnemonic: "ld".to_string(),
            },
        ]
    }

    fn sample_tables() -> Vec<VmProgramDescriptor> {
        vec![
            VmProgramDescriptor {
                owner: ScopedOwner::Cpu("m6502".to_string()),
                mnemonic: "lda".to_string(),
                mode_key: "immediate".to_string(),
                program: vec![0x01, 0xA9, 0x02, 0x00, 0xFF],
            },
            VmProgramDescriptor {
                owner: ScopedOwner::Cpu("m6502".to_string()),
                mnemonic: "LDA".to_string(),
                mode_key: "Immediate".to_string(),
                program: vec![0x01, 0xA9, 0x02, 0x00, 0xFF],
            },
        ]
    }

    #[test]
    fn encode_decode_round_trip_is_deterministic() {
        let bytes = encode_hierarchy_chunks(
            &sample_families(),
            &sample_cpus(),
            &sample_dialects(),
            &sample_registers(),
            &sample_forms(),
            &sample_tables(),
        )
        .expect("encode should succeed");
        let decoded = decode_hierarchy_chunks(&bytes).expect("decode should succeed");
        let reencoded = encode_hierarchy_chunks(
            &decoded.families,
            &decoded.cpus,
            &decoded.dialects,
            &decoded.registers,
            &decoded.forms,
            &decoded.tables,
        )
        .expect("re-encode should succeed");
        assert_eq!(bytes, reencoded);
    }

    #[test]
    fn load_hierarchy_package_validates_and_resolves() {
        let bytes = encode_hierarchy_chunks(
            &sample_families(),
            &sample_cpus(),
            &sample_dialects(),
            &sample_registers(),
            &sample_forms(),
            &sample_tables(),
        )
        .expect("encode should succeed");
        let package = load_hierarchy_package(&bytes).expect("load should succeed");

        let resolved_8085 = package
            .resolve_pipeline("8085", None)
            .expect("8085 should resolve");
        assert_eq!(resolved_8085.dialect_id, "intel");

        let resolved_z80 = package
            .resolve_pipeline("z80", None)
            .expect("z80 should resolve");
        assert_eq!(resolved_z80.dialect_id, "zilog");
    }

    #[test]
    fn encoding_is_stable_across_input_order() {
        let mut families = sample_families();
        families.reverse();
        let mut cpus = sample_cpus();
        cpus.reverse();
        let mut dialects = sample_dialects();
        dialects.reverse();
        let mut registers = sample_registers();
        registers.reverse();
        let mut forms = sample_forms();
        forms.reverse();
        let mut tables = sample_tables();
        tables.reverse();

        let a = encode_hierarchy_chunks(
            &sample_families(),
            &sample_cpus(),
            &sample_dialects(),
            &sample_registers(),
            &sample_forms(),
            &sample_tables(),
        )
        .expect("ordered encode should succeed");
        let b = encode_hierarchy_chunks(&families, &cpus, &dialects, &registers, &forms, &tables)
            .expect("shuffled encode should succeed");
        assert_eq!(a, b);
    }

    #[test]
    fn metadata_snapshot_is_stable() {
        let bytes = encode_hierarchy_chunks(
            &sample_families(),
            &sample_cpus(),
            &sample_dialects(),
            &sample_registers(),
            &sample_forms(),
            &sample_tables(),
        )
        .expect("encode should succeed");
        let decoded = decode_hierarchy_chunks(&bytes).expect("decode should succeed");

        let family_snapshot: Vec<String> = decoded
            .families
            .iter()
            .map(|entry| format!("{}->{}", entry.id, entry.canonical_dialect))
            .collect();
        assert_eq!(family_snapshot, vec!["intel8080->intel", "mos6502->mos"]);

        let cpu_snapshot: Vec<String> = decoded
            .cpus
            .iter()
            .map(|entry| {
                format!(
                    "{}:{}:{}",
                    entry.id,
                    entry.family_id,
                    entry.default_dialect.as_deref().unwrap_or("-")
                )
            })
            .collect();
        assert_eq!(
            cpu_snapshot,
            vec![
                "6502:mos6502:mos",
                "8085:intel8080:intel",
                "z80:intel8080:zilog"
            ]
        );

        let dialect_snapshot: Vec<String> = decoded
            .dialects
            .iter()
            .map(|entry| format!("{}:{}", entry.family_id, entry.id))
            .collect();
        assert_eq!(
            dialect_snapshot,
            vec!["intel8080:intel", "intel8080:zilog", "mos6502:mos"]
        );
    }

    #[test]
    fn toc_snapshot_is_stable() {
        let bytes = encode_hierarchy_chunks(
            &sample_families(),
            &sample_cpus(),
            &sample_dialects(),
            &sample_registers(),
            &sample_forms(),
            &sample_tables(),
        )
        .expect("encode should succeed");

        let toc_count = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
        let mut toc_entries = Vec::new();
        for idx in 0..toc_count {
            let base = HEADER_SIZE + idx * TOC_ENTRY_SIZE;
            let chunk_id = String::from_utf8_lossy(&bytes[base..base + 4]).to_string();
            let offset = u32::from_le_bytes([
                bytes[base + 4],
                bytes[base + 5],
                bytes[base + 6],
                bytes[base + 7],
            ]);
            let length = u32::from_le_bytes([
                bytes[base + 8],
                bytes[base + 9],
                bytes[base + 10],
                bytes[base + 11],
            ]);
            toc_entries.push(format!("{}@{}+{}", chunk_id, offset, length));
        }

        assert_eq!(
            toc_entries,
            vec![
                "FAMS@96+44",
                "CPUS@140+92",
                "DIAL@232+80",
                "REGS@312+57",
                "FORM@369+57",
                "TABL@426+43",
                "MSEL@469+4"
            ]
        );
    }

    #[test]
    fn decode_rejects_missing_required_chunk() {
        let bytes = encode_container(&[]).expect("container encode should succeed");
        let err = decode_hierarchy_chunks(&bytes).expect_err("missing FAMS should fail");
        assert!(matches!(err, OpcpuCodecError::MissingRequiredChunk { .. }));
        assert_eq!(err.code(), "OPC006");
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let mut bytes = encode_hierarchy_chunks(
            &sample_families(),
            &sample_cpus(),
            &sample_dialects(),
            &sample_registers(),
            &sample_forms(),
            &sample_tables(),
        )
        .expect("encode should succeed");
        bytes.pop();
        let err = decode_hierarchy_chunks(&bytes).expect_err("truncated payload should fail");
        assert!(matches!(
            err,
            OpcpuCodecError::ChunkOutOfBounds { .. } | OpcpuCodecError::UnexpectedEof { .. }
        ));
    }

    #[test]
    fn decode_rejects_invalid_endian_marker() {
        let mut bytes = encode_hierarchy_chunks(
            &sample_families(),
            &sample_cpus(),
            &sample_dialects(),
            &sample_registers(),
            &sample_forms(),
            &sample_tables(),
        )
        .expect("encode should succeed");
        bytes[6] = 0x78;
        bytes[7] = 0x56;
        let err = decode_hierarchy_chunks(&bytes).expect_err("invalid marker should fail");
        assert!(matches!(
            err,
            OpcpuCodecError::InvalidEndiannessMarker { .. }
        ));
        assert_eq!(err.code(), "OPC003");
    }

    #[test]
    fn load_rejects_cross_reference_errors() {
        let families = vec![FamilyDescriptor {
            id: "intel8080".to_string(),
            canonical_dialect: "intel".to_string(),
        }];
        let cpus = vec![CpuDescriptor {
            id: "8085".to_string(),
            family_id: "missing".to_string(),
            default_dialect: Some("intel".to_string()),
        }];
        let dials = vec![DialectDescriptor {
            id: "intel".to_string(),
            family_id: "intel8080".to_string(),
            cpu_allow_list: None,
        }];
        let chunks = vec![
            (CHUNK_FAMS, encode_fams_chunk(&families).expect("fams")),
            (CHUNK_CPUS, encode_cpus_chunk(&cpus).expect("cpus")),
            (CHUNK_DIAL, encode_dial_chunk(&dials).expect("dial")),
            (CHUNK_REGS, encode_regs_chunk(&[]).expect("regs")),
            (CHUNK_FORM, encode_form_chunk(&[]).expect("form")),
            (CHUNK_TABL, encode_tabl_chunk(&[]).expect("tabl")),
        ];
        let bytes = encode_container(&chunks).expect("container");

        let err = load_hierarchy_package(&bytes).expect_err("cross-reference should fail");
        assert!(matches!(err, OpcpuCodecError::Hierarchy(_)));
        assert_eq!(err.code(), "OPC011");
    }
}
