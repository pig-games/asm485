use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TocEntry {
    pub(super) offset: u32,
    pub(super) length: u32,
}

pub(super) fn encode_hierarchy_chunks(
    families: &[FamilyDescriptor],
    cpus: &[CpuDescriptor],
    dialects: &[DialectDescriptor],
    registers: &[ScopedRegisterDescriptor],
    forms: &[ScopedFormDescriptor],
    tables: &[VmProgramDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    encode_hierarchy_chunks_full(families, cpus, dialects, registers, forms, tables, &[])
}

pub(super) fn encode_hierarchy_chunks_full(
    families: &[FamilyDescriptor],
    cpus: &[CpuDescriptor],
    dialects: &[DialectDescriptor],
    registers: &[ScopedRegisterDescriptor],
    forms: &[ScopedFormDescriptor],
    tables: &[VmProgramDescriptor],
    selectors: &[ModeSelectorDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let chunks = HierarchyChunks {
        metadata: PackageMetaDescriptor::default(),
        strings: Vec::new(),
        diagnostics: Vec::new(),
        token_policies: Vec::new(),
        tokenizer_vm_programs: Vec::new(),
        parser_contracts: Vec::new(),
        parser_vm_programs: Vec::new(),
        expr_contracts: Vec::new(),
        expr_parser_contracts: Vec::new(),
        families: families.to_vec(),
        cpus: cpus.to_vec(),
        dialects: dialects.to_vec(),
        registers: registers.to_vec(),
        forms: forms.to_vec(),
        tables: tables.to_vec(),
        selectors: selectors.to_vec(),
    };
    encode_hierarchy_chunks_from_chunks(&chunks)
}

pub(super) fn encode_hierarchy_chunks_from_chunks(
    chunks: &HierarchyChunks,
) -> Result<Vec<u8>, OpcpuCodecError> {
    // Validate cross references and compatibility before encoding.
    HierarchyPackage::new(
        chunks.families.clone(),
        chunks.cpus.clone(),
        chunks.dialects.clone(),
    )?;

    let metadata = chunks.metadata.clone();
    let mut strings = chunks.strings.to_vec();
    let mut diagnostics = chunks.diagnostics.to_vec();
    let mut token_policies = chunks.token_policies.to_vec();
    let mut tokenizer_vm_programs = chunks.tokenizer_vm_programs.to_vec();
    let mut parser_contracts = chunks.parser_contracts.to_vec();
    let mut parser_vm_programs = chunks.parser_vm_programs.to_vec();
    let mut expr_contracts = chunks.expr_contracts.to_vec();
    let mut expr_parser_contracts = chunks.expr_parser_contracts.to_vec();
    let mut fams = chunks.families.to_vec();
    let mut cpus = chunks.cpus.to_vec();
    let mut dials = chunks.dialects.to_vec();
    let mut regs = chunks.registers.to_vec();
    let mut forms = chunks.forms.to_vec();
    let mut tables = chunks.tables.to_vec();
    let mut selectors = chunks.selectors.to_vec();
    canonicalize_hierarchy_metadata(
        &mut fams,
        &mut cpus,
        &mut dials,
        &mut regs,
        &mut forms,
        &mut tables,
        &mut selectors,
    );
    canonicalize_token_policies(&mut token_policies);
    canonicalize_tokenizer_vm_programs(&mut tokenizer_vm_programs);
    canonicalize_parser_contracts(&mut parser_contracts);
    canonicalize_parser_vm_programs(&mut parser_vm_programs);
    canonicalize_expr_contracts(&mut expr_contracts);
    canonicalize_expr_parser_contracts(&mut expr_parser_contracts);
    canonicalize_package_support_chunks(&mut strings, &mut diagnostics);

    let mut chunks = vec![
        (CHUNK_META, encode_meta_chunk(&metadata)?),
        (CHUNK_STRS, encode_strs_chunk(&strings)?),
        (CHUNK_DIAG, encode_diag_chunk(&diagnostics)?),
    ];
    if !token_policies.is_empty() {
        chunks.push((CHUNK_TOKS, encode_toks_chunk(&token_policies)?));
    }
    if !tokenizer_vm_programs.is_empty() {
        chunks.push((CHUNK_TKVM, encode_tkvm_chunk(&tokenizer_vm_programs)?));
    }
    if !parser_contracts.is_empty() {
        chunks.push((CHUNK_PARS, encode_pars_chunk(&parser_contracts)?));
    }
    if !parser_vm_programs.is_empty() {
        chunks.push((CHUNK_PRVM, encode_prvm_chunk(&parser_vm_programs)?));
    }
    if !expr_contracts.is_empty() {
        chunks.push((CHUNK_EXPR, encode_expr_chunk(&expr_contracts)?));
    }
    if !expr_parser_contracts.is_empty() {
        chunks.push((CHUNK_EXPP, encode_expp_chunk(&expr_parser_contracts)?));
    }
    chunks.extend_from_slice(&[
        (CHUNK_FAMS, encode_fams_chunk(&fams)?),
        (CHUNK_CPUS, encode_cpus_chunk(&cpus)?),
        (CHUNK_DIAL, encode_dial_chunk(&dials)?),
        (CHUNK_REGS, encode_regs_chunk(&regs)?),
        (CHUNK_FORM, encode_form_chunk(&forms)?),
        (CHUNK_TABL, encode_tabl_chunk(&tables)?),
        (CHUNK_MSEL, encode_msel_chunk(&selectors)?),
    ]);

    encode_container(&chunks)
}

pub(super) fn default_runtime_diagnostic_catalog() -> Vec<DiagnosticDescriptor> {
    vec![
        DiagnosticDescriptor {
            code: DIAG_OPTHREAD_MISSING_VM_PROGRAM.to_string(),
            message_template: "missing VM program for {mnemonic}".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_OPTHREAD_INVALID_FORCE_OVERRIDE.to_string(),
            message_template: "Explicit addressing override ',{force}' is not valid for {context}"
                .to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_OPTHREAD_FORCE_UNSUPPORTED_65C02.to_string(),
            message_template: "65816-only addressing mode not supported on 65C02".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_OPTHREAD_FORCE_UNSUPPORTED_6502.to_string(),
            message_template: "65816-only addressing mode not supported on base 6502".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_TOKENIZER_INVALID_CHAR.to_string(),
            message_template: "invalid tokenizer character".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_TOKENIZER_UNTERMINATED_STRING.to_string(),
            message_template: "unterminated string literal".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_TOKENIZER_STEP_LIMIT_EXCEEDED.to_string(),
            message_template: "tokenizer step budget exceeded".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_TOKENIZER_TOKEN_LIMIT_EXCEEDED.to_string(),
            message_template: "tokenizer token budget exceeded".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_TOKENIZER_LEXEME_LIMIT_EXCEEDED.to_string(),
            message_template: "tokenizer lexeme budget exceeded".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_TOKENIZER_ERROR_LIMIT_EXCEEDED.to_string(),
            message_template: "tokenizer diagnostic budget exceeded".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_PARSER_UNEXPECTED_TOKEN.to_string(),
            message_template: "unexpected token".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_PARSER_EXPECTED_EXPRESSION.to_string(),
            message_template: "expected expression".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_PARSER_EXPECTED_OPERAND.to_string(),
            message_template: "expected operand".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_PARSER_INVALID_STATEMENT.to_string(),
            message_template: "invalid statement".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_INVALID_OPCODE.to_string(),
            message_template: "invalid expression VM opcode".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_STACK_UNDERFLOW.to_string(),
            message_template: "expression VM stack underflow".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_STACK_DEPTH_EXCEEDED.to_string(),
            message_template: "expression VM stack depth exceeded".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_UNKNOWN_SYMBOL.to_string(),
            message_template: "undefined expression symbol".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_EVAL_FAILURE.to_string(),
            message_template: "expression VM evaluation failure".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_UNSUPPORTED_FEATURE.to_string(),
            message_template: "expression VM unsupported feature".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_BUDGET_EXCEEDED.to_string(),
            message_template: "expression VM budget exceeded".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_INVALID_PROGRAM.to_string(),
            message_template: "expression VM program is invalid".to_string(),
        },
    ]
}

pub(super) fn decode_hierarchy_chunks(bytes: &[u8]) -> Result<HierarchyChunks, OpcpuCodecError> {
    let toc = parse_toc(bytes)?;
    let meta_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_META)?;
    let strs_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_STRS)?;
    let diag_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_DIAG)?;
    let toks_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_TOKS)?;
    let tkvm_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_TKVM)?;
    let pars_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_PARS)?;
    let prvm_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_PRVM)?;
    let expr_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_EXPR)?;
    let expp_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_EXPP)?;
    let fams_bytes = slice_for_chunk(bytes, &toc, CHUNK_FAMS)?;
    let cpus_bytes = slice_for_chunk(bytes, &toc, CHUNK_CPUS)?;
    let dial_bytes = slice_for_chunk(bytes, &toc, CHUNK_DIAL)?;
    let regs_bytes = slice_for_chunk(bytes, &toc, CHUNK_REGS)?;
    let form_bytes = slice_for_chunk(bytes, &toc, CHUNK_FORM)?;
    let tabl_bytes = slice_for_chunk(bytes, &toc, CHUNK_TABL)?;
    let msel_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_MSEL)?;

    Ok(HierarchyChunks {
        metadata: match meta_bytes {
            Some(payload) => decode_meta_chunk(payload)?,
            None => PackageMetaDescriptor::default(),
        },
        strings: match strs_bytes {
            Some(payload) => decode_strs_chunk(payload)?,
            None => Vec::new(),
        },
        diagnostics: match diag_bytes {
            Some(payload) => decode_diag_chunk(payload)?,
            None => Vec::new(),
        },
        token_policies: match toks_bytes {
            Some(payload) => decode_toks_chunk(payload)?,
            None => Vec::new(),
        },
        tokenizer_vm_programs: match tkvm_bytes {
            Some(payload) => decode_tkvm_chunk(payload)?,
            None => Vec::new(),
        },
        parser_contracts: match pars_bytes {
            Some(payload) => decode_pars_chunk(payload)?,
            None => Vec::new(),
        },
        parser_vm_programs: match prvm_bytes {
            Some(payload) => decode_prvm_chunk(payload)?,
            None => Vec::new(),
        },
        expr_contracts: match expr_bytes {
            Some(payload) => decode_expr_chunk(payload)?,
            None => Vec::new(),
        },
        expr_parser_contracts: match expp_bytes {
            Some(payload) => decode_expp_chunk(payload)?,
            None => Vec::new(),
        },
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

pub(super) fn load_hierarchy_package(bytes: &[u8]) -> Result<HierarchyPackage, OpcpuCodecError> {
    let decoded = decode_hierarchy_chunks(bytes)?;
    HierarchyPackage::new(decoded.families, decoded.cpus, decoded.dialects).map_err(Into::into)
}

pub(super) fn encode_container(chunks: &[([u8; 4], Vec<u8>)]) -> Result<Vec<u8>, OpcpuCodecError> {
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

pub(super) fn parse_toc(bytes: &[u8]) -> Result<HashMap<[u8; 4], TocEntry>, OpcpuCodecError> {
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

pub(super) fn slice_for_chunk<'a>(
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

pub(super) fn slice_for_chunk_optional<'a>(
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

pub(super) fn encode_fams_chunk(families: &[FamilyDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(families.len(), "FAMS count")?);
    for family in families {
        write_string(&mut out, "FAMS", &family.id)?;
        write_string(&mut out, "FAMS", &family.canonical_dialect)?;
    }
    Ok(out)
}

pub(super) fn decode_fams_chunk(bytes: &[u8]) -> Result<Vec<FamilyDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "FAMS");
    let count = read_bounded_count(&mut cur, 8, "family entry")?;
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

pub(super) fn encode_meta_chunk(
    metadata: &PackageMetaDescriptor,
) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_string(&mut out, "META", &metadata.package_id)?;
    write_string(&mut out, "META", &metadata.package_version)?;
    write_u32(&mut out, metadata.capability_flags);
    Ok(out)
}

pub(super) fn decode_meta_chunk(bytes: &[u8]) -> Result<PackageMetaDescriptor, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "META");
    let metadata = PackageMetaDescriptor {
        package_id: cur.read_string()?,
        package_version: cur.read_string()?,
        capability_flags: cur.read_u32()?,
    };
    cur.finish()?;
    Ok(metadata)
}

pub(super) fn encode_strs_chunk(strings: &[String]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(strings.len(), "STRS count")?);
    for entry in strings {
        write_string(&mut out, "STRS", entry)?;
    }
    Ok(out)
}

pub(super) fn decode_strs_chunk(bytes: &[u8]) -> Result<Vec<String>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "STRS");
    let count = read_bounded_count(&mut cur, 4, "string entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(cur.read_string()?);
    }
    cur.finish()?;
    Ok(entries)
}

pub(super) fn encode_diag_chunk(
    diagnostics: &[DiagnosticDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(diagnostics.len(), "DIAG count")?);
    for entry in diagnostics {
        write_string(&mut out, "DIAG", &entry.code)?;
        write_string(&mut out, "DIAG", &entry.message_template)?;
    }
    Ok(out)
}

pub(super) fn decode_diag_chunk(
    bytes: &[u8],
) -> Result<Vec<DiagnosticDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "DIAG");
    let count = read_bounded_count(&mut cur, 8, "diagnostic entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(DiagnosticDescriptor {
            code: cur.read_string()?,
            message_template: cur.read_string()?,
        });
    }
    cur.finish()?;
    Ok(entries)
}

pub(super) fn encode_scoped_owner(
    out: &mut Vec<u8>,
    chunk: &str,
    owner: &ScopedOwner,
) -> Result<(), OpcpuCodecError> {
    out.push(owner.owner_tag());
    write_string(out, chunk, owner.owner_id())
}

pub(super) fn decode_scoped_owner(
    cur: &mut Decoder<'_>,
    chunk: &'static str,
) -> Result<ScopedOwner, OpcpuCodecError> {
    let owner_tag = cur.read_u8()?;
    let owner_id = cur.read_string()?;
    ScopedOwner::from_owner_tag(owner_tag, owner_id).ok_or_else(|| {
        OpcpuCodecError::InvalidChunkFormat {
            chunk: chunk.to_string(),
            detail: format!("invalid owner tag: {}", owner_tag),
        }
    })
}

pub(super) fn encode_toks_chunk(
    policies: &[TokenPolicyDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(policies.len(), "TOKS count")?);
    for entry in policies {
        encode_scoped_owner(&mut out, "TOKS", &entry.owner)?;
        out.push(entry.case_rule as u8);
        write_u32(&mut out, entry.identifier_start_class);
        write_u32(&mut out, entry.identifier_continue_class);
        write_string(&mut out, "TOKS", &entry.punctuation_chars)?;
        out.push(TOKS_EXT_MARKER);
        write_string(&mut out, "TOKS", &entry.comment_prefix)?;
        write_string(&mut out, "TOKS", &entry.quote_chars)?;
        match entry.escape_char {
            Some(ch) if ch.is_ascii() => {
                out.push(1);
                out.push(ch as u8);
            }
            Some(ch) => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "TOKS".to_string(),
                    detail: format!("escape_char must be ASCII: {:?}", ch),
                });
            }
            None => out.push(0),
        }
        write_string(&mut out, "TOKS", &entry.number_prefix_chars)?;
        write_string(&mut out, "TOKS", &entry.number_suffix_binary)?;
        write_string(&mut out, "TOKS", &entry.number_suffix_octal)?;
        write_string(&mut out, "TOKS", &entry.number_suffix_decimal)?;
        write_string(&mut out, "TOKS", &entry.number_suffix_hex)?;
        write_string(&mut out, "TOKS", &entry.operator_chars)?;
        write_u32(
            &mut out,
            u32_count(
                entry.multi_char_operators.len(),
                "TOKS multi-char operator count",
            )?,
        );
        for operator in &entry.multi_char_operators {
            write_string(&mut out, "TOKS", operator)?;
        }
    }
    Ok(out)
}

pub(super) fn decode_toks_chunk(
    bytes: &[u8],
) -> Result<Vec<TokenPolicyDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "TOKS");
    let count = read_bounded_count(&mut cur, 1, "token policy entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "TOKS")?;
        let case_rule = TokenCaseRule::from_u8(cur.read_u8()?, "TOKS")?;
        let identifier_start_class = cur.read_u32()?;
        let identifier_continue_class = cur.read_u32()?;
        let punctuation_chars = cur.read_string()?;
        let defaults = default_token_policy_lexical_defaults();
        let mut comment_prefix = defaults.comment_prefix;
        let mut quote_chars = defaults.quote_chars;
        let mut escape_char = defaults.escape_char;
        let mut number_prefix_chars = defaults.number_prefix_chars;
        let mut number_suffix_binary = defaults.number_suffix_binary;
        let mut number_suffix_octal = defaults.number_suffix_octal;
        let mut number_suffix_decimal = defaults.number_suffix_decimal;
        let mut number_suffix_hex = defaults.number_suffix_hex;
        let mut operator_chars = defaults.operator_chars;
        let mut multi_char_operators = defaults.multi_char_operators;
        if cur.has_remaining() {
            let marker = cur.peek_u8()?;
            if marker == TOKS_EXT_MARKER {
                let _ = cur.read_u8()?;
                comment_prefix = cur.read_string()?;
                quote_chars = cur.read_string()?;
                escape_char = match cur.read_u8()? {
                    0 => None,
                    1 => Some(cur.read_u8()? as char),
                    other => {
                        return Err(OpcpuCodecError::InvalidChunkFormat {
                            chunk: "TOKS".to_string(),
                            detail: format!("invalid bool flag for escape_char: {}", other),
                        });
                    }
                };
                number_prefix_chars = cur.read_string()?;
                number_suffix_binary = cur.read_string()?;
                number_suffix_octal = cur.read_string()?;
                number_suffix_decimal = cur.read_string()?;
                number_suffix_hex = cur.read_string()?;
                operator_chars = cur.read_string()?;
                let operator_count = read_bounded_count(&mut cur, 1, "multi-char operator")?;
                let mut operators = Vec::with_capacity(operator_count);
                for _ in 0..operator_count {
                    operators.push(cur.read_string()?);
                }
                multi_char_operators = operators;
            }
        }
        entries.push(TokenPolicyDescriptor {
            owner,
            case_rule,
            identifier_start_class,
            identifier_continue_class,
            punctuation_chars,
            comment_prefix,
            quote_chars,
            escape_char,
            number_prefix_chars,
            number_suffix_binary,
            number_suffix_octal,
            number_suffix_decimal,
            number_suffix_hex,
            operator_chars,
            multi_char_operators,
        });
    }
    cur.finish()?;
    Ok(entries)
}

pub(super) fn encode_cpus_chunk(cpus: &[CpuDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
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

pub(super) fn decode_cpus_chunk(bytes: &[u8]) -> Result<Vec<CpuDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "CPUS");
    let count = read_bounded_count(&mut cur, 1, "cpu entry")?;
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

pub(super) fn encode_dial_chunk(
    dialects: &[DialectDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
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

pub(super) fn decode_dial_chunk(bytes: &[u8]) -> Result<Vec<DialectDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "DIAL");
    let count = read_bounded_count(&mut cur, 1, "dialect entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let id = cur.read_string()?;
        let family_id = cur.read_string()?;
        let has_allow_list = cur.read_u8()?;
        let cpu_allow_list = match has_allow_list {
            0 => None,
            1 => {
                let allow_count = read_bounded_count(&mut cur, 1, "dialect allow-list entry")?;
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

pub(super) fn encode_regs_chunk(
    registers: &[ScopedRegisterDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(registers.len(), "REGS count")?);
    for register in registers {
        encode_scoped_owner(&mut out, "REGS", &register.owner)?;
        write_string(&mut out, "REGS", &register.id)?;
    }
    Ok(out)
}

pub(super) fn decode_regs_chunk(
    bytes: &[u8],
) -> Result<Vec<ScopedRegisterDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "REGS");
    let count = read_bounded_count(&mut cur, 1, "register entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "REGS")?;
        let id = cur.read_string()?;
        entries.push(ScopedRegisterDescriptor { owner, id });
    }
    cur.finish()?;
    Ok(entries)
}

pub(super) fn encode_form_chunk(
    forms: &[ScopedFormDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(forms.len(), "FORM count")?);
    for form in forms {
        encode_scoped_owner(&mut out, "FORM", &form.owner)?;
        write_string(&mut out, "FORM", &form.mnemonic)?;
    }
    Ok(out)
}

pub(super) fn decode_form_chunk(
    bytes: &[u8],
) -> Result<Vec<ScopedFormDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "FORM");
    let count = read_bounded_count(&mut cur, 1, "form entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "FORM")?;
        let mnemonic = cur.read_string()?;
        entries.push(ScopedFormDescriptor { owner, mnemonic });
    }
    cur.finish()?;
    Ok(entries)
}

pub(super) fn encode_tabl_chunk(
    tables: &[VmProgramDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(tables.len(), "TABL count")?);
    for entry in tables {
        encode_scoped_owner(&mut out, "TABL", &entry.owner)?;
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

pub(super) fn decode_tabl_chunk(bytes: &[u8]) -> Result<Vec<VmProgramDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "TABL");
    let count = read_bounded_count(&mut cur, 1, "table entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "TABL")?;
        let mnemonic = cur.read_string()?;
        let mode_key = cur.read_string()?;
        let byte_count = cur.read_u32()? as usize;
        let program = cur.read_exact(byte_count, "program bytes")?.to_vec();
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

pub(super) fn encode_msel_chunk(
    selectors: &[ModeSelectorDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(selectors.len(), "MSEL count")?);
    for entry in selectors {
        encode_scoped_owner(&mut out, "MSEL", &entry.owner)?;
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

pub(super) fn decode_msel_chunk(
    bytes: &[u8],
) -> Result<Vec<ModeSelectorDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "MSEL");
    let count = read_bounded_count(&mut cur, 1, "mode selector entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "MSEL")?;
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

pub(super) fn encode_tkvm_chunk(
    programs: &[TokenizerVmProgramDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(programs.len(), "TKVM count")?);
    for entry in programs {
        encode_scoped_owner(&mut out, "TKVM", &entry.owner)?;
        write_u16(&mut out, entry.opcode_version);
        write_u16(&mut out, entry.start_state);
        write_u32(
            &mut out,
            u32_count(
                entry.state_entry_offsets.len(),
                "TKVM state_entry_offsets count",
            )?,
        );
        for offset in &entry.state_entry_offsets {
            write_u32(&mut out, *offset);
        }
        write_u32(&mut out, entry.limits.max_steps_per_line);
        write_u32(&mut out, entry.limits.max_tokens_per_line);
        write_u32(&mut out, entry.limits.max_lexeme_bytes);
        write_u32(&mut out, entry.limits.max_errors_per_line);
        write_string(&mut out, "TKVM", &entry.diagnostics.invalid_char)?;
        write_string(&mut out, "TKVM", &entry.diagnostics.unterminated_string)?;
        write_string(&mut out, "TKVM", &entry.diagnostics.step_limit_exceeded)?;
        write_string(&mut out, "TKVM", &entry.diagnostics.token_limit_exceeded)?;
        write_string(&mut out, "TKVM", &entry.diagnostics.lexeme_limit_exceeded)?;
        write_string(&mut out, "TKVM", &entry.diagnostics.error_limit_exceeded)?;
        write_u32(
            &mut out,
            u32_count(entry.program.len(), "TKVM program byte length")?,
        );
        out.extend_from_slice(&entry.program);
    }
    Ok(out)
}

pub(super) fn decode_tkvm_chunk(
    bytes: &[u8],
) -> Result<Vec<TokenizerVmProgramDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "TKVM");
    let count = read_bounded_count(&mut cur, 1, "tokenizer VM entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "TKVM")?;
        let opcode_version = cur.read_u16()?;
        let start_state = cur.read_u16()?;
        let state_count = read_bounded_count(&mut cur, 4, "state-entry offset")?;
        let mut state_entry_offsets = Vec::with_capacity(state_count);
        for _ in 0..state_count {
            state_entry_offsets.push(cur.read_u32()?);
        }
        let limits = TokenizerVmLimits {
            max_steps_per_line: cur.read_u32()?,
            max_tokens_per_line: cur.read_u32()?,
            max_lexeme_bytes: cur.read_u32()?,
            max_errors_per_line: cur.read_u32()?,
        };
        let diagnostics = TokenizerVmDiagnosticMap {
            invalid_char: cur.read_string()?,
            unterminated_string: cur.read_string()?,
            step_limit_exceeded: cur.read_string()?,
            token_limit_exceeded: cur.read_string()?,
            lexeme_limit_exceeded: cur.read_string()?,
            error_limit_exceeded: cur.read_string()?,
        };
        let program_len = cur.read_u32()? as usize;
        let program = cur
            .read_exact(program_len, "tokenizer vm program")?
            .to_vec();
        entries.push(TokenizerVmProgramDescriptor {
            owner,
            opcode_version,
            start_state,
            state_entry_offsets,
            limits,
            diagnostics,
            program,
        });
    }
    cur.finish()?;
    Ok(entries)
}

pub(super) fn encode_pars_chunk(
    contracts: &[ParserContractDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(contracts.len(), "PARS count")?);
    for entry in contracts {
        encode_scoped_owner(&mut out, "PARS", &entry.owner)?;
        write_string(&mut out, "PARS", &entry.grammar_id)?;
        write_string(&mut out, "PARS", &entry.ast_schema_id)?;
        write_u16(&mut out, entry.opcode_version);
        write_u32(&mut out, entry.max_ast_nodes_per_line);
        write_string(&mut out, "PARS", &entry.diagnostics.unexpected_token)?;
        write_string(&mut out, "PARS", &entry.diagnostics.expected_expression)?;
        write_string(&mut out, "PARS", &entry.diagnostics.expected_operand)?;
        write_string(&mut out, "PARS", &entry.diagnostics.invalid_statement)?;
    }
    Ok(out)
}

pub(super) fn decode_pars_chunk(
    bytes: &[u8],
) -> Result<Vec<ParserContractDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "PARS");
    let count = read_bounded_count(&mut cur, 1, "parser contract entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "PARS")?;
        let grammar_id = cur.read_string()?;
        let ast_schema_id = cur.read_string()?;
        let opcode_version = cur.read_u16()?;
        let max_ast_nodes_per_line = cur.read_u32()?;
        let diagnostics = ParserDiagnosticMap {
            unexpected_token: cur.read_string()?,
            expected_expression: cur.read_string()?,
            expected_operand: cur.read_string()?,
            invalid_statement: cur.read_string()?,
        };
        entries.push(ParserContractDescriptor {
            owner,
            grammar_id,
            ast_schema_id,
            opcode_version,
            max_ast_nodes_per_line,
            diagnostics,
        });
    }
    cur.finish()?;
    Ok(entries)
}

pub(super) fn encode_prvm_chunk(
    programs: &[ParserVmProgramDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(programs.len(), "PRVM count")?);
    for entry in programs {
        encode_scoped_owner(&mut out, "PRVM", &entry.owner)?;
        write_u16(&mut out, entry.opcode_version);
        write_u32(
            &mut out,
            u32_count(entry.program.len(), "PRVM program byte length")?,
        );
        out.extend_from_slice(&entry.program);
    }
    Ok(out)
}

pub(super) fn decode_prvm_chunk(
    bytes: &[u8],
) -> Result<Vec<ParserVmProgramDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "PRVM");
    let count = read_bounded_count(&mut cur, 1, "parser VM entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "PRVM")?;
        let opcode_version = cur.read_u16()?;
        let program_len = cur.read_u32()? as usize;
        let program = cur.read_exact(program_len, "parser vm program")?.to_vec();
        entries.push(ParserVmProgramDescriptor {
            owner,
            opcode_version,
            program,
        });
    }
    cur.finish()?;
    Ok(entries)
}

pub(super) fn encode_expr_chunk(
    contracts: &[ExprContractDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(contracts.len(), "EXPR count")?);
    for entry in contracts {
        encode_scoped_owner(&mut out, "EXPR", &entry.owner)?;
        write_u16(&mut out, entry.opcode_version);
        write_u32(&mut out, entry.max_program_bytes);
        write_u32(&mut out, entry.max_stack_depth);
        write_u32(&mut out, entry.max_symbol_refs);
        write_u32(&mut out, entry.max_eval_steps);
        write_string(&mut out, "EXPR", &entry.diagnostics.invalid_opcode)?;
        write_string(&mut out, "EXPR", &entry.diagnostics.stack_underflow)?;
        write_string(&mut out, "EXPR", &entry.diagnostics.stack_depth_exceeded)?;
        write_string(&mut out, "EXPR", &entry.diagnostics.unknown_symbol)?;
        write_string(&mut out, "EXPR", &entry.diagnostics.eval_failure)?;
        write_string(&mut out, "EXPR", &entry.diagnostics.unsupported_feature)?;
        write_string(&mut out, "EXPR", &entry.diagnostics.budget_exceeded)?;
        write_string(&mut out, "EXPR", &entry.diagnostics.invalid_program)?;
    }
    Ok(out)
}

pub(super) fn decode_expr_chunk(
    bytes: &[u8],
) -> Result<Vec<ExprContractDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "EXPR");
    let count = read_bounded_count(&mut cur, 1, "expression contract entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "EXPR")?;
        let opcode_version = cur.read_u16()?;
        let max_program_bytes = cur.read_u32()?;
        let max_stack_depth = cur.read_u32()?;
        let max_symbol_refs = cur.read_u32()?;
        let max_eval_steps = cur.read_u32()?;
        let diagnostics = ExprDiagnosticMap {
            invalid_opcode: cur.read_string()?,
            stack_underflow: cur.read_string()?,
            stack_depth_exceeded: cur.read_string()?,
            unknown_symbol: cur.read_string()?,
            eval_failure: cur.read_string()?,
            unsupported_feature: cur.read_string()?,
            budget_exceeded: cur.read_string()?,
            invalid_program: cur.read_string()?,
        };
        entries.push(ExprContractDescriptor {
            owner,
            opcode_version,
            max_program_bytes,
            max_stack_depth,
            max_symbol_refs,
            max_eval_steps,
            diagnostics,
        });
        if let Some(entry) = entries.last() {
            validate_expr_contract_descriptor(entry)?;
        }
    }
    cur.finish()?;
    Ok(entries)
}

pub(super) fn encode_expp_chunk(
    contracts: &[ExprParserContractDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(contracts.len(), "EXPP count")?);
    for entry in contracts {
        encode_scoped_owner(&mut out, "EXPP", &entry.owner)?;
        write_u16(&mut out, entry.opcode_version);
        write_string(
            &mut out,
            "EXPP",
            &entry.diagnostics.invalid_expression_program,
        )?;
    }
    Ok(out)
}

pub(super) fn decode_expp_chunk(
    bytes: &[u8],
) -> Result<Vec<ExprParserContractDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "EXPP");
    let count = read_bounded_count(&mut cur, 1, "expression parser contract entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "EXPP")?;
        let opcode_version = cur.read_u16()?;
        let diagnostics = ExprParserDiagnosticMap {
            invalid_expression_program: cur.read_string()?,
        };
        entries.push(ExprParserContractDescriptor {
            owner,
            opcode_version,
            diagnostics,
        });
        if let Some(entry) = entries.last() {
            validate_expr_parser_contract_descriptor(entry)?;
        }
    }
    cur.finish()?;
    Ok(entries)
}

pub(super) fn validate_expr_contract_descriptor(
    descriptor: &ExprContractDescriptor,
) -> Result<(), OpcpuCodecError> {
    if descriptor.opcode_version != EXPR_VM_OPCODE_VERSION_V1 {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: "EXPR".to_string(),
            detail: format!("unsupported opcode_version: {}", descriptor.opcode_version),
        });
    }

    if descriptor.max_program_bytes == 0 {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: "EXPR".to_string(),
            detail: "max_program_bytes must be > 0".to_string(),
        });
    }
    if descriptor.max_stack_depth == 0 {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: "EXPR".to_string(),
            detail: "max_stack_depth must be > 0".to_string(),
        });
    }
    if descriptor.max_symbol_refs == 0 {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: "EXPR".to_string(),
            detail: "max_symbol_refs must be > 0".to_string(),
        });
    }
    if descriptor.max_eval_steps == 0 {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: "EXPR".to_string(),
            detail: "max_eval_steps must be > 0".to_string(),
        });
    }

    let diagnostics = &descriptor.diagnostics;
    let required_codes = [
        (
            "diagnostics.invalid_opcode",
            diagnostics.invalid_opcode.as_str(),
        ),
        (
            "diagnostics.stack_underflow",
            diagnostics.stack_underflow.as_str(),
        ),
        (
            "diagnostics.stack_depth_exceeded",
            diagnostics.stack_depth_exceeded.as_str(),
        ),
        (
            "diagnostics.unknown_symbol",
            diagnostics.unknown_symbol.as_str(),
        ),
        (
            "diagnostics.eval_failure",
            diagnostics.eval_failure.as_str(),
        ),
        (
            "diagnostics.unsupported_feature",
            diagnostics.unsupported_feature.as_str(),
        ),
        (
            "diagnostics.budget_exceeded",
            diagnostics.budget_exceeded.as_str(),
        ),
        (
            "diagnostics.invalid_program",
            diagnostics.invalid_program.as_str(),
        ),
    ];
    for (name, code) in required_codes {
        if code.trim().is_empty() {
            return Err(OpcpuCodecError::InvalidChunkFormat {
                chunk: "EXPR".to_string(),
                detail: format!("missing {} code", name),
            });
        }
    }

    Ok(())
}

pub(super) fn validate_expr_parser_contract_descriptor(
    descriptor: &ExprParserContractDescriptor,
) -> Result<(), OpcpuCodecError> {
    if descriptor.opcode_version != EXPR_PARSER_VM_OPCODE_VERSION_V1 {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: "EXPP".to_string(),
            detail: format!("unsupported opcode_version: {}", descriptor.opcode_version),
        });
    }

    if descriptor
        .diagnostics
        .invalid_expression_program
        .trim()
        .is_empty()
    {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: "EXPP".to_string(),
            detail: "missing diagnostics.invalid_expression_program code".to_string(),
        });
    }

    Ok(())
}

pub(super) fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn write_string(
    out: &mut Vec<u8>,
    chunk: &str,
    value: &str,
) -> Result<(), OpcpuCodecError> {
    let len = u32::try_from(value.len()).map_err(|_| OpcpuCodecError::CountOutOfRange {
        context: format!("{} string length exceeds u32", chunk),
    })?;
    write_u32(out, len);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

pub(super) fn u32_count(count: usize, context: &str) -> Result<u32, OpcpuCodecError> {
    u32::try_from(count).map_err(|_| OpcpuCodecError::CountOutOfRange {
        context: context.to_string(),
    })
}

pub(super) fn chunk_name(tag: &[u8; 4]) -> String {
    std::str::from_utf8(tag)
        .map(|value| value.to_string())
        .unwrap_or_else(|_| format!("{:02X?}", tag))
}

pub(super) fn read_bounded_count(
    cur: &mut Decoder<'_>,
    min_record_bytes: usize,
    detail: &str,
) -> Result<usize, OpcpuCodecError> {
    let count = cur.read_u32()? as usize;
    if min_record_bytes == 0 {
        if count > MAX_DECODE_ENTRY_COUNT {
            return Err(OpcpuCodecError::InvalidChunkFormat {
                chunk: cur.chunk.to_string(),
                detail: format!(
                    "{} count {} exceeds hard limit {}",
                    detail, count, MAX_DECODE_ENTRY_COUNT
                ),
            });
        }
        return Ok(count);
    }

    let max_by_payload = cur.remaining_len() / min_record_bytes;
    if count > MAX_DECODE_ENTRY_COUNT {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: cur.chunk.to_string(),
            detail: format!(
                "{} count {} exceeds hard limit {}",
                detail, count, MAX_DECODE_ENTRY_COUNT
            ),
        });
    }

    if count > max_by_payload {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: cur.chunk.to_string(),
            detail: format!(
                "{} count {} exceeds remaining payload bound {}",
                detail, count, max_by_payload
            ),
        });
    }

    Ok(count)
}

pub(super) struct Decoder<'a> {
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

    fn peek_u8(&self) -> Result<u8, OpcpuCodecError> {
        self.bytes
            .get(self.pos)
            .copied()
            .ok_or_else(|| OpcpuCodecError::UnexpectedEof {
                context: format!("chunk {} u8", self.chunk),
            })
    }

    fn has_remaining(&self) -> bool {
        self.pos < self.bytes.len()
    }

    fn remaining_len(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn read_u32(&mut self) -> Result<u32, OpcpuCodecError> {
        let slice = self.read_exact(4, "u32")?;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    fn read_u16(&mut self) -> Result<u16, OpcpuCodecError> {
        let slice = self.read_exact(2, "u16")?;
        Ok(u16::from_le_bytes([slice[0], slice[1]]))
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
