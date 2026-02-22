use super::*;

impl HierarchyExecutionModel {
    pub fn tokenize_portable_statement(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        source_line: &str,
        line_num: u32,
    ) -> Result<Vec<PortableToken>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        let request = PortableTokenizeRequest {
            family_id: resolved.family_id.as_str(),
            cpu_id: resolved.cpu_id.as_str(),
            dialect_id: resolved.dialect_id.as_str(),
            source_line,
            line_num,
            token_policy: self.token_policy_for_resolved(&resolved),
        };
        match self.effective_tokenizer_mode() {
            RuntimeTokenizerMode::Auto | RuntimeTokenizerMode::Vm => {
                let vm_program = self
                    .tokenizer_vm_program_for_resolved(&resolved)
                    .ok_or_else(|| {
                        RuntimeBridgeError::Resolve(format!(
                            "missing opThread tokenizer VM program for family '{}'",
                            resolved.family_id
                        ))
                    })?;
                let tokens = self.tokenize_with_vm_core(&request, vm_program)?;
                if tokens.is_empty()
                    && !source_line_can_tokenize_to_empty(source_line, &request.token_policy)
                {
                    return Err(RuntimeBridgeError::Resolve(format!(
                        "{}: tokenizer VM produced no tokens for non-empty source line",
                        vm_program.diagnostics.invalid_char
                    )));
                }
                Ok(tokens)
            }
        }
    }

    pub fn tokenize_portable_statement_for_assembler(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        source_line: &str,
        line_num: u32,
    ) -> Result<Vec<PortableToken>, RuntimeBridgeError> {
        self.tokenize_portable_statement_vm_authoritative(
            cpu_id,
            dialect_override,
            source_line,
            line_num,
        )
    }

    pub fn tokenize_portable_statement_vm_authoritative(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        source_line: &str,
        line_num: u32,
    ) -> Result<Vec<PortableToken>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        let request = PortableTokenizeRequest {
            family_id: resolved.family_id.as_str(),
            cpu_id: resolved.cpu_id.as_str(),
            dialect_id: resolved.dialect_id.as_str(),
            source_line,
            line_num,
            token_policy: self.token_policy_for_resolved(&resolved),
        };
        let vm_program = self
            .tokenizer_vm_program_for_resolved(&resolved)
            .ok_or_else(|| {
                RuntimeBridgeError::Resolve(format!(
                    "missing opThread tokenizer VM program for family '{}'",
                    resolved.family_id
                ))
            })?;
        let tokens = self.tokenize_with_vm_core(&request, vm_program)?;
        if tokens.is_empty()
            && !source_line_can_tokenize_to_empty(source_line, &request.token_policy)
        {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: tokenizer VM produced no tokens for non-empty source line",
                vm_program.diagnostics.invalid_char
            )));
        }
        Ok(tokens)
    }

    pub fn resolve_tokenizer_vm_program(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<Option<RuntimeTokenizerVmProgram>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        Ok(self.tokenizer_vm_program_for_resolved(&resolved).cloned())
    }

    pub fn resolve_tokenizer_vm_limits(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<TokenizerVmLimits, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        Ok(self
            .tokenizer_vm_program_for_resolved(&resolved)
            .map(|entry| entry.limits)
            .unwrap_or_default())
    }

    pub(super) fn token_policy_for_resolved(
        &self,
        resolved: &ResolvedHierarchy,
    ) -> RuntimeTokenPolicy {
        self.lookup_scoped(&self.token_policies, resolved)
            .cloned()
            .unwrap_or_default()
    }

    fn effective_tokenizer_mode(&self) -> RuntimeTokenizerMode {
        match self.tokenizer_mode {
            RuntimeTokenizerMode::Auto => RuntimeTokenizerMode::Vm,
            mode => mode,
        }
    }

    fn tokenizer_vm_program_for_resolved(
        &self,
        resolved: &ResolvedHierarchy,
    ) -> Option<&RuntimeTokenizerVmProgram> {
        self.lookup_scoped(&self.tokenizer_vm_programs, resolved)
    }

    fn ensure_tokenizer_vm_program_compatible_for_assembler(
        &self,
        vm_program: &RuntimeTokenizerVmProgram,
    ) -> Result<(), RuntimeBridgeError> {
        let error_code = tokenizer_vm_error_code(vm_program);
        if vm_program.opcode_version != TOKENIZER_VM_OPCODE_VERSION_V1 {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: unsupported tokenizer VM opcode version {}",
                error_code, vm_program.opcode_version
            )));
        }
        for (field_name, value) in [
            ("invalid_char", vm_program.diagnostics.invalid_char.as_str()),
            (
                "unterminated_string",
                vm_program.diagnostics.unterminated_string.as_str(),
            ),
            (
                "step_limit_exceeded",
                vm_program.diagnostics.step_limit_exceeded.as_str(),
            ),
            (
                "token_limit_exceeded",
                vm_program.diagnostics.token_limit_exceeded.as_str(),
            ),
            (
                "lexeme_limit_exceeded",
                vm_program.diagnostics.lexeme_limit_exceeded.as_str(),
            ),
            (
                "error_limit_exceeded",
                vm_program.diagnostics.error_limit_exceeded.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(RuntimeBridgeError::Resolve(format!(
                    "{}: missing tokenizer VM diagnostic mapping for '{}'",
                    error_code, field_name
                )));
            }
            self.ensure_diag_code_declared_in_package_catalog(error_code, "tokenizer VM", value)?;
        }
        Ok(())
    }

    pub(super) fn tokenize_with_vm_core(
        &self,
        request: &PortableTokenizeRequest<'_>,
        vm_program: &RuntimeTokenizerVmProgram,
    ) -> Result<Vec<PortableToken>, RuntimeBridgeError> {
        self.ensure_tokenizer_vm_program_compatible_for_assembler(vm_program)?;
        if vm_program.state_entry_offsets.is_empty() {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: tokenizer VM state table is empty",
                vm_program.diagnostics.invalid_char
            )));
        }
        let start_state = usize::from(vm_program.start_state);
        let Some(start_offset) = vm_program.state_entry_offsets.get(start_state).copied() else {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: tokenizer VM start state {} out of range",
                vm_program.diagnostics.invalid_char, vm_program.start_state
            )));
        };

        let bytes = request.source_line.as_bytes();
        let max_steps_per_line = vm_program
            .limits
            .max_steps_per_line
            .min(self.budget_limits.max_tokenizer_steps_per_line);
        let max_tokens_per_line = vm_program
            .limits
            .max_tokens_per_line
            .min(self.budget_limits.max_tokenizer_tokens_per_line);
        let max_lexeme_bytes = vm_program
            .limits
            .max_lexeme_bytes
            .min(self.budget_limits.max_tokenizer_lexeme_bytes);
        let max_errors_per_line = vm_program
            .limits
            .max_errors_per_line
            .min(self.budget_limits.max_tokenizer_errors_per_line);
        let max_lexeme_bytes_usize = usize::try_from(max_lexeme_bytes).unwrap_or(usize::MAX);
        let max_tokens_per_line_usize = usize::try_from(max_tokens_per_line).unwrap_or(usize::MAX);
        let lexeme_capacity = max_lexeme_bytes_usize.min(bytes.len());
        let token_capacity = max_tokens_per_line_usize.min(bytes.len().saturating_add(1));
        let mut pc = vm_offset_to_pc(
            vm_program.program.as_slice(),
            start_offset,
            vm_program.diagnostics.invalid_char.as_str(),
            "start state offset",
        )?;
        let mut cursor = 0usize;
        let mut current_byte: Option<u8> = None;
        let mut lexeme = Vec::with_capacity(lexeme_capacity);
        let mut lexeme_start = 0usize;
        let mut lexeme_end = 0usize;
        let mut tokens = Vec::with_capacity(token_capacity);
        let mut emitted_errors = 0u32;
        let mut step_count = 0u32;
        let mut core_tokenizer: Option<Tokenizer<'_>> = None;

        loop {
            step_count = step_count.saturating_add(1);
            if step_count > max_steps_per_line {
                return Err(RuntimeBridgeError::Resolve(format!(
                    "{}: tokenizer VM step budget exceeded ({}/{})",
                    vm_program.diagnostics.step_limit_exceeded, step_count, max_steps_per_line
                )));
            }

            let opcode_byte = vm_read_u8(
                vm_program.program.as_slice(),
                &mut pc,
                vm_program.diagnostics.invalid_char.as_str(),
                "opcode",
            )?;
            let Some(opcode) = TokenizerVmOpcode::from_u8(opcode_byte) else {
                return Err(RuntimeBridgeError::Resolve(format!(
                    "{}: unknown tokenizer VM opcode 0x{:02X}",
                    vm_program.diagnostics.invalid_char, opcode_byte
                )));
            };

            match opcode {
                TokenizerVmOpcode::End => break,
                TokenizerVmOpcode::ReadChar => {
                    current_byte = bytes.get(cursor).copied();
                }
                TokenizerVmOpcode::Advance => {
                    if cursor < bytes.len() {
                        cursor += 1;
                    }
                }
                TokenizerVmOpcode::StartLexeme => {
                    lexeme.clear();
                    lexeme_start = cursor;
                    lexeme_end = cursor;
                }
                TokenizerVmOpcode::PushChar => {
                    let Some(byte) = current_byte else {
                        return Err(RuntimeBridgeError::Resolve(format!(
                            "{}: PushChar requires ReadChar at non-EOL",
                            vm_program.diagnostics.invalid_char
                        )));
                    };
                    if lexeme.len() >= max_lexeme_bytes_usize {
                        return Err(RuntimeBridgeError::Resolve(format!(
                            "{}: tokenizer VM lexeme budget exceeded ({}/{})",
                            vm_program.diagnostics.lexeme_limit_exceeded,
                            lexeme.len().saturating_add(1),
                            max_lexeme_bytes
                        )));
                    }
                    lexeme.push(byte);
                    lexeme_end = cursor.saturating_add(1);
                }
                TokenizerVmOpcode::EmitToken => {
                    let token_kind = vm_read_u8(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "emit token kind",
                    )?;
                    if tokens.len() >= max_tokens_per_line_usize {
                        return Err(RuntimeBridgeError::Resolve(format!(
                            "{}: tokenizer VM token budget exceeded ({}/{})",
                            vm_program.diagnostics.token_limit_exceeded,
                            tokens.len().saturating_add(1),
                            max_tokens_per_line
                        )));
                    }
                    let token = vm_build_token(
                        token_kind,
                        lexeme.as_slice(),
                        request.line_num,
                        lexeme_start,
                        lexeme_end,
                        cursor,
                    )?;
                    tokens.push(apply_token_policy_to_token(token, &request.token_policy));
                }
                TokenizerVmOpcode::SetState => {
                    let state = usize::from(vm_read_u16(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "state index",
                    )?);
                    let Some(offset) = vm_program.state_entry_offsets.get(state).copied() else {
                        return Err(RuntimeBridgeError::Resolve(format!(
                            "{}: state index {} out of range",
                            vm_program.diagnostics.invalid_char, state
                        )));
                    };
                    pc = vm_offset_to_pc(
                        vm_program.program.as_slice(),
                        offset,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "state entry offset",
                    )?;
                }
                TokenizerVmOpcode::Jump => {
                    let target = vm_read_u32(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "jump target",
                    )?;
                    pc = vm_offset_to_pc(
                        vm_program.program.as_slice(),
                        target,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "jump target",
                    )?;
                }
                TokenizerVmOpcode::JumpIfEol => {
                    let target = vm_read_u32(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "conditional jump target",
                    )?;
                    if cursor >= bytes.len() {
                        pc = vm_offset_to_pc(
                            vm_program.program.as_slice(),
                            target,
                            vm_program.diagnostics.invalid_char.as_str(),
                            "conditional jump target",
                        )?;
                    }
                }
                TokenizerVmOpcode::JumpIfByteEq => {
                    let expected = vm_read_u8(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "expected byte",
                    )?;
                    let target = vm_read_u32(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "conditional jump target",
                    )?;
                    if current_byte.is_some_and(|byte| byte == expected) {
                        pc = vm_offset_to_pc(
                            vm_program.program.as_slice(),
                            target,
                            vm_program.diagnostics.invalid_char.as_str(),
                            "conditional jump target",
                        )?;
                    }
                }
                TokenizerVmOpcode::JumpIfClass => {
                    let class = vm_read_u8(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "character class",
                    )?;
                    let target = vm_read_u32(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "conditional jump target",
                    )?;
                    if vm_char_class_matches(current_byte, class, &request.token_policy) {
                        pc = vm_offset_to_pc(
                            vm_program.program.as_slice(),
                            target,
                            vm_program.diagnostics.invalid_char.as_str(),
                            "conditional jump target",
                        )?;
                    }
                }
                TokenizerVmOpcode::Fail => {
                    let reason = vm_read_u8(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "failure reason",
                    )?;
                    return Err(RuntimeBridgeError::Resolve(format!(
                        "{}: tokenizer VM failure reason {}",
                        vm_program.diagnostics.invalid_char, reason
                    )));
                }
                TokenizerVmOpcode::EmitDiag => {
                    let slot = vm_read_u8(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "diagnostic slot",
                    )?;
                    emitted_errors = emitted_errors.saturating_add(1);
                    if emitted_errors > max_errors_per_line {
                        return Err(RuntimeBridgeError::Resolve(format!(
                            "{}: tokenizer VM diagnostic budget exceeded ({}/{})",
                            vm_program.diagnostics.error_limit_exceeded,
                            emitted_errors,
                            max_errors_per_line
                        )));
                    }
                    let code = vm_diag_code_for_slot(&vm_program.diagnostics, slot);
                    return Err(RuntimeBridgeError::Resolve(format!(
                        "{}: tokenizer VM emitted diagnostic slot {}",
                        code, slot
                    )));
                }
                TokenizerVmOpcode::DelegateCore => {
                    return Err(RuntimeBridgeError::Resolve(format!(
                        "{}: tokenizer VM DelegateCore opcode is forbidden in VM tokenizer execution mode",
                        vm_program.diagnostics.invalid_char
                    )));
                }
                TokenizerVmOpcode::ScanCoreToken => {
                    match vm_scan_next_core_token(request, cursor, &mut core_tokenizer)? {
                        Some((portable, next_cursor)) => {
                            if tokens.len() >= max_tokens_per_line_usize {
                                return Err(RuntimeBridgeError::Resolve(format!(
                                    "{}: tokenizer VM token budget exceeded ({}/{})",
                                    vm_program.diagnostics.token_limit_exceeded,
                                    tokens.len().saturating_add(1),
                                    max_tokens_per_line
                                )));
                            }
                            let lexeme_len = vm_token_lexeme_len(&portable);
                            if lexeme_len > max_lexeme_bytes_usize {
                                return Err(RuntimeBridgeError::Resolve(format!(
                                    "{}: tokenizer VM lexeme budget exceeded ({}/{})",
                                    vm_program.diagnostics.lexeme_limit_exceeded,
                                    lexeme_len,
                                    max_lexeme_bytes
                                )));
                            }
                            tokens
                                .push(apply_token_policy_to_token(portable, &request.token_policy));
                            cursor = next_cursor;
                            current_byte = bytes.get(cursor).copied();
                        }
                        None => {
                            cursor = bytes.len();
                            current_byte = None;
                        }
                    }
                }
            }
        }

        Ok(tokens)
    }
}

fn tokenizer_vm_error_code(program: &RuntimeTokenizerVmProgram) -> &str {
    let code = program.diagnostics.invalid_char.trim();
    if code.is_empty() {
        "opthread-runtime"
    } else {
        code
    }
}

fn vm_diag_code_for_slot(diagnostics: &TokenizerVmDiagnosticMap, slot: u8) -> &str {
    match slot {
        0 => diagnostics.invalid_char.as_str(),
        1 => diagnostics.unterminated_string.as_str(),
        2 => diagnostics.step_limit_exceeded.as_str(),
        3 => diagnostics.token_limit_exceeded.as_str(),
        4 => diagnostics.lexeme_limit_exceeded.as_str(),
        5 => diagnostics.error_limit_exceeded.as_str(),
        _ => diagnostics.invalid_char.as_str(),
    }
}

fn source_line_can_tokenize_to_empty(source_line: &str, policy: &RuntimeTokenPolicy) -> bool {
    let trimmed = source_line.trim_start();
    trimmed.is_empty()
        || (!policy.comment_prefix.is_empty()
            && trimmed.starts_with(policy.comment_prefix.as_str()))
}

fn vm_read_u8(
    program: &[u8],
    pc: &mut usize,
    diag_code: &str,
    context: &str,
) -> Result<u8, RuntimeBridgeError> {
    let Some(value) = program.get(*pc).copied() else {
        return Err(RuntimeBridgeError::Resolve(format!(
            "{}: tokenizer VM truncated while reading {}",
            diag_code, context
        )));
    };
    *pc += 1;
    Ok(value)
}

fn vm_read_u16(
    program: &[u8],
    pc: &mut usize,
    diag_code: &str,
    context: &str,
) -> Result<u16, RuntimeBridgeError> {
    let lo = vm_read_u8(program, pc, diag_code, context)?;
    let hi = vm_read_u8(program, pc, diag_code, context)?;
    Ok(u16::from_le_bytes([lo, hi]))
}

fn vm_read_u32(
    program: &[u8],
    pc: &mut usize,
    diag_code: &str,
    context: &str,
) -> Result<u32, RuntimeBridgeError> {
    let b0 = vm_read_u8(program, pc, diag_code, context)?;
    let b1 = vm_read_u8(program, pc, diag_code, context)?;
    let b2 = vm_read_u8(program, pc, diag_code, context)?;
    let b3 = vm_read_u8(program, pc, diag_code, context)?;
    Ok(u32::from_le_bytes([b0, b1, b2, b3]))
}

fn vm_offset_to_pc(
    program: &[u8],
    offset: u32,
    diag_code: &str,
    context: &str,
) -> Result<usize, RuntimeBridgeError> {
    let offset = usize::try_from(offset).map_err(|_| {
        RuntimeBridgeError::Resolve(format!(
            "{}: tokenizer VM {} exceeds host address range",
            diag_code, context
        ))
    })?;
    if offset > program.len() {
        return Err(RuntimeBridgeError::Resolve(format!(
            "{}: tokenizer VM {} {} exceeds program length {}",
            diag_code,
            context,
            offset,
            program.len()
        )));
    }
    Ok(offset)
}

fn vm_scan_next_core_token<'a>(
    request: &PortableTokenizeRequest<'a>,
    cursor: usize,
    tokenizer: &mut Option<Tokenizer<'a>>,
) -> Result<Option<(PortableToken, usize)>, RuntimeBridgeError> {
    if cursor >= request.source_line.len() {
        return Ok(None);
    }

    if tokenizer.is_none() {
        *tokenizer = Some(Tokenizer::new(request.source_line, request.line_num));
    }
    let Some(tokenizer) = tokenizer.as_mut() else {
        return Ok(None);
    };
    loop {
        let token = tokenizer
            .next_token()
            .map_err(|err| RuntimeBridgeError::Resolve(err.message))?;
        let token_end = token.span.col_end.saturating_sub(1);
        if token_end <= cursor {
            if matches!(token.kind, TokenKind::End) {
                return Ok(None);
            }
            continue;
        }
        if matches!(token.kind, TokenKind::End) {
            return Ok(None);
        }
        if let Some(portable) = PortableToken::from_core_token(token) {
            return Ok(Some((portable, token_end)));
        }
        return Ok(None);
    }
}

fn vm_token_lexeme_len(token: &PortableToken) -> usize {
    match &token.kind {
        PortableTokenKind::Identifier(name) | PortableTokenKind::Register(name) => name.len(),
        PortableTokenKind::Number { text, .. } => text.len(),
        PortableTokenKind::String { bytes, .. } => bytes.len(),
        PortableTokenKind::Comma
        | PortableTokenKind::Colon
        | PortableTokenKind::Dollar
        | PortableTokenKind::Dot
        | PortableTokenKind::Hash
        | PortableTokenKind::Question
        | PortableTokenKind::OpenBracket
        | PortableTokenKind::CloseBracket
        | PortableTokenKind::OpenBrace
        | PortableTokenKind::CloseBrace
        | PortableTokenKind::OpenParen
        | PortableTokenKind::CloseParen => 1,
        PortableTokenKind::Operator(op) => match op {
            PortableOperatorKind::Power
            | PortableOperatorKind::Shl
            | PortableOperatorKind::Shr
            | PortableOperatorKind::LogicAnd
            | PortableOperatorKind::LogicOr
            | PortableOperatorKind::LogicXor
            | PortableOperatorKind::Eq
            | PortableOperatorKind::Ne
            | PortableOperatorKind::Ge
            | PortableOperatorKind::Le => 2,
            _ => 1,
        },
    }
}

fn vm_char_class_matches(byte: Option<u8>, class: u8, policy: &RuntimeTokenPolicy) -> bool {
    let Some(byte) = byte else {
        return false;
    };
    let ch = byte as char;
    match class {
        VM_CHAR_CLASS_WHITESPACE => ch.is_ascii_whitespace(),
        VM_CHAR_CLASS_IDENTIFIER_START => {
            vm_matches_identifier_start_class(byte, policy.identifier_start_class)
        }
        VM_CHAR_CLASS_IDENTIFIER_CONTINUE => {
            vm_matches_identifier_continue_class(byte, policy.identifier_continue_class)
        }
        VM_CHAR_CLASS_DIGIT => ch.is_ascii_digit(),
        VM_CHAR_CLASS_QUOTE => policy.quote_chars.as_bytes().contains(&byte),
        VM_CHAR_CLASS_PUNCTUATION => policy.punctuation_chars.as_bytes().contains(&byte),
        VM_CHAR_CLASS_OPERATOR => policy.operator_chars.as_bytes().contains(&byte),
        _ => false,
    }
}

fn vm_matches_identifier_start_class(byte: u8, class_mask: u32) -> bool {
    let is_alpha = (class_mask & crate::opthread::package::token_identifier_class::ASCII_ALPHA)
        != 0
        && (byte as char).is_ascii_alphabetic();
    let is_underscore = (class_mask & crate::opthread::package::token_identifier_class::UNDERSCORE)
        != 0
        && byte == b'_';
    let is_dot =
        (class_mask & crate::opthread::package::token_identifier_class::DOT) != 0 && byte == b'.';
    is_alpha || is_underscore || is_dot
}

fn vm_matches_identifier_continue_class(byte: u8, class_mask: u32) -> bool {
    let ch = byte as char;
    let is_alpha = (class_mask & crate::opthread::package::token_identifier_class::ASCII_ALPHA)
        != 0
        && ch.is_ascii_alphabetic();
    let is_digit = (class_mask & crate::opthread::package::token_identifier_class::ASCII_DIGIT)
        != 0
        && ch.is_ascii_digit();
    let is_underscore = (class_mask & crate::opthread::package::token_identifier_class::UNDERSCORE)
        != 0
        && byte == b'_';
    let is_dollar = (class_mask & crate::opthread::package::token_identifier_class::DOLLAR) != 0
        && byte == b'$';
    let is_at = (class_mask & crate::opthread::package::token_identifier_class::AT_SIGN) != 0
        && byte == b'@';
    let is_dot =
        (class_mask & crate::opthread::package::token_identifier_class::DOT) != 0 && byte == b'.';
    is_alpha || is_digit || is_underscore || is_dollar || is_at || is_dot
}

fn vm_build_token(
    kind_code: u8,
    lexeme: &[u8],
    line_num: u32,
    lexeme_start: usize,
    lexeme_end: usize,
    cursor: usize,
) -> Result<PortableToken, RuntimeBridgeError> {
    let span_start = if lexeme_end > lexeme_start {
        lexeme_start
    } else {
        cursor
    };
    let span_end = if lexeme_end > lexeme_start {
        lexeme_end
    } else {
        cursor.saturating_add(1)
    };
    let span = PortableSpan {
        line: line_num,
        col_start: span_start.saturating_add(1),
        col_end: span_end.saturating_add(1),
    };
    let kind = match kind_code {
        VM_TOKEN_KIND_IDENTIFIER => {
            PortableTokenKind::Identifier(String::from_utf8_lossy(lexeme).to_string())
        }
        VM_TOKEN_KIND_REGISTER => {
            PortableTokenKind::Register(String::from_utf8_lossy(lexeme).to_string())
        }
        VM_TOKEN_KIND_NUMBER => {
            let upper = String::from_utf8_lossy(lexeme).to_ascii_uppercase();
            let base = if upper.starts_with('$') {
                16
            } else if upper.starts_with('%') {
                2
            } else if upper.ends_with('H') {
                16
            } else if upper.ends_with('B') {
                2
            } else if upper.ends_with('O') || upper.ends_with('Q') {
                8
            } else {
                10
            };
            PortableTokenKind::Number { text: upper, base }
        }
        VM_TOKEN_KIND_STRING => PortableTokenKind::String {
            raw: String::from_utf8_lossy(lexeme).to_string(),
            bytes: lexeme.to_vec(),
        },
        VM_TOKEN_KIND_COMMA => PortableTokenKind::Comma,
        VM_TOKEN_KIND_COLON => PortableTokenKind::Colon,
        VM_TOKEN_KIND_DOLLAR => PortableTokenKind::Dollar,
        VM_TOKEN_KIND_DOT => PortableTokenKind::Dot,
        VM_TOKEN_KIND_HASH => PortableTokenKind::Hash,
        VM_TOKEN_KIND_QUESTION => PortableTokenKind::Question,
        VM_TOKEN_KIND_OPEN_BRACKET => PortableTokenKind::OpenBracket,
        VM_TOKEN_KIND_CLOSE_BRACKET => PortableTokenKind::CloseBracket,
        VM_TOKEN_KIND_OPEN_BRACE => PortableTokenKind::OpenBrace,
        VM_TOKEN_KIND_CLOSE_BRACE => PortableTokenKind::CloseBrace,
        VM_TOKEN_KIND_OPEN_PAREN => PortableTokenKind::OpenParen,
        VM_TOKEN_KIND_CLOSE_PAREN => PortableTokenKind::CloseParen,
        _ => {
            return Err(RuntimeBridgeError::Resolve(format!(
                "unknown tokenizer VM token kind {}",
                kind_code
            )))
        }
    };
    Ok(PortableToken { kind, span })
}

pub(super) fn apply_token_policy_to_token(
    token: PortableToken,
    policy: &RuntimeTokenPolicy,
) -> PortableToken {
    let kind = match token.kind {
        PortableTokenKind::Identifier(name) => {
            PortableTokenKind::Identifier(apply_identifier_case_rule(name, policy.case_rule))
        }
        PortableTokenKind::Register(name) => {
            PortableTokenKind::Register(apply_identifier_case_rule(name, policy.case_rule))
        }
        other => other,
    };
    PortableToken {
        kind,
        span: token.span,
    }
}

fn apply_identifier_case_rule(name: String, rule: TokenCaseRule) -> String {
    match rule {
        TokenCaseRule::Preserve => name,
        TokenCaseRule::AsciiLower => name.to_ascii_lowercase(),
        TokenCaseRule::AsciiUpper => name.to_ascii_uppercase(),
    }
}
