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
