// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Instruction processing for `AsmLine`.
//!
//! Handles instruction encoding, VM runtime dispatch, dialect‐fixit
//! hints, and "instruction not found" diagnostics.

use super::*;

impl<'a> AsmLine<'a> {
    pub(super) fn process_instruction_ast(
        &mut self,
        mnemonic: &str,
        operands: &[Expr],
    ) -> LineStatus {
        let pipeline = match Self::resolve_pipeline_for_cpu(self.registry, self.cpu) {
            Ok(pipeline) => pipeline,
            Err(message) => {
                return self.failure(LineStatus::Error, AsmErrorKind::Instruction, &message, None)
            }
        };

        let family_operands = match pipeline.family.parse_operands(mnemonic, operands) {
            Ok(ops) => ops,
            Err(err) => {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    &err.message,
                    None,
                    err.span,
                )
            }
        };

        let (mapped_mnemonic, mapped_operands) = pipeline
            .dialect
            .map_mnemonic(mnemonic, family_operands.as_ref())
            .unwrap_or_else(|| (mnemonic.to_string(), family_operands.clone()));

        if let Some(status) = self.try_encode_instruction_via_runtime_expr(
            &pipeline,
            mnemonic,
            operands,
            family_operands.as_ref(),
            &mapped_mnemonic,
            mapped_operands.as_ref(),
        ) {
            return status;
        }

        match pipeline.family.encode_family_operands(
            &mapped_mnemonic,
            mnemonic,
            mapped_operands.as_ref(),
            self,
        ) {
            crate::core::family::FamilyEncodeResult::Ok(bytes) => {
                if let Err(err) =
                    self.validate_instruction_emit_span(&mapped_mnemonic, operands, bytes.len())
                {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        err.error.message(),
                        None,
                        err.span,
                    );
                }
                self.bytes.extend_from_slice(&bytes);
                return LineStatus::Ok;
            }
            crate::core::family::FamilyEncodeResult::Error {
                bytes,
                message,
                span,
                param,
            } => {
                self.bytes.extend_from_slice(&bytes);
                if let Some(span) = span {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        &message,
                        param.as_deref(),
                        span,
                    );
                }
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    &message,
                    param.as_deref(),
                );
            }
            crate::core::family::FamilyEncodeResult::NotFound => {}
        }

        let resolved_operands =
            match pipeline
                .cpu
                .resolve_operands(mnemonic, mapped_operands.as_ref(), self)
            {
                Ok(ops) => ops,
                Err(err) => {
                    return self.failure(LineStatus::Error, AsmErrorKind::Instruction, &err, None)
                }
            };

        if let Some(validator) = pipeline.validator.as_ref() {
            if let Err(err) =
                validator.validate_instruction(&mapped_mnemonic, resolved_operands.as_ref(), self)
            {
                return self.failure(LineStatus::Error, AsmErrorKind::Instruction, &err, None);
            }
        }

        if let Some(status) = self.try_encode_instruction_via_runtime_operands(
            &pipeline,
            &mapped_mnemonic,
            operands,
            resolved_operands.as_ref(),
        ) {
            return status;
        }

        match pipeline
            .family
            .encode_instruction(&mapped_mnemonic, resolved_operands.as_ref(), self)
            .into_outcome()
        {
            Ok(Some(bytes)) => {
                if let Err(err) =
                    self.validate_instruction_emit_span(&mapped_mnemonic, operands, bytes.len())
                {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        err.error.message(),
                        None,
                        err.span,
                    );
                }
                self.bytes.extend_from_slice(&bytes);
                self.apply_cpu_runtime_state_after_encode(
                    pipeline.cpu.as_ref(),
                    &mapped_mnemonic,
                    resolved_operands.as_ref(),
                );
                LineStatus::Ok
            }
            Err(err) => {
                if let Some(span) = err.span {
                    self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        &err.message,
                        None,
                        span,
                    )
                } else {
                    self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        &err.message,
                        None,
                    )
                }
            }
            Ok(None) => match pipeline
                .cpu
                .encode_instruction(&mapped_mnemonic, resolved_operands.as_ref(), self)
                .into_outcome()
            {
                Ok(Some(bytes)) => {
                    if let Err(err) =
                        self.validate_instruction_emit_span(&mapped_mnemonic, operands, bytes.len())
                    {
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Instruction,
                            err.error.message(),
                            None,
                            err.span,
                        );
                    }
                    self.bytes.extend_from_slice(&bytes);
                    self.apply_cpu_runtime_state_after_encode(
                        pipeline.cpu.as_ref(),
                        &mapped_mnemonic,
                        resolved_operands.as_ref(),
                    );
                    LineStatus::Ok
                }
                Err(err) => {
                    if let Some(span) = err.span {
                        self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Instruction,
                            &err.message,
                            None,
                            span,
                        )
                    } else {
                        self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Instruction,
                            &err.message,
                            None,
                        )
                    }
                }
                Ok(None) => self.failure_instruction_not_found(
                    LineStatus::Error,
                    &pipeline,
                    mnemonic,
                    family_operands.as_ref(),
                ),
            },
        }
    }

    fn try_encode_instruction_via_runtime_expr(
        &mut self,
        pipeline: &ResolvedPipeline<'_>,
        mnemonic: &str,
        operands: &[Expr],
        family_operands: &dyn FamilyOperandSet,
        mapped_mnemonic: &str,
        mapped_operands: &dyn FamilyOperandSet,
    ) -> Option<LineStatus> {
        let vm_instruction_runtime_supported_for_cpu = self.cpu != crate::m45gs02::module::CPU_ID;
        let family_runtime_authoritative =
            crate::vm::rollout::package_runtime_default_enabled_for_family(
                pipeline.family_id.as_str(),
            ) && vm_instruction_runtime_supported_for_cpu;

        let allow = match self.opthread_form_allows_mnemonic(pipeline, mapped_mnemonic) {
            Ok(allow) => allow,
            Err(message) => {
                return Some(self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    &message,
                    None,
                ))
            }
        };
        if !allow {
            return Some(self.failure_instruction_not_found(
                LineStatus::Error,
                pipeline,
                mnemonic,
                family_operands,
            ));
        }

        if self.opthread_execution_model.is_none() && family_runtime_authoritative {
            return Some(self.failure(
                LineStatus::Error,
                AsmErrorKind::Instruction,
                &format!(
                    "VM runtime model unavailable for authoritative family '{}'",
                    pipeline.family_id.as_str()
                ),
                None,
            ));
        }

        let model = self.opthread_execution_model.as_ref()?;

        let runtime_expr_force_host =
            self.portable_expr_runtime_force_host_for_family(pipeline.family_id.as_str());
        let strict_runtime_parse_resolve = model
            .expr_resolution_is_strict_for_family(pipeline.family_id.as_str())
            && vm_instruction_runtime_supported_for_cpu;
        let runtime_expr_bytes_authoritative = (strict_runtime_parse_resolve
            || family_runtime_authoritative)
            && !runtime_expr_force_host;
        let runtime_expr_vm_path_enabled = runtime_expr_bytes_authoritative;
        let runtime_expr_selector_gate_only = runtime_expr_vm_path_enabled
            && model.selector_gate_only_expr_runtime_for_cpu(self.cpu.as_str());
        if !runtime_expr_vm_path_enabled {
            return None;
        }

        let runtime_expr_operands_storage =
            Self::opthread_runtime_expr_operands_from_mapped(mapped_operands);
        let runtime_expr_operands = runtime_expr_operands_storage.as_deref().unwrap_or(operands);
        match model.encode_instruction_from_exprs(
            self.cpu.as_str(),
            None,
            mapped_mnemonic,
            runtime_expr_operands,
            self,
        ) {
            Ok(Some(bytes)) => {
                if runtime_expr_selector_gate_only {
                    return None;
                }
                if bytes.is_empty() {
                    if family_runtime_authoritative {
                        return Some(self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Instruction,
                            &format!(
                                "VM program emitted no bytes for {}",
                                mapped_mnemonic.to_ascii_uppercase()
                            ),
                            None,
                        ));
                    }
                    return None;
                }
                if !runtime_expr_bytes_authoritative {
                    return None;
                }

                if let Some(status) =
                    self.emit_instruction_bytes_checked(mapped_mnemonic, operands, bytes.as_slice())
                {
                    return Some(status);
                }
                if let Ok(resolved_operands) =
                    pipeline
                        .cpu
                        .resolve_operands(mnemonic, mapped_operands, self)
                {
                    self.apply_cpu_runtime_state_after_encode(
                        pipeline.cpu.as_ref(),
                        mapped_mnemonic,
                        resolved_operands.as_ref(),
                    );
                }
                Some(LineStatus::Ok)
            }
            Ok(None) => {
                let defer_to_native_diagnostics =
                    model.defer_native_diagnostics_on_expr_none(pipeline.family_id.as_str());
                if strict_runtime_parse_resolve && !defer_to_native_diagnostics {
                    Some(self.failure_instruction_not_found(
                        LineStatus::Error,
                        pipeline,
                        mapped_mnemonic,
                        mapped_operands,
                    ))
                } else {
                    None
                }
            }
            Err(err) => {
                if runtime_expr_selector_gate_only {
                    None
                } else {
                    Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        &err.to_string(),
                        None,
                    ))
                }
            }
        }
    }

    fn try_encode_instruction_via_runtime_operands(
        &mut self,
        pipeline: &ResolvedPipeline<'_>,
        mapped_mnemonic: &str,
        operands: &[Expr],
        resolved_operands: &dyn OperandSet,
    ) -> Option<LineStatus> {
        let model = self.opthread_execution_model.as_ref()?;

        let vm_instruction_runtime_supported_for_cpu = self.cpu != crate::m45gs02::module::CPU_ID;
        let family_runtime_authoritative =
            crate::vm::rollout::package_runtime_default_enabled_for_family(
                pipeline.family_id.as_str(),
            ) && vm_instruction_runtime_supported_for_cpu;

        let strict_runtime_vm_programs = family_runtime_authoritative
            || (model.expr_resolution_is_strict_for_family(pipeline.family_id.as_str())
                && vm_instruction_runtime_supported_for_cpu);
        match model.encode_instruction(self.cpu.as_str(), None, mapped_mnemonic, resolved_operands)
        {
            Ok(Some(bytes)) => {
                if bytes.is_empty() {
                    if family_runtime_authoritative {
                        return Some(self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Instruction,
                            &format!(
                                "VM program emitted no bytes for {}",
                                mapped_mnemonic.to_ascii_uppercase()
                            ),
                            None,
                        ));
                    }
                    return None;
                }

                if let Some(status) =
                    self.emit_instruction_bytes_checked(mapped_mnemonic, operands, bytes.as_slice())
                {
                    return Some(status);
                }
                self.apply_cpu_runtime_state_after_encode(
                    pipeline.cpu.as_ref(),
                    mapped_mnemonic,
                    resolved_operands,
                );
                Some(LineStatus::Ok)
            }
            Ok(None) => {
                if strict_runtime_vm_programs {
                    Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        &format!(
                            "missing VM program for {}",
                            mapped_mnemonic.to_ascii_uppercase()
                        ),
                        None,
                    ))
                } else {
                    None
                }
            }
            Err(err) => Some(self.failure(
                LineStatus::Error,
                AsmErrorKind::Instruction,
                &err.to_string(),
                None,
            )),
        }
    }

    fn emit_instruction_bytes_checked(
        &mut self,
        mapped_mnemonic: &str,
        operands: &[Expr],
        bytes: &[u8],
    ) -> Option<LineStatus> {
        if let Err(err) =
            self.validate_instruction_emit_span(mapped_mnemonic, operands, bytes.len())
        {
            return Some(self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Instruction,
                err.error.message(),
                None,
                err.span,
            ));
        }
        self.bytes.extend_from_slice(bytes);
        None
    }

    fn failure_instruction_not_found(
        &mut self,
        status: LineStatus,
        pipeline: &ResolvedPipeline<'_>,
        mnemonic: &str,
        operands: &dyn FamilyOperandSet,
    ) -> LineStatus {
        let message = format!("No instruction found for {}", mnemonic.to_ascii_uppercase());
        if let Some((help, fixit)) =
            self.dialect_fixit_for_instruction_not_found(pipeline, mnemonic, operands)
        {
            let column = self
                .mnemonic_span_in_current_line(mnemonic)
                .map(|(start, _)| start)
                .or(self.line_end_span.map(|span| span.col_start));
            let status =
                self.set_failure_core(status, AsmErrorKind::Instruction, &message, None, column);
            self.diagnostics.last_error_help = Some(help);
            self.diagnostics.last_error_fixits = vec![fixit];
            return status;
        }

        self.failure(status, AsmErrorKind::Instruction, &message, None)
    }

    fn dialect_fixit_for_instruction_not_found(
        &self,
        pipeline: &ResolvedPipeline<'_>,
        mnemonic: &str,
        operands: &dyn FamilyOperandSet,
    ) -> Option<(String, Fixit)> {
        if !pipeline
            .family_id
            .as_str()
            .eq_ignore_ascii_case(INTEL8080_FAMILY_ID.as_str())
        {
            return None;
        }

        if pipeline.dialect_id.eq_ignore_ascii_case("zilog") {
            return None;
        }

        let intel_operands = operands
            .as_any()
            .downcast_ref::<Intel8080FamilyOperands>()?;
        let (canonical_mnemonic, _mapped_operands) =
            map_zilog_to_canonical(mnemonic, intel_operands.0.as_slice())?;

        if canonical_mnemonic.eq_ignore_ascii_case(mnemonic) {
            return None;
        }

        let (col_start, col_end) = self.mnemonic_span_in_current_line(mnemonic)?;
        let replacement = canonical_mnemonic.to_ascii_uppercase();
        let help = format!(
            "{} appears to use Z80 dialect under {} CPU mode; replace with Intel8080-family form '{}', or switch CPU/dialect",
            mnemonic.to_ascii_uppercase(),
            self.cpu.as_str(),
            replacement
        );

        Some((
            help,
            Fixit {
                file: None,
                line: self.current_line_num,
                col_start: Some(col_start),
                col_end: Some(col_end),
                replacement,
                applicability: "machine-applicable".to_string(),
            },
        ))
    }

    fn mnemonic_span_in_current_line(&self, mnemonic: &str) -> Option<(usize, usize)> {
        let source = self.current_source_line.as_ref()?;
        if mnemonic.is_empty() {
            return None;
        }

        let source_lower = source.to_ascii_lowercase();
        let needle = mnemonic.to_ascii_lowercase();
        let mut search_from = 0usize;

        while let Some(relative) = source_lower.get(search_from..)?.find(&needle) {
            let start = search_from + relative;
            let end = start + needle.len();

            let prev = source[..start].chars().next_back();
            let next = source[end..].chars().next();

            let left_ok = prev.is_none_or(|ch| !is_identifierish(ch));
            let right_ok = next.is_none_or(|ch| !is_identifierish(ch));
            if left_ok && right_ok {
                return Some((start + 1, end + 1));
            }

            search_from = end;
        }

        None
    }

    pub(super) fn attach_dialect_fixit_hint_from_source_line(&mut self) {
        let Ok(pipeline) = Self::resolve_pipeline_for_cpu(self.registry, self.cpu) else {
            return;
        };

        if !pipeline
            .family_id
            .as_str()
            .eq_ignore_ascii_case(INTEL8080_FAMILY_ID.as_str())
            || pipeline.dialect_id.eq_ignore_ascii_case("zilog")
        {
            return;
        }

        let Some((mnemonic, col_start, col_end)) = self.statement_mnemonic_from_source_line()
        else {
            return;
        };
        let Some(suggestion) = canonical_suggestion_for_zilog_mnemonic(mnemonic.as_str()) else {
            return;
        };
        if suggestion.eq_ignore_ascii_case(mnemonic.as_str()) {
            return;
        }

        self.diagnostics.last_error_help = Some(format!(
            "{} appears to use Z80 dialect under {} CPU mode; consider Intel8080-family '{}' syntax, or switch CPU/dialect",
            mnemonic.to_ascii_uppercase(),
            self.cpu.as_str(),
            suggestion.to_ascii_uppercase()
        ));
        self.diagnostics.last_error_fixits.push(Fixit {
            file: None,
            line: self.current_line_num,
            col_start: Some(col_start),
            col_end: Some(col_end),
            replacement: suggestion.to_ascii_uppercase(),
            applicability: "maybe-incorrect".to_string(),
        });
    }

    fn statement_mnemonic_from_source_line(&self) -> Option<(String, usize, usize)> {
        let source = self.current_source_line.as_ref()?;
        let without_comment = source.split(';').next().unwrap_or("");
        let bytes = without_comment.as_bytes();
        let mut idx = 0usize;

        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() {
            return None;
        }

        let mut probe = idx;
        while probe < bytes.len() && is_identifierish(bytes[probe] as char) {
            probe += 1;
        }
        if probe < bytes.len() && bytes[probe] == b':' {
            idx = probe + 1;
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
        }

        let start = idx;
        while idx < bytes.len() && is_identifierish(bytes[idx] as char) {
            idx += 1;
        }
        if idx == start {
            return None;
        }

        let mnemonic = without_comment[start..idx].trim();
        if mnemonic.is_empty() {
            return None;
        }

        Some((mnemonic.to_string(), start + 1, idx + 1))
    }

    pub(super) fn failure_for_unknown_directive_with_fixit(
        &mut self,
        mnemonic: &str,
    ) -> Option<LineStatus> {
        let suggestion = match mnemonic.to_ascii_uppercase().as_str() {
            ".EDIF" | ".ENDFI" | ".ENIDF" => ".ENDIF",
            ".ESLEIF" | ".ELSIEF" | ".ELSIF" | ".ELIF" | ".ELSFI" | ".ELSEFI" => ".ELSEIF",
            ".ENDMOD" | ".ENDMODUL" | ".ENDMODLE" | ".ENDMODUEL" => ".ENDMODULE",
            ".ENDSECT" | ".ENDSECTON" | ".ENDSEC" | ".ENDSECTIO" => ".ENDSECTION",
            ".ENDMACH" | ".ENDMTACH" | ".ENDMATC" => ".ENDMATCH",
            _ => return None,
        };

        let (col_start, col_end) = self
            .mnemonic_span_in_current_line(mnemonic)
            .or_else(|| {
                self.statement_mnemonic_from_source_line()
                    .map(|(_, start, end)| (start, end))
            })
            .unwrap_or((1, 1));

        let status = self.set_failure_core(
            LineStatus::Error,
            AsmErrorKind::Directive,
            &format!("Unknown directive {}", mnemonic.to_ascii_uppercase()),
            None,
            Some(col_start),
        );
        self.diagnostics.last_error_help =
            Some(format!("did you mean {}?", suggestion.to_ascii_lowercase()));
        self.diagnostics.last_error_fixits = vec![Fixit {
            file: None,
            line: self.current_line_num,
            col_start: Some(col_start),
            col_end: Some(col_end),
            replacement: suggestion.to_string(),
            applicability: "machine-applicable".to_string(),
        }];

        Some(status)
    }
}
