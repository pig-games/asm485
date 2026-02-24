use super::*;

pub(super) fn canonicalize_package_support_chunks(
    strings: &mut Vec<String>,
    diagnostics: &mut Vec<DiagnosticDescriptor>,
) {
    strings.sort();
    strings.dedup();

    diagnostics.sort_by(|left, right| {
        compare_ascii_case_insensitive(&left.code, &right.code).then_with(|| {
            compare_ascii_case_insensitive(&left.message_template, &right.message_template)
        })
    });
    diagnostics.dedup_by(|left, right| {
        left.code.eq_ignore_ascii_case(&right.code)
            && left
                .message_template
                .eq_ignore_ascii_case(&right.message_template)
    });
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
    families.sort_by(|left, right| compare_ascii_case_insensitive(&left.id, &right.id));
    cpus.sort_by(|left, right| compare_ascii_case_insensitive(&left.id, &right.id));

    for entry in dialects.iter_mut() {
        if let Some(allow) = entry.cpu_allow_list.as_mut() {
            allow.sort_by(|left, right| compare_ascii_case_insensitive(left, right));
            allow.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        }
    }
    dialects.sort_by(|left, right| {
        compare_ascii_case_insensitive(&left.family_id, &right.family_id)
            .then_with(|| compare_ascii_case_insensitive(&left.id, &right.id))
    });

    for entry in registers.iter_mut() {
        entry.owner.normalize_owner_id_ascii_lowercase();
        entry.id = entry.id.to_ascii_lowercase();
    }
    registers.sort_by(|left, right| {
        left.owner
            .cmp_scope_key(&right.owner)
            .then_with(|| left.id.cmp(&right.id))
    });
    registers.dedup_by(|left, right| left.id == right.id && left.owner.same_scope(&right.owner));

    for entry in forms.iter_mut() {
        entry.owner.normalize_owner_id_ascii_lowercase();
        entry.mnemonic = entry.mnemonic.to_ascii_lowercase();
    }
    forms.sort_by(|left, right| {
        left.owner
            .cmp_scope_key(&right.owner)
            .then_with(|| left.mnemonic.cmp(&right.mnemonic))
    });
    forms.dedup_by(|left, right| {
        left.mnemonic == right.mnemonic && left.owner.same_scope(&right.owner)
    });

    for entry in tables.iter_mut() {
        entry.owner.normalize_owner_id_ascii_lowercase();
        entry.mnemonic = entry.mnemonic.to_ascii_lowercase();
        entry.mode_key = entry.mode_key.to_ascii_lowercase();
    }
    tables.sort_by(|left, right| {
        left.owner
            .cmp_scope_key(&right.owner)
            .then_with(|| left.mnemonic.cmp(&right.mnemonic))
            .then_with(|| left.mode_key.cmp(&right.mode_key))
    });
    tables.dedup_by(|left, right| {
        left.mnemonic == right.mnemonic
            && left.mode_key == right.mode_key
            && left.owner.same_scope(&right.owner)
    });

    for entry in selectors.iter_mut() {
        entry.owner.normalize_owner_id_ascii_lowercase();
        entry.mnemonic = entry.mnemonic.to_ascii_lowercase();
        entry.shape_key = entry.shape_key.to_ascii_lowercase();
        entry.mode_key = entry.mode_key.to_ascii_lowercase();
        entry.operand_plan = entry.operand_plan.to_ascii_lowercase();
    }
    selectors.sort_by(|left, right| {
        left.owner
            .cmp_scope_key(&right.owner)
            .then_with(|| left.mnemonic.cmp(&right.mnemonic))
            .then_with(|| left.shape_key.cmp(&right.shape_key))
            .then_with(|| left.priority.cmp(&right.priority))
            .then_with(|| left.mode_key.cmp(&right.mode_key))
    });
    selectors.dedup_by(|left, right| {
        left.priority == right.priority
            && left.mnemonic == right.mnemonic
            && left.shape_key == right.shape_key
            && left.mode_key == right.mode_key
            && left.operand_plan == right.operand_plan
            && left.unstable_widen == right.unstable_widen
            && left.width_rank == right.width_rank
            && left.owner.same_scope(&right.owner)
    });
}

fn compare_ascii_case_insensitive(left: &str, right: &str) -> std::cmp::Ordering {
    left.bytes()
        .map(|value| value.to_ascii_lowercase())
        .cmp(right.bytes().map(|value| value.to_ascii_lowercase()))
}

fn canonicalize_scoped_descriptors<T, FNormalize, FCompare, FEquivalent>(
    descriptors: &mut Vec<T>,
    mut normalize: FNormalize,
    mut compare: FCompare,
    mut equivalent: FEquivalent,
) where
    FNormalize: FnMut(&mut T),
    FCompare: FnMut(&T, &T) -> std::cmp::Ordering,
    FEquivalent: FnMut(&T, &T) -> bool,
{
    for descriptor in descriptors.iter_mut() {
        normalize(descriptor);
    }
    descriptors.sort_by(|left, right| compare(left, right));
    descriptors.dedup_by(|left, right| equivalent(left, right));
}

pub(crate) fn canonicalize_token_policies(token_policies: &mut Vec<TokenPolicyDescriptor>) {
    canonicalize_scoped_descriptors(
        token_policies,
        |entry| {
            entry.owner.normalize_owner_id_ascii_lowercase();
            entry.punctuation_chars = canonicalize_ascii_char_set(&entry.punctuation_chars);
            entry.quote_chars = canonicalize_ascii_char_set(&entry.quote_chars);
            entry.number_prefix_chars = canonicalize_ascii_char_set(&entry.number_prefix_chars);
            entry.number_suffix_binary = canonicalize_ascii_char_set(&entry.number_suffix_binary);
            entry.number_suffix_octal = canonicalize_ascii_char_set(&entry.number_suffix_octal);
            entry.number_suffix_decimal = canonicalize_ascii_char_set(&entry.number_suffix_decimal);
            entry.number_suffix_hex = canonicalize_ascii_char_set(&entry.number_suffix_hex);
            entry.operator_chars = canonicalize_ascii_char_set(&entry.operator_chars);
            entry.multi_char_operators.retain(|value| !value.is_empty());
            entry.multi_char_operators.sort();
            entry.multi_char_operators.dedup();
        },
        |left, right| {
            left.owner
                .cmp_scope_key(&right.owner)
                .then_with(|| (left.case_rule as u8).cmp(&(right.case_rule as u8)))
                .then_with(|| {
                    left.identifier_start_class
                        .cmp(&right.identifier_start_class)
                })
                .then_with(|| {
                    left.identifier_continue_class
                        .cmp(&right.identifier_continue_class)
                })
                .then_with(|| left.punctuation_chars.cmp(&right.punctuation_chars))
                .then_with(|| left.comment_prefix.cmp(&right.comment_prefix))
                .then_with(|| left.quote_chars.cmp(&right.quote_chars))
                .then_with(|| left.escape_char.cmp(&right.escape_char))
                .then_with(|| left.number_prefix_chars.cmp(&right.number_prefix_chars))
                .then_with(|| left.number_suffix_binary.cmp(&right.number_suffix_binary))
                .then_with(|| left.number_suffix_octal.cmp(&right.number_suffix_octal))
                .then_with(|| left.number_suffix_decimal.cmp(&right.number_suffix_decimal))
                .then_with(|| left.number_suffix_hex.cmp(&right.number_suffix_hex))
                .then_with(|| left.operator_chars.cmp(&right.operator_chars))
                .then_with(|| left.multi_char_operators.cmp(&right.multi_char_operators))
        },
        |left, right| {
            left.case_rule == right.case_rule
                && left.identifier_start_class == right.identifier_start_class
                && left.identifier_continue_class == right.identifier_continue_class
                && left.punctuation_chars == right.punctuation_chars
                && left.comment_prefix == right.comment_prefix
                && left.quote_chars == right.quote_chars
                && left.escape_char == right.escape_char
                && left.number_prefix_chars == right.number_prefix_chars
                && left.number_suffix_binary == right.number_suffix_binary
                && left.number_suffix_octal == right.number_suffix_octal
                && left.number_suffix_decimal == right.number_suffix_decimal
                && left.number_suffix_hex == right.number_suffix_hex
                && left.operator_chars == right.operator_chars
                && left.multi_char_operators == right.multi_char_operators
                && left.owner.same_scope(&right.owner)
        },
    );
}

pub(crate) fn canonicalize_tokenizer_vm_programs(
    tokenizer_vm_programs: &mut Vec<TokenizerVmProgramDescriptor>,
) {
    canonicalize_scoped_descriptors(
        tokenizer_vm_programs,
        |entry| {
            entry.owner.normalize_owner_id_ascii_lowercase();
        },
        |left, right| {
            left.owner
                .cmp_scope_key(&right.owner)
                .then_with(|| left.opcode_version.cmp(&right.opcode_version))
                .then_with(|| left.start_state.cmp(&right.start_state))
                .then_with(|| left.state_entry_offsets.cmp(&right.state_entry_offsets))
                .then_with(|| {
                    left.limits
                        .max_steps_per_line
                        .cmp(&right.limits.max_steps_per_line)
                })
                .then_with(|| {
                    left.limits
                        .max_tokens_per_line
                        .cmp(&right.limits.max_tokens_per_line)
                })
                .then_with(|| {
                    left.limits
                        .max_lexeme_bytes
                        .cmp(&right.limits.max_lexeme_bytes)
                })
                .then_with(|| {
                    left.limits
                        .max_errors_per_line
                        .cmp(&right.limits.max_errors_per_line)
                })
                .then_with(|| {
                    left.diagnostics
                        .invalid_char
                        .cmp(&right.diagnostics.invalid_char)
                })
                .then_with(|| {
                    left.diagnostics
                        .unterminated_string
                        .cmp(&right.diagnostics.unterminated_string)
                })
                .then_with(|| {
                    left.diagnostics
                        .step_limit_exceeded
                        .cmp(&right.diagnostics.step_limit_exceeded)
                })
                .then_with(|| {
                    left.diagnostics
                        .token_limit_exceeded
                        .cmp(&right.diagnostics.token_limit_exceeded)
                })
                .then_with(|| {
                    left.diagnostics
                        .lexeme_limit_exceeded
                        .cmp(&right.diagnostics.lexeme_limit_exceeded)
                })
                .then_with(|| {
                    left.diagnostics
                        .error_limit_exceeded
                        .cmp(&right.diagnostics.error_limit_exceeded)
                })
                .then_with(|| left.program.cmp(&right.program))
        },
        |left, right| {
            left.opcode_version == right.opcode_version
                && left.start_state == right.start_state
                && left.state_entry_offsets == right.state_entry_offsets
                && left.limits == right.limits
                && left.diagnostics == right.diagnostics
                && left.program == right.program
                && left.owner.same_scope(&right.owner)
        },
    );
}

pub(crate) fn canonicalize_parser_contracts(parser_contracts: &mut Vec<ParserContractDescriptor>) {
    canonicalize_scoped_descriptors(
        parser_contracts,
        |entry| {
            entry.owner.normalize_owner_id_ascii_lowercase();
            entry.grammar_id = entry.grammar_id.to_ascii_lowercase();
            entry.ast_schema_id = entry.ast_schema_id.to_ascii_lowercase();
        },
        |left, right| {
            left.owner
                .cmp_scope_key(&right.owner)
                .then_with(|| left.grammar_id.cmp(&right.grammar_id))
                .then_with(|| left.ast_schema_id.cmp(&right.ast_schema_id))
                .then_with(|| left.opcode_version.cmp(&right.opcode_version))
                .then_with(|| {
                    left.max_ast_nodes_per_line
                        .cmp(&right.max_ast_nodes_per_line)
                })
                .then_with(|| {
                    left.diagnostics
                        .unexpected_token
                        .cmp(&right.diagnostics.unexpected_token)
                })
                .then_with(|| {
                    left.diagnostics
                        .expected_expression
                        .cmp(&right.diagnostics.expected_expression)
                })
                .then_with(|| {
                    left.diagnostics
                        .expected_operand
                        .cmp(&right.diagnostics.expected_operand)
                })
                .then_with(|| {
                    left.diagnostics
                        .invalid_statement
                        .cmp(&right.diagnostics.invalid_statement)
                })
        },
        |left, right| {
            left.grammar_id == right.grammar_id
                && left.ast_schema_id == right.ast_schema_id
                && left.opcode_version == right.opcode_version
                && left.max_ast_nodes_per_line == right.max_ast_nodes_per_line
                && left.diagnostics == right.diagnostics
                && left.owner.same_scope(&right.owner)
        },
    );
}

pub(crate) fn canonicalize_parser_vm_programs(
    parser_vm_programs: &mut Vec<ParserVmProgramDescriptor>,
) {
    canonicalize_scoped_descriptors(
        parser_vm_programs,
        |entry| {
            entry.owner.normalize_owner_id_ascii_lowercase();
        },
        |left, right| {
            left.owner
                .cmp_scope_key(&right.owner)
                .then_with(|| left.opcode_version.cmp(&right.opcode_version))
                .then_with(|| left.program.cmp(&right.program))
        },
        |left, right| {
            left.opcode_version == right.opcode_version
                && left.program == right.program
                && left.owner.same_scope(&right.owner)
        },
    );
}

pub(crate) fn canonicalize_expr_contracts(expr_contracts: &mut Vec<ExprContractDescriptor>) {
    canonicalize_scoped_descriptors(
        expr_contracts,
        |entry| {
            entry.owner.normalize_owner_id_ascii_lowercase();
        },
        |left, right| {
            left.owner
                .cmp_scope_key(&right.owner)
                .then_with(|| left.opcode_version.cmp(&right.opcode_version))
                .then_with(|| left.max_program_bytes.cmp(&right.max_program_bytes))
                .then_with(|| left.max_stack_depth.cmp(&right.max_stack_depth))
                .then_with(|| left.max_symbol_refs.cmp(&right.max_symbol_refs))
                .then_with(|| left.max_eval_steps.cmp(&right.max_eval_steps))
                .then_with(|| {
                    left.diagnostics
                        .invalid_opcode
                        .cmp(&right.diagnostics.invalid_opcode)
                })
                .then_with(|| {
                    left.diagnostics
                        .stack_underflow
                        .cmp(&right.diagnostics.stack_underflow)
                })
                .then_with(|| {
                    left.diagnostics
                        .stack_depth_exceeded
                        .cmp(&right.diagnostics.stack_depth_exceeded)
                })
                .then_with(|| {
                    left.diagnostics
                        .unknown_symbol
                        .cmp(&right.diagnostics.unknown_symbol)
                })
                .then_with(|| {
                    left.diagnostics
                        .eval_failure
                        .cmp(&right.diagnostics.eval_failure)
                })
                .then_with(|| {
                    left.diagnostics
                        .unsupported_feature
                        .cmp(&right.diagnostics.unsupported_feature)
                })
                .then_with(|| {
                    left.diagnostics
                        .budget_exceeded
                        .cmp(&right.diagnostics.budget_exceeded)
                })
                .then_with(|| {
                    left.diagnostics
                        .invalid_program
                        .cmp(&right.diagnostics.invalid_program)
                })
        },
        |left, right| {
            left.opcode_version == right.opcode_version
                && left.max_program_bytes == right.max_program_bytes
                && left.max_stack_depth == right.max_stack_depth
                && left.max_symbol_refs == right.max_symbol_refs
                && left.max_eval_steps == right.max_eval_steps
                && left.diagnostics == right.diagnostics
                && left.owner.same_scope(&right.owner)
        },
    );
}

pub(crate) fn canonicalize_expr_parser_contracts(
    expr_parser_contracts: &mut Vec<ExprParserContractDescriptor>,
) {
    canonicalize_scoped_descriptors(
        expr_parser_contracts,
        |entry| {
            entry.owner.normalize_owner_id_ascii_lowercase();
            entry.diagnostics.invalid_expression_program = entry
                .diagnostics
                .invalid_expression_program
                .to_ascii_lowercase();
        },
        |left, right| {
            left.owner
                .cmp_scope_key(&right.owner)
                .then_with(|| left.opcode_version.cmp(&right.opcode_version))
                .then_with(|| {
                    left.diagnostics
                        .invalid_expression_program
                        .cmp(&right.diagnostics.invalid_expression_program)
                })
        },
        |left, right| {
            left.opcode_version == right.opcode_version
                && left.diagnostics == right.diagnostics
                && left.owner.same_scope(&right.owner)
        },
    );
}

fn canonicalize_ascii_char_set(value: &str) -> String {
    let mut chars: Vec<char> = value.chars().collect();
    chars.sort_unstable();
    chars.dedup();
    chars.into_iter().collect()
}
