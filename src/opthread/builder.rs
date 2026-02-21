// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Build opThread hierarchy chunks from the live opForge module registry.

use crate::core::expr_vm::PortableExprBudgets;
use crate::core::family::CpuHandler;
use crate::core::registry::ModuleRegistry;
use crate::families::intel8080::module::FAMILY_ID as INTEL8080_FAMILY_ID;
use crate::families::intel8080::table::FAMILY_INSTRUCTION_TABLE as INTEL8080_FAMILY_INSTRUCTION_TABLE;
use crate::families::mos6502::module::FAMILY_ID as MOS6502_FAMILY_ID;
use crate::families::mos6502::{AddressMode, FAMILY_INSTRUCTION_TABLE};
use crate::i8085::extensions::I8085_EXTENSION_TABLE;
use crate::i8085::module::CPU_ID as I8085_CPU_ID;
use crate::m65816::instructions::CPU_INSTRUCTION_TABLE as M65816_CPU_INSTRUCTION_TABLE;
use crate::m65816::module::CPU_ID as M65816_CPU_ID;
use crate::m65816::M65816CpuHandler;
use crate::m65c02::instructions::CPU_INSTRUCTION_TABLE as M65C02_CPU_INSTRUCTION_TABLE;
use crate::m65c02::module::CPU_ID as M65C02_CPU_ID;
use crate::opthread::hierarchy::{
    CpuDescriptor, DialectDescriptor, FamilyDescriptor, HierarchyError, HierarchyPackage,
    ScopedFormDescriptor, ScopedOwner, ScopedRegisterDescriptor,
};
use crate::opthread::intel8080_vm::{
    compile_vm_program_for_instruction_entry, compile_vm_program_for_z80_cb_register,
    compile_vm_program_for_z80_half_index, compile_vm_program_for_z80_indexed_cb,
    compile_vm_program_for_z80_indexed_memory, compile_vm_program_for_z80_interrupt_mode,
    compile_vm_program_for_z80_ld_indirect, mode_key_for_instruction_entry,
    mode_key_for_z80_cb_register, mode_key_for_z80_half_index, mode_key_for_z80_indexed_cb,
    mode_key_for_z80_indexed_memory, mode_key_for_z80_interrupt_mode, mode_key_for_z80_ld_indirect,
};
use crate::opthread::package::{
    canonicalize_expr_parser_contracts, canonicalize_hierarchy_metadata,
    canonicalize_parser_contracts, canonicalize_parser_vm_programs, canonicalize_token_policies,
    canonicalize_tokenizer_vm_programs, default_runtime_diagnostic_catalog,
    default_token_policy_lexical_defaults, encode_hierarchy_chunks_from_chunks,
    token_identifier_class, ExprContractDescriptor, ExprDiagnosticMap,
    ExprParserContractDescriptor, ExprParserDiagnosticMap, HierarchyChunks, ModeSelectorDescriptor,
    OpcpuCodecError, ParserContractDescriptor, ParserDiagnosticMap, ParserVmOpcode,
    ParserVmProgramDescriptor, TokenCaseRule, TokenPolicyDescriptor, TokenizerVmDiagnosticMap,
    TokenizerVmLimits, TokenizerVmOpcode, TokenizerVmProgramDescriptor, VmProgramDescriptor,
    DIAG_EXPR_BUDGET_EXCEEDED, DIAG_EXPR_EVAL_FAILURE, DIAG_EXPR_INVALID_OPCODE,
    DIAG_EXPR_INVALID_PROGRAM, DIAG_EXPR_STACK_DEPTH_EXCEEDED, DIAG_EXPR_STACK_UNDERFLOW,
    DIAG_EXPR_UNKNOWN_SYMBOL, DIAG_EXPR_UNSUPPORTED_FEATURE, DIAG_PARSER_EXPECTED_EXPRESSION,
    DIAG_PARSER_EXPECTED_OPERAND, DIAG_PARSER_INVALID_STATEMENT, DIAG_PARSER_UNEXPECTED_TOKEN,
    DIAG_TOKENIZER_ERROR_LIMIT_EXCEEDED, DIAG_TOKENIZER_INVALID_CHAR,
    DIAG_TOKENIZER_LEXEME_LIMIT_EXCEEDED, DIAG_TOKENIZER_STEP_LIMIT_EXCEEDED,
    DIAG_TOKENIZER_TOKEN_LIMIT_EXCEEDED, DIAG_TOKENIZER_UNTERMINATED_STRING,
    EXPR_PARSER_VM_OPCODE_VERSION_V1, EXPR_VM_OPCODE_VERSION_V1, PARSER_AST_SCHEMA_ID_LINE_V1,
    PARSER_GRAMMAR_ID_LINE_V1, PARSER_VM_OPCODE_VERSION_V1, TOKENIZER_VM_OPCODE_VERSION_V1,
};
use crate::opthread::vm::{OP_EMIT_OPERAND, OP_EMIT_U8, OP_END};
use crate::z80::extensions::Z80_EXTENSION_TABLE;
use crate::z80::module::CPU_ID as Z80_CPU_ID;

/// Errors emitted while building hierarchy package data from registry metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HierarchyBuildError {
    MissingFamilyMetadata { family_id: String },
    MissingCpuMetadata { cpu_id: String },
    Hierarchy(HierarchyError),
    Codec(OpcpuCodecError),
}

impl std::fmt::Display for HierarchyBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingFamilyMetadata { family_id } => {
                write!(f, "missing registry metadata for family '{}'", family_id)
            }
            Self::MissingCpuMetadata { cpu_id } => {
                write!(f, "missing registry metadata for cpu '{}'", cpu_id)
            }
            Self::Hierarchy(err) => write!(f, "hierarchy validation error: {}", err),
            Self::Codec(err) => write!(f, "package codec error: {}", err),
        }
    }
}

impl std::error::Error for HierarchyBuildError {}

impl From<HierarchyError> for HierarchyBuildError {
    fn from(value: HierarchyError) -> Self {
        Self::Hierarchy(value)
    }
}

impl From<OpcpuCodecError> for HierarchyBuildError {
    fn from(value: OpcpuCodecError) -> Self {
        Self::Codec(value)
    }
}

/// Build `TOKS`/`TKVM`/`PARS`/`PRVM` + hierarchy chunks from registry metadata.
pub fn build_hierarchy_chunks_from_registry(
    registry: &ModuleRegistry,
) -> Result<HierarchyChunks, HierarchyBuildError> {
    let family_ids = registry.family_ids();

    let mut families = Vec::with_capacity(family_ids.len());
    for family in &family_ids {
        let canonical = registry
            .canonical_dialect_for_family(*family)
            .ok_or_else(|| HierarchyBuildError::MissingFamilyMetadata {
                family_id: family.as_str().to_string(),
            })?;
        families.push(FamilyDescriptor {
            id: family.as_str().to_string(),
            canonical_dialect: canonical.to_string(),
        });
    }

    let cpu_ids = registry.cpu_ids();
    let mut cpus = Vec::with_capacity(cpu_ids.len());
    for cpu in cpu_ids {
        let family_id =
            registry
                .cpu_family_id(cpu)
                .ok_or_else(|| HierarchyBuildError::MissingCpuMetadata {
                    cpu_id: cpu.as_str().to_string(),
                })?;
        let default_dialect = registry.cpu_default_dialect(cpu).map(ToString::to_string);
        cpus.push(CpuDescriptor {
            id: cpu.as_str().to_string(),
            family_id: family_id.as_str().to_string(),
            default_dialect,
        });
    }

    let mut dialects = Vec::new();
    for family in &family_ids {
        let family_id = family.as_str().to_string();
        for dialect in registry.dialect_ids_for_family(*family) {
            dialects.push(DialectDescriptor {
                id: dialect,
                family_id: family_id.clone(),
                cpu_allow_list: None,
            });
        }
    }
    let mut token_policies = family_ids
        .iter()
        .map(|family| default_family_token_policy(family.as_str()))
        .collect();
    let mut tokenizer_vm_programs = family_ids
        .iter()
        .map(|family| default_family_tokenizer_vm_program(family.as_str()))
        .collect();
    let mut parser_contracts = family_ids
        .iter()
        .map(|family| default_family_parser_contract(family.as_str()))
        .collect();
    let mut parser_vm_programs = family_ids
        .iter()
        .map(|family| default_family_parser_vm_program(family.as_str()))
        .collect();
    let expr_budget_defaults = PortableExprBudgets::default();
    let expr_budget_defaults = (
        expr_budget_defaults.max_program_bytes,
        expr_budget_defaults.max_stack_depth,
        expr_budget_defaults.max_symbol_refs,
        expr_budget_defaults.max_eval_steps,
    );
    let mut expr_contracts = family_ids
        .iter()
        .map(|family| default_family_expr_contract(family.as_str(), expr_budget_defaults))
        .collect();
    let mut expr_parser_contracts = family_ids
        .iter()
        .map(|family| default_family_expr_parser_contract(family.as_str()))
        .collect();

    let mut registers = Vec::new();
    for family in &family_ids {
        for register_id in registry.family_register_ids(*family) {
            registers.push(ScopedRegisterDescriptor {
                owner: ScopedOwner::Family(family.as_str().to_string()),
                id: register_id,
            });
        }
    }
    for cpu in registry.cpu_ids() {
        for register_id in registry.cpu_register_ids(cpu) {
            registers.push(ScopedRegisterDescriptor {
                owner: ScopedOwner::Cpu(cpu.as_str().to_string()),
                id: register_id,
            });
        }
    }

    let mut forms = Vec::new();
    for family in &family_ids {
        for mnemonic in registry.family_form_mnemonics(*family) {
            forms.push(ScopedFormDescriptor {
                owner: ScopedOwner::Family(family.as_str().to_string()),
                mnemonic,
            });
        }
    }
    for cpu in registry.cpu_ids() {
        for mnemonic in registry.cpu_form_mnemonics(cpu) {
            forms.push(ScopedFormDescriptor {
                owner: ScopedOwner::Cpu(cpu.as_str().to_string()),
                mnemonic,
            });
        }
    }
    for family in &family_ids {
        for dialect_id in registry.dialect_ids_for_family(*family) {
            for mnemonic in registry.dialect_form_mnemonics(*family, &dialect_id) {
                forms.push(ScopedFormDescriptor {
                    owner: ScopedOwner::Dialect(dialect_id.clone()),
                    mnemonic,
                });
            }
        }
    }

    let mut tables = Vec::new();
    let mut selectors = Vec::new();
    let registered_family_ids: std::collections::HashSet<String> = family_ids
        .iter()
        .map(|family| family.as_str().to_ascii_lowercase())
        .collect();
    let registered_cpu_ids: std::collections::HashSet<String> = registry
        .cpu_ids()
        .iter()
        .map(|cpu| cpu.as_str().to_ascii_lowercase())
        .collect();
    let has_m65816 = registered_cpu_ids.contains(M65816_CPU_ID.as_str());

    if registered_family_ids.contains(INTEL8080_FAMILY_ID.as_str()) {
        for entry in INTEL8080_FAMILY_INSTRUCTION_TABLE {
            let Some(program) = compile_vm_program_for_instruction_entry(entry) else {
                continue;
            };
            tables.push(VmProgramDescriptor {
                owner: ScopedOwner::Family(INTEL8080_FAMILY_ID.as_str().to_string()),
                mnemonic: entry.mnemonic.to_string(),
                mode_key: mode_key_for_instruction_entry(entry),
                program,
            });
        }
    }
    if registered_cpu_ids.contains(I8085_CPU_ID.as_str()) {
        for entry in I8085_EXTENSION_TABLE {
            let Some(program) = compile_vm_program_for_instruction_entry(entry) else {
                continue;
            };
            tables.push(VmProgramDescriptor {
                owner: ScopedOwner::Cpu(I8085_CPU_ID.as_str().to_string()),
                mnemonic: entry.mnemonic.to_string(),
                mode_key: mode_key_for_instruction_entry(entry),
                program,
            });
        }
    }
    if registered_cpu_ids.contains(Z80_CPU_ID.as_str()) {
        for mnemonic in [
            "BIT", "RES", "SET", "RLC", "RRC", "RL", "RR", "SLA", "SRA", "SLL", "SRL",
        ] {
            forms.push(ScopedFormDescriptor {
                owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                mnemonic: mnemonic.to_string(),
            });
        }

        for register in ["B", "C", "D", "E", "H", "L", "M", "A"] {
            for mnemonic in ["RLC", "RRC", "RL", "RR", "SLA", "SRA", "SLL", "SRL"] {
                let Some(mode_key) = mode_key_for_z80_cb_register(mnemonic, None, register) else {
                    continue;
                };
                let Some(program) =
                    compile_vm_program_for_z80_cb_register(mnemonic, None, register)
                else {
                    continue;
                };
                tables.push(VmProgramDescriptor {
                    owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                    mnemonic: mnemonic.to_string(),
                    mode_key,
                    program,
                });
            }

            for mnemonic in ["BIT", "RES", "SET"] {
                for bit in 0u8..=7 {
                    let Some(mode_key) =
                        mode_key_for_z80_cb_register(mnemonic, Some(bit), register)
                    else {
                        continue;
                    };
                    let Some(program) =
                        compile_vm_program_for_z80_cb_register(mnemonic, Some(bit), register)
                    else {
                        continue;
                    };
                    tables.push(VmProgramDescriptor {
                        owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                        mnemonic: mnemonic.to_string(),
                        mode_key,
                        program,
                    });
                }
            }
        }

        for base in ["IX", "IY"] {
            for mnemonic in ["RLC", "RRC", "RL", "RR", "SLA", "SRA", "SLL", "SRL"] {
                let Some(mode_key) = mode_key_for_z80_indexed_cb(base, mnemonic, None) else {
                    continue;
                };
                let Some(program) = compile_vm_program_for_z80_indexed_cb(base, mnemonic, None)
                else {
                    continue;
                };
                tables.push(VmProgramDescriptor {
                    owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                    mnemonic: mnemonic.to_string(),
                    mode_key,
                    program,
                });
            }
            for bit in 0u8..=7 {
                for mnemonic in ["BIT", "RES", "SET"] {
                    let Some(mode_key) = mode_key_for_z80_indexed_cb(base, mnemonic, Some(bit))
                    else {
                        continue;
                    };
                    let Some(program) =
                        compile_vm_program_for_z80_indexed_cb(base, mnemonic, Some(bit))
                    else {
                        continue;
                    };
                    tables.push(VmProgramDescriptor {
                        owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                        mnemonic: mnemonic.to_string(),
                        mode_key,
                        program,
                    });
                }
            }

            for (reg, code) in [
                ("B", 0u8),
                ("C", 1),
                ("D", 2),
                ("E", 3),
                ("H", 4),
                ("L", 5),
                ("A", 7),
            ] {
                let from_idx_form = format!("ld_r_from_idx_{}", reg.to_ascii_lowercase());
                let Some(mode_key) = mode_key_for_z80_indexed_memory(base, from_idx_form.as_str())
                else {
                    continue;
                };
                let Some(program) =
                    compile_vm_program_for_z80_indexed_memory(base, 0x46 | (code << 3), 1)
                else {
                    continue;
                };
                tables.push(VmProgramDescriptor {
                    owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                    mnemonic: "LD".to_string(),
                    mode_key,
                    program,
                });

                let to_idx_form = format!("ld_idx_from_r_{}", reg.to_ascii_lowercase());
                let Some(mode_key) = mode_key_for_z80_indexed_memory(base, to_idx_form.as_str())
                else {
                    continue;
                };
                let Some(program) = compile_vm_program_for_z80_indexed_memory(base, 0x70 | code, 1)
                else {
                    continue;
                };
                tables.push(VmProgramDescriptor {
                    owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                    mnemonic: "LD".to_string(),
                    mode_key,
                    program,
                });
            }

            for (form, opcode, operand_count, mnemonic) in [
                ("ld_idx_imm", 0x36u8, 2u8, "LD"),
                ("inc_idx", 0x34, 1, "INC"),
                ("dec_idx", 0x35, 1, "DEC"),
                ("add_a_idx", 0x86, 1, "ADD"),
                ("adc_a_idx", 0x8E, 1, "ADC"),
                ("sub_idx", 0x96, 1, "SUB"),
                ("sbc_a_idx", 0x9E, 1, "SBC"),
                ("and_idx", 0xA6, 1, "AND"),
                ("xor_idx", 0xAE, 1, "XOR"),
                ("or_idx", 0xB6, 1, "OR"),
                ("cp_idx", 0xBE, 1, "CP"),
            ] {
                let Some(mode_key) = mode_key_for_z80_indexed_memory(base, form) else {
                    continue;
                };
                let Some(program) =
                    compile_vm_program_for_z80_indexed_memory(base, opcode, operand_count)
                else {
                    continue;
                };
                tables.push(VmProgramDescriptor {
                    owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                    mnemonic: mnemonic.to_string(),
                    mode_key,
                    program,
                });
            }
        }

        for register in ["A", "HL", "BC", "DE", "SP", "IX", "IY"] {
            let Some(load_mode_key) = mode_key_for_z80_ld_indirect(register, false) else {
                continue;
            };
            let Some(load_program) = compile_vm_program_for_z80_ld_indirect(register, false) else {
                continue;
            };
            tables.push(VmProgramDescriptor {
                owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                mnemonic: "LD".to_string(),
                mode_key: load_mode_key,
                program: load_program,
            });

            let Some(store_mode_key) = mode_key_for_z80_ld_indirect(register, true) else {
                continue;
            };
            let Some(store_program) = compile_vm_program_for_z80_ld_indirect(register, true) else {
                continue;
            };
            tables.push(VmProgramDescriptor {
                owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                mnemonic: "LD".to_string(),
                mode_key: store_mode_key,
                program: store_program,
            });
        }

        for prefix in ["IX", "IY"] {
            for dst_code in [0u8, 1, 2, 3, 4, 5, 7] {
                for src_code in [0u8, 1, 2, 3, 4, 5, 7] {
                    if dst_code != 4 && dst_code != 5 && src_code != 4 && src_code != 5 {
                        continue;
                    }
                    let opcode = 0x40 | (dst_code << 3) | src_code;
                    let form = format!("rr:{dst_code}:{src_code}");
                    let Some(mode_key) = mode_key_for_z80_half_index(prefix, "LD", form.as_str())
                    else {
                        continue;
                    };
                    let Some(program) = compile_vm_program_for_z80_half_index(prefix, opcode, 0)
                    else {
                        continue;
                    };
                    tables.push(VmProgramDescriptor {
                        owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                        mnemonic: "LD".to_string(),
                        mode_key,
                        program,
                    });
                }
            }

            for dst_code in [4u8, 5] {
                let opcode = 0x06 | (dst_code << 3);
                let form = format!("ri:{dst_code}");
                let Some(mode_key) = mode_key_for_z80_half_index(prefix, "LD", form.as_str())
                else {
                    continue;
                };
                let Some(program) = compile_vm_program_for_z80_half_index(prefix, opcode, 1) else {
                    continue;
                };
                tables.push(VmProgramDescriptor {
                    owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                    mnemonic: "LD".to_string(),
                    mode_key,
                    program,
                });
            }

            for (mnemonic, base_opcode) in [("INC", 0x04u8), ("DEC", 0x05)] {
                for code in [4u8, 5] {
                    let opcode = base_opcode | (code << 3);
                    let form = format!("r:{code}");
                    let Some(mode_key) =
                        mode_key_for_z80_half_index(prefix, mnemonic, form.as_str())
                    else {
                        continue;
                    };
                    let Some(program) = compile_vm_program_for_z80_half_index(prefix, opcode, 0)
                    else {
                        continue;
                    };
                    tables.push(VmProgramDescriptor {
                        owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                        mnemonic: mnemonic.to_string(),
                        mode_key,
                        program,
                    });
                }
            }

            for (mnemonic, base_opcode) in [
                ("ADD", 0x80u8),
                ("ADC", 0x88),
                ("SUB", 0x90),
                ("SBC", 0x98),
                ("AND", 0xA0),
                ("XOR", 0xA8),
                ("OR", 0xB0),
                ("CP", 0xB8),
            ] {
                for code in [4u8, 5] {
                    let opcode = base_opcode | code;
                    let form = format!("r:{code}");
                    let Some(mode_key) =
                        mode_key_for_z80_half_index(prefix, mnemonic, form.as_str())
                    else {
                        continue;
                    };
                    let Some(program) = compile_vm_program_for_z80_half_index(prefix, opcode, 0)
                    else {
                        continue;
                    };
                    tables.push(VmProgramDescriptor {
                        owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                        mnemonic: mnemonic.to_string(),
                        mode_key,
                        program,
                    });
                }
            }
        }

        for entry in Z80_EXTENSION_TABLE {
            if entry.mnemonic.eq_ignore_ascii_case("IM") {
                for mode in 0u8..=2 {
                    let Some(mode_key) = mode_key_for_z80_interrupt_mode(mode) else {
                        continue;
                    };
                    let Some(program) = compile_vm_program_for_z80_interrupt_mode(mode) else {
                        continue;
                    };
                    tables.push(VmProgramDescriptor {
                        owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                        mnemonic: entry.mnemonic.to_string(),
                        mode_key,
                        program,
                    });
                }
                continue;
            }
            let Some(program) = compile_vm_program_for_instruction_entry(entry) else {
                continue;
            };
            tables.push(VmProgramDescriptor {
                owner: ScopedOwner::Cpu(Z80_CPU_ID.as_str().to_string()),
                mnemonic: entry.mnemonic.to_string(),
                mode_key: mode_key_for_instruction_entry(entry),
                program,
            });
        }
    }

    if registered_family_ids.contains(MOS6502_FAMILY_ID.as_str()) {
        for entry in FAMILY_INSTRUCTION_TABLE {
            tables.push(VmProgramDescriptor {
                owner: ScopedOwner::Family(MOS6502_FAMILY_ID.as_str().to_string()),
                mnemonic: entry.mnemonic.to_string(),
                mode_key: format!("{:?}", entry.mode),
                program: compile_opcode_program(
                    entry.opcode,
                    if entry.mode.operand_size() > 0 { 1 } else { 0 },
                ),
            });
            if let Some(selector) = compile_mode_selector(
                ScopedOwner::Family(MOS6502_FAMILY_ID.as_str().to_string()),
                entry.mnemonic,
                entry.mode,
                false,
            ) {
                selectors.push(selector);
            }
            if has_m65816 {
                if let Some(selector) =
                    compile_m65816_immediate_width_selector(entry.mnemonic, entry.mode)
                {
                    selectors.push(selector);
                }
                selectors.extend(compile_m65816_force_selectors(entry.mnemonic, entry.mode));
            }
        }
    }
    if registered_cpu_ids.contains(M65C02_CPU_ID.as_str()) {
        for entry in M65C02_CPU_INSTRUCTION_TABLE {
            tables.push(VmProgramDescriptor {
                owner: ScopedOwner::Cpu(M65C02_CPU_ID.as_str().to_string()),
                mnemonic: entry.mnemonic.to_string(),
                mode_key: format!("{:?}", entry.mode),
                program: compile_opcode_program(
                    entry.opcode,
                    if entry.mode.operand_size() > 0 { 1 } else { 0 },
                ),
            });
            if let Some(selector) = compile_mode_selector(
                ScopedOwner::Cpu(M65C02_CPU_ID.as_str().to_string()),
                entry.mnemonic,
                entry.mode,
                false,
            ) {
                selectors.push(selector);
            }
        }
        tables.extend(compile_m65c02_bit_branch_programs());
        selectors.extend(compile_m65c02_bit_branch_selectors());
    }
    if registered_cpu_ids.contains(M65816_CPU_ID.as_str()) {
        let m65816_handler = M65816CpuHandler::new();
        for entry in M65816_CPU_INSTRUCTION_TABLE {
            tables.push(VmProgramDescriptor {
                owner: ScopedOwner::Cpu(M65816_CPU_ID.as_str().to_string()),
                mnemonic: entry.mnemonic.to_string(),
                mode_key: format!("{:?}", entry.mode),
                program: compile_opcode_program(
                    entry.opcode,
                    if entry.mode.operand_size() > 0 { 1 } else { 0 },
                ),
            });
            if let Some(selector) = compile_mode_selector(
                ScopedOwner::Cpu(M65816_CPU_ID.as_str().to_string()),
                entry.mnemonic,
                entry.mode,
                true,
            ) {
                selectors.push(selector);
            }
            selectors.extend(compile_m65816_force_selectors(entry.mnemonic, entry.mode));
            selectors.extend(compile_m65816_long_mode_selectors(
                entry.mnemonic,
                entry.mode,
            ));
        }
        for entry in M65C02_CPU_INSTRUCTION_TABLE {
            if !<M65816CpuHandler as CpuHandler>::supports_mnemonic(&m65816_handler, entry.mnemonic)
            {
                continue;
            }
            tables.push(VmProgramDescriptor {
                owner: ScopedOwner::Cpu(M65816_CPU_ID.as_str().to_string()),
                mnemonic: entry.mnemonic.to_string(),
                mode_key: format!("{:?}", entry.mode),
                program: compile_opcode_program(
                    entry.opcode,
                    if entry.mode.operand_size() > 0 { 1 } else { 0 },
                ),
            });
            if let Some(selector) = compile_mode_selector(
                ScopedOwner::Cpu(M65816_CPU_ID.as_str().to_string()),
                entry.mnemonic,
                entry.mode,
                true,
            ) {
                selectors.push(selector);
            }
            selectors.extend(compile_m65816_force_selectors(entry.mnemonic, entry.mode));
            selectors.extend(compile_m65816_long_mode_selectors(
                entry.mnemonic,
                entry.mode,
            ));
        }
    }

    canonicalize_hierarchy_metadata(
        &mut families,
        &mut cpus,
        &mut dialects,
        &mut registers,
        &mut forms,
        &mut tables,
        &mut selectors,
    );
    canonicalize_token_policies(&mut token_policies);
    canonicalize_tokenizer_vm_programs(&mut tokenizer_vm_programs);
    canonicalize_parser_contracts(&mut parser_contracts);
    canonicalize_parser_vm_programs(&mut parser_vm_programs);
    crate::opthread::package::canonicalize_expr_contracts(&mut expr_contracts);
    canonicalize_expr_parser_contracts(&mut expr_parser_contracts);

    // Ensure the materialized metadata is coherent before returning.
    HierarchyPackage::new(families.clone(), cpus.clone(), dialects.clone())?;

    Ok(HierarchyChunks {
        metadata: crate::opthread::package::PackageMetaDescriptor::default(),
        strings: Vec::new(),
        diagnostics: default_runtime_diagnostic_catalog(),
        token_policies,
        tokenizer_vm_programs,
        parser_contracts,
        parser_vm_programs,
        expr_contracts,
        expr_parser_contracts,
        families,
        cpus,
        dialects,
        registers,
        forms,
        tables,
        selectors,
    })
}

fn default_family_expr_contract(
    family_id: &str,
    budget_defaults: (usize, usize, usize, usize),
) -> ExprContractDescriptor {
    ExprContractDescriptor {
        owner: ScopedOwner::Family(family_id.to_string()),
        opcode_version: EXPR_VM_OPCODE_VERSION_V1,
        max_program_bytes: budget_defaults.0 as u32,
        max_stack_depth: budget_defaults.1 as u32,
        max_symbol_refs: budget_defaults.2 as u32,
        max_eval_steps: budget_defaults.3 as u32,
        diagnostics: ExprDiagnosticMap {
            invalid_opcode: DIAG_EXPR_INVALID_OPCODE.to_string(),
            stack_underflow: DIAG_EXPR_STACK_UNDERFLOW.to_string(),
            stack_depth_exceeded: DIAG_EXPR_STACK_DEPTH_EXCEEDED.to_string(),
            unknown_symbol: DIAG_EXPR_UNKNOWN_SYMBOL.to_string(),
            eval_failure: DIAG_EXPR_EVAL_FAILURE.to_string(),
            unsupported_feature: DIAG_EXPR_UNSUPPORTED_FEATURE.to_string(),
            budget_exceeded: DIAG_EXPR_BUDGET_EXCEEDED.to_string(),
            invalid_program: DIAG_EXPR_INVALID_PROGRAM.to_string(),
        },
    }
}

fn default_family_expr_parser_contract(family_id: &str) -> ExprParserContractDescriptor {
    ExprParserContractDescriptor {
        owner: ScopedOwner::Family(family_id.to_string()),
        opcode_version: EXPR_PARSER_VM_OPCODE_VERSION_V1,
        diagnostics: ExprParserDiagnosticMap {
            invalid_expression_program: DIAG_PARSER_INVALID_STATEMENT.to_string(),
        },
    }
}

fn default_family_token_policy(family_id: &str) -> TokenPolicyDescriptor {
    let defaults = default_token_policy_lexical_defaults();
    TokenPolicyDescriptor {
        owner: ScopedOwner::Family(family_id.to_string()),
        case_rule: TokenCaseRule::AsciiLower,
        identifier_start_class: token_identifier_class::ASCII_ALPHA
            | token_identifier_class::UNDERSCORE
            | token_identifier_class::DOT,
        identifier_continue_class: token_identifier_class::ASCII_ALPHA
            | token_identifier_class::ASCII_DIGIT
            | token_identifier_class::UNDERSCORE
            | token_identifier_class::DOLLAR
            | token_identifier_class::AT_SIGN
            | token_identifier_class::DOT,
        punctuation_chars: ",()[]{}+-*/#<>:=.&|^%!~;".to_string(),
        comment_prefix: defaults.comment_prefix,
        quote_chars: defaults.quote_chars,
        escape_char: defaults.escape_char,
        number_prefix_chars: defaults.number_prefix_chars,
        number_suffix_binary: defaults.number_suffix_binary,
        number_suffix_octal: defaults.number_suffix_octal,
        number_suffix_decimal: defaults.number_suffix_decimal,
        number_suffix_hex: defaults.number_suffix_hex,
        operator_chars: defaults.operator_chars,
        multi_char_operators: defaults.multi_char_operators,
    }
}

fn default_family_tokenizer_vm_program(family_id: &str) -> TokenizerVmProgramDescriptor {
    let program = default_family_tokenizer_vm_program_bytes();
    TokenizerVmProgramDescriptor {
        owner: ScopedOwner::Family(family_id.to_string()),
        opcode_version: TOKENIZER_VM_OPCODE_VERSION_V1,
        start_state: 0,
        state_entry_offsets: vec![0],
        limits: TokenizerVmLimits {
            max_steps_per_line: 2048,
            max_tokens_per_line: 256,
            max_lexeme_bytes: 256,
            max_errors_per_line: 16,
        },
        diagnostics: TokenizerVmDiagnosticMap {
            invalid_char: DIAG_TOKENIZER_INVALID_CHAR.to_string(),
            unterminated_string: DIAG_TOKENIZER_UNTERMINATED_STRING.to_string(),
            step_limit_exceeded: DIAG_TOKENIZER_STEP_LIMIT_EXCEEDED.to_string(),
            token_limit_exceeded: DIAG_TOKENIZER_TOKEN_LIMIT_EXCEEDED.to_string(),
            lexeme_limit_exceeded: DIAG_TOKENIZER_LEXEME_LIMIT_EXCEEDED.to_string(),
            error_limit_exceeded: DIAG_TOKENIZER_ERROR_LIMIT_EXCEEDED.to_string(),
        },
        // Default tokenizer VM loop:
        // - scan exactly one core token from the current cursor
        // - detect EOL/comment termination
        // - loop until done
        //
        // This keeps assembler tokenization VM-authoritative while preserving
        // parity with core token semantics for now.
        program,
    }
}

fn default_family_parser_contract(family_id: &str) -> ParserContractDescriptor {
    ParserContractDescriptor {
        owner: ScopedOwner::Family(family_id.to_string()),
        grammar_id: PARSER_GRAMMAR_ID_LINE_V1.to_string(),
        ast_schema_id: PARSER_AST_SCHEMA_ID_LINE_V1.to_string(),
        opcode_version: PARSER_VM_OPCODE_VERSION_V1,
        max_ast_nodes_per_line: 1024,
        diagnostics: ParserDiagnosticMap {
            unexpected_token: DIAG_PARSER_UNEXPECTED_TOKEN.to_string(),
            expected_expression: DIAG_PARSER_EXPECTED_EXPRESSION.to_string(),
            expected_operand: DIAG_PARSER_EXPECTED_OPERAND.to_string(),
            invalid_statement: DIAG_PARSER_INVALID_STATEMENT.to_string(),
        },
    }
}

fn default_family_parser_vm_program(family_id: &str) -> ParserVmProgramDescriptor {
    ParserVmProgramDescriptor {
        owner: ScopedOwner::Family(family_id.to_string()),
        opcode_version: PARSER_VM_OPCODE_VERSION_V1,
        program: default_family_parser_vm_program_bytes(),
    }
}

fn default_family_parser_vm_program_bytes() -> Vec<u8> {
    vec![
        ParserVmOpcode::ParseDotDirectiveEnvelope as u8,
        ParserVmOpcode::ParseStarOrgEnvelope as u8,
        ParserVmOpcode::ParseAssignmentEnvelope as u8,
        ParserVmOpcode::ParseInstructionEnvelope as u8,
        ParserVmOpcode::EmitDiagIfNoAst as u8,
        0,
        ParserVmOpcode::End as u8,
    ]
}

fn default_family_tokenizer_vm_program_bytes() -> Vec<u8> {
    let loop_offset = 0u32;
    let mut program = Vec::new();

    // Scan one token from current cursor (or advance to done at EOL/comment).
    program.push(TokenizerVmOpcode::ScanCoreToken as u8);
    // Read current cursor byte after scan; if at EOL, finish.
    program.push(TokenizerVmOpcode::ReadChar as u8);
    program.push(TokenizerVmOpcode::JumpIfEol as u8);
    let eol_target_patch = program.len();
    program.extend_from_slice(&0u32.to_le_bytes());
    // Continue scanning until EOL.
    program.push(TokenizerVmOpcode::Jump as u8);
    program.extend_from_slice(&loop_offset.to_le_bytes());
    let end_offset = program.len() as u32;
    program[eol_target_patch..eol_target_patch + 4].copy_from_slice(&end_offset.to_le_bytes());
    program.push(TokenizerVmOpcode::End as u8);

    program
}

fn compile_opcode_program(opcode: u8, operand_count: usize) -> Vec<u8> {
    let mut program = vec![OP_EMIT_U8, opcode];
    for operand_index in 0..operand_count {
        program.push(OP_EMIT_OPERAND);
        program.push(operand_index as u8);
    }
    program.push(OP_END);
    program
}

fn compile_mode_selector(
    owner: ScopedOwner,
    mnemonic: &str,
    mode: AddressMode,
    is_m65816: bool,
) -> Option<ModeSelectorDescriptor> {
    let shape_key = selector_shape_key(mode)?;
    let operand_plan = selector_operand_plan(mode, mnemonic, is_m65816)?;
    Some(ModeSelectorDescriptor {
        owner,
        mnemonic: mnemonic.to_string(),
        shape_key: shape_key.to_string(),
        mode_key: format!("{:?}", mode),
        operand_plan: operand_plan.to_string(),
        priority: selector_priority(mode),
        unstable_widen: matches!(
            mode,
            AddressMode::ZeroPage | AddressMode::ZeroPageX | AddressMode::ZeroPageY
        ),
        width_rank: selector_width_rank(mode),
    })
}

fn compile_m65c02_bit_branch_selectors() -> Vec<ModeSelectorDescriptor> {
    let mut selectors = Vec::with_capacity(16);
    for bit in 0u8..=7 {
        selectors.push(ModeSelectorDescriptor {
            owner: ScopedOwner::Cpu(M65C02_CPU_ID.as_str().to_string()),
            mnemonic: format!("BBR{bit}"),
            shape_key: "pair_direct".to_string(),
            mode_key: format!("{:?}", AddressMode::ZeroPage),
            operand_plan: "pair_u8_rel8".to_string(),
            priority: 0,
            unstable_widen: false,
            width_rank: 1,
        });
        selectors.push(ModeSelectorDescriptor {
            owner: ScopedOwner::Cpu(M65C02_CPU_ID.as_str().to_string()),
            mnemonic: format!("BBS{bit}"),
            shape_key: "pair_direct".to_string(),
            mode_key: format!("{:?}", AddressMode::ZeroPage),
            operand_plan: "pair_u8_rel8".to_string(),
            priority: 0,
            unstable_widen: false,
            width_rank: 1,
        });
    }
    selectors
}

fn compile_m65816_force_selectors(
    mnemonic: &str,
    mode: AddressMode,
) -> Vec<ModeSelectorDescriptor> {
    let mut selectors = Vec::new();
    let forced_shape_key = match mode {
        AddressMode::AbsoluteLong => "direct",
        AddressMode::AbsoluteLongX => "direct_x",
        other => match selector_shape_key(other) {
            Some(shape_key) => shape_key,
            None => return selectors,
        },
    };
    let upper_mnemonic = mnemonic.to_ascii_uppercase();

    let mut emit = |suffix: &str, operand_plan: &str| {
        selectors.push(ModeSelectorDescriptor {
            owner: ScopedOwner::Cpu(M65816_CPU_ID.as_str().to_string()),
            mnemonic: mnemonic.to_string(),
            shape_key: format!("{forced_shape_key}:force_{suffix}"),
            mode_key: format!("{:?}", mode),
            operand_plan: operand_plan.to_string(),
            priority: selector_priority(mode),
            unstable_widen: false,
            width_rank: selector_width_rank(mode),
        });
    };

    match mode {
        AddressMode::ZeroPage
        | AddressMode::ZeroPageX
        | AddressMode::ZeroPageY
        | AddressMode::IndexedIndirectX
        | AddressMode::IndirectIndexedY
        | AddressMode::ZeroPageIndirect => emit("d", "force_d_u8"),
        AddressMode::Absolute => {
            if matches!(upper_mnemonic.as_str(), "JMP" | "JSR") {
                emit("k", "force_k_abs16_pbr");
            } else {
                emit("b", "force_b_abs16_dbr");
            }
        }
        AddressMode::AbsoluteX | AddressMode::AbsoluteY => emit("b", "force_b_abs16_dbr"),
        AddressMode::AbsoluteIndexedIndirect => {
            if matches!(upper_mnemonic.as_str(), "JMP" | "JSR") {
                emit("k", "force_k_abs16_pbr");
            }
        }
        AddressMode::Indirect => {
            if upper_mnemonic == "JMP" {
                emit("k", "force_k_abs16_pbr");
            }
        }
        AddressMode::AbsoluteLong | AddressMode::AbsoluteLongX => emit("l", "force_l_u24"),
        _ => {}
    }

    selectors
}

fn compile_m65816_immediate_width_selector(
    mnemonic: &str,
    mode: AddressMode,
) -> Option<ModeSelectorDescriptor> {
    if mode != AddressMode::Immediate || !m65816_immediate_width_mnemonic(mnemonic) {
        return None;
    }
    Some(ModeSelectorDescriptor {
        owner: ScopedOwner::Cpu(M65816_CPU_ID.as_str().to_string()),
        mnemonic: mnemonic.to_string(),
        shape_key: "immediate".to_string(),
        mode_key: format!("{:?}", AddressMode::Immediate),
        operand_plan: "imm_mx".to_string(),
        priority: selector_priority(AddressMode::Immediate),
        unstable_widen: false,
        width_rank: selector_width_rank(AddressMode::Immediate),
    })
}

fn compile_m65816_long_mode_selectors(
    mnemonic: &str,
    mode: AddressMode,
) -> Vec<ModeSelectorDescriptor> {
    let (shape_key, base_mode, base_plan) = match mode {
        AddressMode::AbsoluteLong => (
            "direct",
            AddressMode::Absolute,
            "m65816_abs16_bank_fold_dbr",
        ),
        AddressMode::AbsoluteLongX => (
            "direct_x",
            AddressMode::AbsoluteX,
            "m65816_abs16_bank_fold_dbr",
        ),
        _ => return Vec::new(),
    };
    let has_short_alternative = FAMILY_INSTRUCTION_TABLE
        .iter()
        .any(|entry| entry.mode == base_mode && entry.mnemonic.eq_ignore_ascii_case(mnemonic));
    let long_plan = if has_short_alternative {
        "m65816_long_pref_u24"
    } else {
        "u24"
    };
    let mut selectors = vec![ModeSelectorDescriptor {
        owner: ScopedOwner::Cpu(M65816_CPU_ID.as_str().to_string()),
        mnemonic: mnemonic.to_string(),
        shape_key: shape_key.to_string(),
        mode_key: format!("{:?}", mode),
        operand_plan: long_plan.to_string(),
        priority: selector_priority(mode),
        unstable_widen: false,
        width_rank: selector_width_rank(mode),
    }];

    if has_short_alternative {
        selectors.push(ModeSelectorDescriptor {
            owner: ScopedOwner::Cpu(M65816_CPU_ID.as_str().to_string()),
            mnemonic: mnemonic.to_string(),
            shape_key: shape_key.to_string(),
            mode_key: format!("{:?}", base_mode),
            operand_plan: base_plan.to_string(),
            priority: selector_priority(base_mode),
            unstable_widen: false,
            width_rank: selector_width_rank(base_mode),
        });
    }

    selectors
}

fn selector_shape_key(mode: AddressMode) -> Option<&'static str> {
    match mode {
        AddressMode::Implied => Some("implied"),
        AddressMode::Accumulator => Some("accumulator"),
        AddressMode::Immediate => Some("immediate"),
        AddressMode::ZeroPage
        | AddressMode::Absolute
        | AddressMode::Relative
        | AddressMode::RelativeLong => Some("direct"),
        AddressMode::ZeroPageX | AddressMode::AbsoluteX => Some("direct_x"),
        AddressMode::ZeroPageY | AddressMode::AbsoluteY => Some("direct_y"),
        AddressMode::IndexedIndirectX | AddressMode::AbsoluteIndexedIndirect => {
            Some("indexed_indirect_x")
        }
        AddressMode::IndirectIndexedY => Some("indirect_indexed_y"),
        AddressMode::Indirect | AddressMode::ZeroPageIndirect => Some("indirect"),
        AddressMode::IndirectLong | AddressMode::DirectPageIndirectLong => Some("indirect_long"),
        AddressMode::DirectPageIndirectLongY => Some("indirect_long_y"),
        AddressMode::StackRelative => Some("stack_relative"),
        AddressMode::StackRelativeIndirectIndexedY => Some("stack_relative_indirect_y"),
        AddressMode::AbsoluteLong => Some("absolute_long"),
        AddressMode::AbsoluteLongX => Some("absolute_long_x"),
        AddressMode::BlockMove => Some("pair_direct"),
    }
}

fn selector_operand_plan(
    mode: AddressMode,
    mnemonic: &str,
    is_m65816: bool,
) -> Option<&'static str> {
    match mode {
        AddressMode::Implied | AddressMode::Accumulator => Some("none"),
        AddressMode::Immediate => {
            if is_m65816 && m65816_immediate_width_mnemonic(mnemonic) {
                Some("imm_mx")
            } else {
                Some("u8")
            }
        }
        AddressMode::Relative => Some("rel8"),
        AddressMode::RelativeLong => Some("rel16"),
        AddressMode::BlockMove => Some("u8u8_packed"),
        AddressMode::AbsoluteLong | AddressMode::AbsoluteLongX => Some("u24"),
        mode => {
            let size = mode.operand_size();
            match size {
                1 => Some("u8"),
                2 => Some("u16"),
                3 => Some("u24"),
                _ => None,
            }
        }
    }
}

fn selector_priority(mode: AddressMode) -> u16 {
    match mode {
        AddressMode::Relative | AddressMode::RelativeLong => 0,
        AddressMode::ZeroPage
        | AddressMode::ZeroPageX
        | AddressMode::ZeroPageY
        | AddressMode::IndexedIndirectX
        | AddressMode::IndirectIndexedY
        | AddressMode::ZeroPageIndirect
        | AddressMode::DirectPageIndirectLong
        | AddressMode::DirectPageIndirectLongY
        | AddressMode::StackRelative
        | AddressMode::StackRelativeIndirectIndexedY => 10,
        AddressMode::Absolute
        | AddressMode::AbsoluteX
        | AddressMode::AbsoluteY
        | AddressMode::Indirect
        | AddressMode::AbsoluteIndexedIndirect
        | AddressMode::IndirectLong => 20,
        AddressMode::AbsoluteLong | AddressMode::AbsoluteLongX => 30,
        AddressMode::BlockMove => 40,
        AddressMode::Implied | AddressMode::Accumulator | AddressMode::Immediate => 0,
    }
}

fn selector_width_rank(mode: AddressMode) -> u8 {
    match mode {
        AddressMode::ZeroPage
        | AddressMode::ZeroPageX
        | AddressMode::ZeroPageY
        | AddressMode::IndexedIndirectX
        | AddressMode::IndirectIndexedY
        | AddressMode::ZeroPageIndirect
        | AddressMode::DirectPageIndirectLong
        | AddressMode::DirectPageIndirectLongY
        | AddressMode::StackRelative
        | AddressMode::StackRelativeIndirectIndexedY => 1,
        AddressMode::Absolute
        | AddressMode::AbsoluteX
        | AddressMode::AbsoluteY
        | AddressMode::Indirect
        | AddressMode::AbsoluteIndexedIndirect
        | AddressMode::Relative
        | AddressMode::RelativeLong
        | AddressMode::IndirectLong => 2,
        AddressMode::AbsoluteLong | AddressMode::AbsoluteLongX => 3,
        AddressMode::Implied
        | AddressMode::Accumulator
        | AddressMode::Immediate
        | AddressMode::BlockMove => 0,
    }
}

fn m65816_immediate_width_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic.to_ascii_uppercase().as_str(),
        "ADC"
            | "AND"
            | "BIT"
            | "CMP"
            | "EOR"
            | "LDA"
            | "ORA"
            | "SBC"
            | "CPX"
            | "CPY"
            | "LDX"
            | "LDY"
    )
}

fn compile_m65c02_bit_branch_programs() -> Vec<VmProgramDescriptor> {
    let mut programs = Vec::with_capacity(16);
    for bit in 0u8..=7 {
        programs.push(VmProgramDescriptor {
            owner: ScopedOwner::Cpu(M65C02_CPU_ID.as_str().to_string()),
            mnemonic: format!("BBR{bit}"),
            mode_key: format!("{:?}", AddressMode::ZeroPage),
            program: compile_opcode_program(m65c02_bit_branch_opcode(bit, false), 2),
        });
        programs.push(VmProgramDescriptor {
            owner: ScopedOwner::Cpu(M65C02_CPU_ID.as_str().to_string()),
            mnemonic: format!("BBS{bit}"),
            mode_key: format!("{:?}", AddressMode::ZeroPage),
            program: compile_opcode_program(m65c02_bit_branch_opcode(bit, true), 2),
        });
    }
    programs
}

fn m65c02_bit_branch_opcode(bit: u8, is_set: bool) -> u8 {
    if is_set {
        0x8F + (bit << 4)
    } else {
        0x0F + (bit << 4)
    }
}

/// Build and encode an `.opcpu` container with hierarchy chunks from registry metadata.
///
/// This remains the primary Rust-table-driven authoring path for onboarding
/// new families/CPUs, even when runtime execution consumes loaded package bytes
/// as source of truth.
pub fn build_hierarchy_package_from_registry(
    registry: &ModuleRegistry,
) -> Result<Vec<u8>, HierarchyBuildError> {
    let chunks = build_hierarchy_chunks_from_registry(registry)?;
    encode_hierarchy_chunks_from_chunks(&chunks).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::registry::ModuleRegistry;
    use crate::families::intel8080::module::Intel8080FamilyModule;
    use crate::families::intel8080::table::lookup_instruction as lookup_intel_instruction;
    use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
    use crate::i8085::extensions::lookup_extension as lookup_i8085_extension;
    use crate::i8085::module::I8085CpuModule;
    use crate::m65816::module::M65816CpuModule;
    use crate::m65c02::module::M65C02CpuModule;
    use crate::opthread::intel8080_vm::{
        mode_key_for_instruction_entry, mode_key_for_z80_cb_register, mode_key_for_z80_half_index,
        mode_key_for_z80_indexed_cb, mode_key_for_z80_indexed_memory,
        mode_key_for_z80_interrupt_mode, mode_key_for_z80_ld_indirect,
    };
    use crate::opthread::package::{
        load_hierarchy_package, token_identifier_class, ParserVmOpcode, TokenizerVmOpcode,
        DIAG_OPTHREAD_MISSING_VM_PROGRAM, DIAG_PARSER_INVALID_STATEMENT,
        DIAG_TOKENIZER_INVALID_CHAR, PARSER_GRAMMAR_ID_LINE_V1,
    };
    use crate::opthread::runtime::HierarchyExecutionModel;
    use crate::z80::extensions::lookup_extension as lookup_z80_extension;
    use crate::z80::module::Z80CpuModule;

    fn test_registry() -> ModuleRegistry {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(Intel8080FamilyModule));
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(I8085CpuModule));
        registry.register_cpu(Box::new(Z80CpuModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
        registry
    }

    #[test]
    fn builder_emits_expected_hierarchy_shape() {
        let registry = test_registry();
        let chunks =
            build_hierarchy_chunks_from_registry(&registry).expect("builder should succeed");

        assert_eq!(chunks.families.len(), 2);
        assert_eq!(chunks.cpus.len(), 5);
        assert_eq!(chunks.dialects.len(), 3);
        assert!(chunks
            .diagnostics
            .iter()
            .any(|entry| entry.code == DIAG_OPTHREAD_MISSING_VM_PROGRAM));
        assert!(chunks
            .diagnostics
            .iter()
            .any(|entry| entry.code == DIAG_TOKENIZER_INVALID_CHAR));
        assert!(chunks
            .diagnostics
            .iter()
            .any(|entry| entry.code == DIAG_PARSER_INVALID_STATEMENT));
        assert!(!chunks.token_policies.is_empty());
        assert!(chunks.token_policies.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner == "mos6502")
                && entry.identifier_start_class
                    & (token_identifier_class::ASCII_ALPHA | token_identifier_class::UNDERSCORE)
                    != 0
        }));
        assert!(!chunks.parser_contracts.is_empty());
        assert!(chunks.parser_contracts.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner == "mos6502")
                && entry.grammar_id == PARSER_GRAMMAR_ID_LINE_V1
        }));
        assert!(!chunks.parser_vm_programs.is_empty());
        assert!(chunks.parser_vm_programs.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner == "mos6502")
                && entry
                    .program
                    .contains(&(ParserVmOpcode::ParseInstructionEnvelope as u8))
        }));
        assert!(!chunks.selectors.is_empty());
        assert!(chunks.registers.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner == "intel8080")
                && entry.id == "a"
        }));
        assert!(chunks.registers.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80") && entry.id == "ix"
        }));
        assert!(chunks.forms.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner == "intel8080")
                && entry.mnemonic == "mov"
        }));
        assert!(chunks.forms.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "djnz"
        }));
        assert!(chunks.forms.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Dialect(owner) if owner == "zilog")
                && entry.mnemonic == "ld"
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner == "mos6502")
                && entry.mnemonic == "lda"
                && entry.mode_key == "immediate"
        }));
        let mvi_a = lookup_intel_instruction("MVI", Some("A"), None).expect("MVI A exists");
        let rim = lookup_i8085_extension("RIM", None, None).expect("RIM exists");
        let djnz = lookup_z80_extension("DJNZ", None, None).expect("DJNZ exists");
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Family(owner) if owner == "intel8080")
                && entry.mnemonic == "mvi"
                && entry.mode_key == mode_key_for_instruction_entry(mvi_a)
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "8085")
                && entry.mnemonic == "rim"
                && entry.mode_key == mode_key_for_instruction_entry(rim)
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "djnz"
                && entry.mode_key == mode_key_for_instruction_entry(djnz)
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "im"
                && entry.mode_key == mode_key_for_z80_interrupt_mode(0).expect("valid mode key")
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "im"
                && entry.mode_key == mode_key_for_z80_interrupt_mode(1).expect("valid mode key")
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "im"
                && entry.mode_key == mode_key_for_z80_interrupt_mode(2).expect("valid mode key")
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "rlc"
                && entry.mode_key
                    == mode_key_for_z80_indexed_cb("IX", "RLC", None).expect("valid mode key")
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "bit"
                && entry.mode_key
                    == mode_key_for_z80_indexed_cb("IY", "BIT", Some(2)).expect("valid mode key")
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "bit"
                && entry.mode_key
                    == mode_key_for_z80_cb_register("BIT", Some(2), "M").expect("valid mode key")
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "ld"
                && entry.mode_key
                    == mode_key_for_z80_indexed_memory("IX", "ld_r_from_idx_a")
                        .expect("valid mode key")
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "ld"
                && entry.mode_key
                    == mode_key_for_z80_indexed_memory("IY", "ld_idx_imm").expect("valid mode key")
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "ld"
                && entry.mode_key
                    == mode_key_for_z80_ld_indirect("BC", false).expect("valid mode key")
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "ld"
                && entry.mode_key
                    == mode_key_for_z80_ld_indirect("IY", true).expect("valid mode key")
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "ld"
                && entry.mode_key
                    == mode_key_for_z80_half_index("IX", "LD", "rr:4:0").expect("valid mode key")
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "z80")
                && entry.mnemonic == "xor"
                && entry.mode_key
                    == mode_key_for_z80_half_index("IY", "XOR", "r:5").expect("valid mode key")
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "65c02")
                && entry.mnemonic == "bra"
                && entry.mode_key == "relative"
        }));
        assert!(chunks.tables.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "65c02")
                && entry.mnemonic == "bbr0"
                && entry.mode_key == "zeropage"
        }));
        assert!(chunks.selectors.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "65c02")
                && entry.mnemonic == "bbr0"
                && entry.shape_key == "pair_direct"
                && entry.operand_plan == "pair_u8_rel8"
        }));

        assert!(chunks
            .families
            .iter()
            .any(|fam| fam.id == "intel8080" && fam.canonical_dialect == "intel8080"));
        assert!(chunks
            .families
            .iter()
            .any(|fam| fam.id == "mos6502" && fam.canonical_dialect == "transparent"));
    }

    #[test]
    fn builder_emits_non_delegate_default_tokenizer_vm_programs() {
        let registry = test_registry();
        let chunks =
            build_hierarchy_chunks_from_registry(&registry).expect("builder should succeed");

        for program in &chunks.tokenizer_vm_programs {
            assert!(
                program
                    .program
                    .contains(&(TokenizerVmOpcode::ScanCoreToken as u8)),
                "default tokenizer VM program for {:?} must include ScanCoreToken",
                program.owner
            );
            assert!(
                !program
                    .program
                    .contains(&(TokenizerVmOpcode::DelegateCore as u8)),
                "default tokenizer VM program for {:?} must not depend on DelegateCore",
                program.owner
            );
        }
        for program in &chunks.parser_vm_programs {
            assert!(
                program
                    .program
                    .contains(&(ParserVmOpcode::ParseInstructionEnvelope as u8)),
                "default parser VM program for {:?} must include ParseInstructionEnvelope",
                program.owner
            );
            assert!(
                program
                    .program
                    .contains(&(ParserVmOpcode::EmitDiagIfNoAst as u8)),
                "default parser VM program for {:?} must include EmitDiagIfNoAst",
                program.owner
            );
            assert!(
                !program.program.contains(&0x01),
                "default parser VM program for {:?} must not require ParseCoreLine",
                program.owner
            );
            assert!(
                !program
                    .program
                    .contains(&(ParserVmOpcode::ParseStatementEnvelope as u8)),
                "default parser VM program for {:?} must not rely on ParseStatementEnvelope fallback",
                program.owner
            );
            assert!(
                program.program.ends_with(&[ParserVmOpcode::End as u8]),
                "default parser VM program for {:?} must terminate with End",
                program.owner
            );
        }
    }

    #[test]
    fn builder_package_round_trip_loads_and_resolves() {
        let registry = test_registry();
        let bytes =
            build_hierarchy_package_from_registry(&registry).expect("encoded package build failed");

        let package = load_hierarchy_package(&bytes).expect("package load should succeed");

        let z80 = package
            .resolve_pipeline("z80", None)
            .expect("z80 pipeline should resolve");
        assert_eq!(z80.family_id, "intel8080");
        assert_eq!(z80.dialect_id, "zilog");

        let c02 = package
            .resolve_pipeline("65c02", None)
            .expect("65c02 pipeline should resolve");
        assert_eq!(c02.family_id, "mos6502");
        assert_eq!(c02.dialect_id, "transparent");
    }

    #[test]
    fn builder_encoding_is_deterministic() {
        let registry = test_registry();
        let a = build_hierarchy_package_from_registry(&registry).expect("first build failed");
        let b = build_hierarchy_package_from_registry(&registry).expect("second build failed");
        assert_eq!(a, b);
    }

    #[test]
    fn builder_authoring_path_feeds_runtime_model_construction() {
        let registry = test_registry();
        let package_bytes =
            build_hierarchy_package_from_registry(&registry).expect("encoded package build failed");
        let model = HierarchyExecutionModel::from_package_bytes(package_bytes.as_slice())
            .expect("runtime model build from package bytes");

        assert!(model
            .supports_mnemonic("m6502", None, "lda")
            .expect("m6502 lda support query"));
        assert!(model
            .supports_mnemonic("8085", None, "mvi")
            .expect("8085 mvi support query"));
        assert!(model
            .supports_mnemonic("65816", None, "phx")
            .expect("65816 phx support query"));
        assert!(model
            .supports_mnemonic("65816", None, "phy")
            .expect("65816 phy support query"));
    }

    #[test]
    fn builder_mos_forms_have_matching_tabl_programs() {
        let registry = test_registry();
        let chunks =
            build_hierarchy_chunks_from_registry(&registry).expect("builder should succeed");

        assert_forms_have_tabl_programs_for_owner(
            &chunks,
            &ScopedOwner::Family(MOS6502_FAMILY_ID.as_str().to_string()),
        );
        assert_forms_have_tabl_programs_for_owner(
            &chunks,
            &ScopedOwner::Cpu(M65C02_CPU_ID.as_str().to_string()),
        );
        assert_forms_have_tabl_programs_for_owner(
            &chunks,
            &ScopedOwner::Cpu(M65816_CPU_ID.as_str().to_string()),
        );
    }

    #[test]
    fn builder_emits_m65816_force_mode_selectors() {
        let registry = test_registry();
        let chunks =
            build_hierarchy_chunks_from_registry(&registry).expect("builder should succeed");

        assert!(chunks.selectors.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "65816")
                && entry.mnemonic == "lda"
                && entry.shape_key == "immediate"
                && entry.mode_key == "immediate"
                && entry.operand_plan == "imm_mx"
        }));
        assert!(chunks.selectors.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "65816")
                && entry.mnemonic == "lda"
                && entry.shape_key == "direct:force_d"
                && entry.mode_key == "zeropage"
                && entry.operand_plan == "force_d_u8"
        }));
        assert!(chunks.selectors.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "65816")
                && entry.mnemonic == "lda"
                && entry.shape_key == "direct:force_b"
                && entry.mode_key == "absolute"
                && entry.operand_plan == "force_b_abs16_dbr"
        }));
        assert!(chunks.selectors.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "65816")
                && entry.mnemonic == "lda"
                && entry.shape_key == "direct:force_l"
                && entry.mode_key == "absolutelong"
                && entry.operand_plan == "force_l_u24"
        }));
        assert!(chunks.selectors.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "65816")
                && entry.mnemonic == "jmp"
                && entry.shape_key == "direct:force_k"
                && entry.mode_key == "absolute"
                && entry.operand_plan == "force_k_abs16_pbr"
        }));
        assert!(chunks.selectors.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "65816")
                && entry.mnemonic == "lda"
                && entry.shape_key == "direct"
                && entry.mode_key == "absolutelong"
                && entry.operand_plan == "m65816_long_pref_u24"
        }));
        assert!(chunks.selectors.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "65816")
                && entry.mnemonic == "lda"
                && entry.shape_key == "direct"
                && entry.mode_key == "absolute"
                && entry.operand_plan == "m65816_abs16_bank_fold_dbr"
        }));
        assert!(chunks.selectors.iter().any(|entry| {
            matches!(&entry.owner, ScopedOwner::Cpu(owner) if owner == "65816")
                && entry.mnemonic == "jsl"
                && entry.shape_key == "direct"
                && entry.mode_key == "absolutelong"
                && entry.operand_plan == "u24"
        }));
    }

    #[test]
    fn compile_mode_selector_builds_expected_descriptor_fields() {
        let selector = compile_mode_selector(
            ScopedOwner::Family("mos6502".to_string()),
            "lda",
            AddressMode::ZeroPage,
            false,
        )
        .expect("mode selector should compile");

        assert_eq!(selector.owner, ScopedOwner::Family("mos6502".to_string()));
        assert_eq!(selector.mnemonic, "lda");
        assert_eq!(selector.shape_key, "direct");
        assert_eq!(selector.mode_key, "ZeroPage");
        assert_eq!(selector.operand_plan, "u8");
        assert_eq!(selector.priority, 10);
        assert!(selector.unstable_widen);
        assert_eq!(selector.width_rank, 1);
    }

    #[test]
    fn selector_priority_orders_modes_by_specificity() {
        assert_eq!(selector_priority(AddressMode::Immediate), 0);
        assert_eq!(selector_priority(AddressMode::Relative), 0);
        assert_eq!(selector_priority(AddressMode::ZeroPage), 10);
        assert_eq!(selector_priority(AddressMode::Absolute), 20);
        assert_eq!(selector_priority(AddressMode::AbsoluteLong), 30);
        assert_eq!(selector_priority(AddressMode::BlockMove), 40);
    }

    #[test]
    fn selector_width_rank_tracks_operand_width_classes() {
        assert_eq!(selector_width_rank(AddressMode::Immediate), 0);
        assert_eq!(selector_width_rank(AddressMode::ZeroPage), 1);
        assert_eq!(selector_width_rank(AddressMode::Absolute), 2);
        assert_eq!(selector_width_rank(AddressMode::AbsoluteLong), 3);
    }

    fn assert_forms_have_tabl_programs_for_owner(chunks: &HierarchyChunks, owner: &ScopedOwner) {
        let form_mnemonics: std::collections::HashSet<String> = chunks
            .forms
            .iter()
            .filter(|entry| entry.owner == *owner)
            .map(|entry| entry.mnemonic.to_ascii_lowercase())
            .collect();
        let tabl_mnemonics: std::collections::HashSet<String> = chunks
            .tables
            .iter()
            .filter(|entry| entry.owner == *owner)
            .map(|entry| entry.mnemonic.to_ascii_lowercase())
            .collect();

        for mnemonic in form_mnemonics {
            assert!(
                tabl_mnemonics.contains(&mnemonic),
                "owner {:?} missing TABL program for mnemonic '{}'",
                owner,
                mnemonic
            );
        }
    }
}
