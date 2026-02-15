// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Build opThread hierarchy chunks from the live opForge module registry.

use crate::core::registry::ModuleRegistry;
use crate::families::mos6502::module::FAMILY_ID as MOS6502_FAMILY_ID;
use crate::families::mos6502::{AddressMode, FAMILY_INSTRUCTION_TABLE};
use crate::m65816::instructions::CPU_INSTRUCTION_TABLE as M65816_CPU_INSTRUCTION_TABLE;
use crate::m65816::module::CPU_ID as M65816_CPU_ID;
use crate::m65c02::instructions::CPU_INSTRUCTION_TABLE as M65C02_CPU_INSTRUCTION_TABLE;
use crate::m65c02::module::CPU_ID as M65C02_CPU_ID;
use crate::opthread::hierarchy::{
    CpuDescriptor, DialectDescriptor, FamilyDescriptor, HierarchyError, HierarchyPackage,
    ScopedFormDescriptor, ScopedOwner, ScopedRegisterDescriptor,
};
use crate::opthread::package::{
    canonicalize_hierarchy_metadata, encode_hierarchy_chunks_full, HierarchyChunks,
    ModeSelectorDescriptor, OpcpuCodecError, VmProgramDescriptor,
};
use crate::opthread::vm::{OP_EMIT_OPERAND, OP_EMIT_U8, OP_END};

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

/// Build `FAMS`/`CPUS`/`DIAL`/`REGS`/`FORM`/`TABL` chunks from registry metadata.
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

    // Ensure the materialized metadata is coherent before returning.
    HierarchyPackage::new(families.clone(), cpus.clone(), dialects.clone())?;

    Ok(HierarchyChunks {
        families,
        cpus,
        dialects,
        registers,
        forms,
        tables,
        selectors,
    })
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
pub fn build_hierarchy_package_from_registry(
    registry: &ModuleRegistry,
) -> Result<Vec<u8>, HierarchyBuildError> {
    let chunks = build_hierarchy_chunks_from_registry(registry)?;
    encode_hierarchy_chunks_full(
        &chunks.families,
        &chunks.cpus,
        &chunks.dialects,
        &chunks.registers,
        &chunks.forms,
        &chunks.tables,
        &chunks.selectors,
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::registry::ModuleRegistry;
    use crate::families::intel8080::module::Intel8080FamilyModule;
    use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
    use crate::i8085::module::I8085CpuModule;
    use crate::m65816::module::M65816CpuModule;
    use crate::m65c02::module::M65C02CpuModule;
    use crate::opthread::package::load_hierarchy_package;
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
