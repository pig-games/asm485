// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Host/runtime bridge helpers for hierarchy-aware target selection.

use std::collections::{HashMap, HashSet};

use crate::core::family::{expr_has_unstable_symbols, AssemblerContext};
use crate::core::parser::{BinaryOp, Expr};
use crate::core::registry::{ModuleRegistry, OperandSet, VmEncodeCandidate};
use crate::opthread::builder::{build_hierarchy_chunks_from_registry, HierarchyBuildError};
use crate::opthread::hierarchy::{
    HierarchyError, HierarchyPackage, ResolvedHierarchy, ResolvedHierarchyContext, ScopedOwner,
};
use crate::opthread::package::HierarchyChunks;
use crate::opthread::vm::{execute_program, VmError};

/// Errors emitted by the opThread host/runtime bridge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeBridgeError {
    ActiveCpuNotSet,
    Build(HierarchyBuildError),
    Hierarchy(HierarchyError),
    Resolve(String),
    Vm(VmError),
}

impl std::fmt::Display for RuntimeBridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActiveCpuNotSet => write!(f, "active cpu is not set"),
            Self::Build(err) => write!(f, "runtime model build error: {}", err),
            Self::Hierarchy(err) => write!(f, "hierarchy resolution error: {}", err),
            Self::Resolve(err) => write!(f, "{}", err),
            Self::Vm(err) => write!(f, "VM encode error: {}", err),
        }
    }
}

impl std::error::Error for RuntimeBridgeError {}

impl From<HierarchyError> for RuntimeBridgeError {
    fn from(value: HierarchyError) -> Self {
        Self::Hierarchy(value)
    }
}

impl From<HierarchyBuildError> for RuntimeBridgeError {
    fn from(value: HierarchyBuildError) -> Self {
        Self::Build(value)
    }
}

impl From<VmError> for RuntimeBridgeError {
    fn from(value: VmError) -> Self {
        Self::Vm(value)
    }
}

/// Small bridge state that mirrors host-side active target selection APIs.
#[derive(Debug)]
pub struct HierarchyRuntimeBridge {
    package: HierarchyPackage,
    active_cpu: Option<String>,
    dialect_override: Option<String>,
}

impl HierarchyRuntimeBridge {
    pub fn new(package: HierarchyPackage) -> Self {
        Self {
            package,
            active_cpu: None,
            dialect_override: None,
        }
    }

    pub fn active_cpu(&self) -> Option<&str> {
        self.active_cpu.as_deref()
    }

    pub fn dialect_override(&self) -> Option<&str> {
        self.dialect_override.as_deref()
    }

    pub fn set_active_cpu(&mut self, cpu_id: &str) -> Result<(), RuntimeBridgeError> {
        self.package
            .resolve_pipeline(cpu_id, self.dialect_override.as_deref())?;
        self.active_cpu = Some(cpu_id.to_string());
        Ok(())
    }

    pub fn set_dialect_override(
        &mut self,
        dialect_override: Option<&str>,
    ) -> Result<(), RuntimeBridgeError> {
        if let Some(cpu_id) = self.active_cpu.as_deref() {
            self.package.resolve_pipeline(cpu_id, dialect_override)?;
        }
        self.dialect_override = dialect_override.map(ToString::to_string);
        Ok(())
    }

    pub fn resolve_pipeline(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<ResolvedHierarchy, RuntimeBridgeError> {
        self.package
            .resolve_pipeline(cpu_id, dialect_override)
            .map_err(Into::into)
    }

    pub fn resolve_active_pipeline(&self) -> Result<ResolvedHierarchy, RuntimeBridgeError> {
        let cpu_id = self
            .active_cpu
            .as_deref()
            .ok_or(RuntimeBridgeError::ActiveCpuNotSet)?;
        self.resolve_pipeline(cpu_id, self.dialect_override.as_deref())
    }

    pub fn resolve_active_pipeline_context(
        &self,
    ) -> Result<ResolvedHierarchyContext<'_>, RuntimeBridgeError> {
        let cpu_id = self
            .active_cpu
            .as_deref()
            .ok_or(RuntimeBridgeError::ActiveCpuNotSet)?;
        self.package
            .resolve_pipeline_context(cpu_id, self.dialect_override.as_deref())
            .map_err(Into::into)
    }
}

/// Runtime view with resolved hierarchy bridge and scoped FORM ownership sets.
#[derive(Debug)]
pub struct HierarchyExecutionModel {
    bridge: HierarchyRuntimeBridge,
    family_forms: HashMap<String, HashSet<String>>,
    cpu_forms: HashMap<String, HashSet<String>>,
    dialect_forms: HashMap<String, HashSet<String>>,
    vm_programs: HashMap<(u8, String, String, String), Vec<u8>>,
}

impl HierarchyExecutionModel {
    pub fn from_registry(registry: &ModuleRegistry) -> Result<Self, RuntimeBridgeError> {
        let chunks = build_hierarchy_chunks_from_registry(registry)?;
        Self::from_chunks(chunks)
    }

    pub fn from_chunks(chunks: HierarchyChunks) -> Result<Self, RuntimeBridgeError> {
        let package = HierarchyPackage::new(chunks.families, chunks.cpus, chunks.dialects)?;
        let mut vm_programs = HashMap::new();
        for entry in chunks.tables {
            let (owner_tag, owner_id) = owner_key_parts(&entry.owner);
            vm_programs.insert(
                (
                    owner_tag,
                    owner_id,
                    entry.mnemonic.to_ascii_lowercase(),
                    entry.mode_key.to_ascii_lowercase(),
                ),
                entry.program,
            );
        }
        let mut family_forms: HashMap<String, HashSet<String>> = HashMap::new();
        let mut cpu_forms: HashMap<String, HashSet<String>> = HashMap::new();
        let mut dialect_forms: HashMap<String, HashSet<String>> = HashMap::new();
        for form in chunks.forms {
            let mnemonic = form.mnemonic.to_ascii_lowercase();
            match form.owner {
                ScopedOwner::Family(owner) => {
                    family_forms
                        .entry(owner.to_ascii_lowercase())
                        .or_default()
                        .insert(mnemonic);
                }
                ScopedOwner::Cpu(owner) => {
                    cpu_forms
                        .entry(owner.to_ascii_lowercase())
                        .or_default()
                        .insert(mnemonic);
                }
                ScopedOwner::Dialect(owner) => {
                    dialect_forms
                        .entry(owner.to_ascii_lowercase())
                        .or_default()
                        .insert(mnemonic);
                }
            }
        }

        Ok(Self {
            bridge: HierarchyRuntimeBridge::new(package),
            family_forms,
            cpu_forms,
            dialect_forms,
            vm_programs,
        })
    }

    pub fn set_active_cpu(&mut self, cpu_id: &str) -> Result<(), RuntimeBridgeError> {
        self.bridge.set_active_cpu(cpu_id)
    }

    pub fn resolve_pipeline(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<ResolvedHierarchy, RuntimeBridgeError> {
        self.bridge.resolve_pipeline(cpu_id, dialect_override)
    }

    pub fn supports_mnemonic(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        mnemonic: &str,
    ) -> Result<bool, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        let needle = mnemonic.to_ascii_lowercase();

        if contains_form(&self.dialect_forms, &resolved.dialect_id, &needle) {
            return Ok(true);
        }
        if contains_form(&self.cpu_forms, &resolved.cpu_id, &needle) {
            return Ok(true);
        }
        Ok(contains_form(
            &self.family_forms,
            &resolved.family_id,
            &needle,
        ))
    }

    pub fn encode_instruction(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        mnemonic: &str,
        operands: &dyn OperandSet,
    ) -> Result<Option<Vec<u8>>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        let candidates = operands.vm_encode_candidates();
        if candidates.is_empty() {
            return Ok(None);
        }
        self.encode_candidates(&resolved, mnemonic, &candidates)
    }

    pub fn encode_instruction_from_exprs(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        mnemonic: &str,
        operands: &[Expr],
        ctx: &dyn AssemblerContext,
    ) -> Result<Option<Vec<u8>>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        if !resolved.family_id.eq_ignore_ascii_case("mos6502")
            || !resolved.cpu_id.eq_ignore_ascii_case("m6502")
        {
            return Ok(None);
        }
        let Some(candidates) = m6502_vm_encode_candidates_from_exprs(mnemonic, operands, ctx)
            .map_err(RuntimeBridgeError::Resolve)?
        else {
            return Ok(None);
        };
        self.encode_candidates(&resolved, mnemonic, &candidates)
    }

    fn encode_candidates(
        &self,
        resolved: &ResolvedHierarchy,
        mnemonic: &str,
        candidates: &[VmEncodeCandidate],
    ) -> Result<Option<Vec<u8>>, RuntimeBridgeError> {
        let normalized_mnemonic = mnemonic.to_ascii_lowercase();
        let owner_order = [
            (2u8, resolved.dialect_id.as_str()),
            (1u8, resolved.cpu_id.as_str()),
            (0u8, resolved.family_id.as_str()),
        ];

        for candidate in candidates {
            let mode_key = candidate.mode_key.to_ascii_lowercase();
            let operand_views: Vec<&[u8]> =
                candidate.operand_bytes.iter().map(Vec::as_slice).collect();
            for (owner_tag, owner_id) in &owner_order {
                let key = (
                    *owner_tag,
                    owner_id.to_ascii_lowercase(),
                    normalized_mnemonic.clone(),
                    mode_key.clone(),
                );
                if let Some(program) = self.vm_programs.get(&key) {
                    return execute_program(program, operand_views.as_slice())
                        .map(Some)
                        .map_err(Into::into);
                }
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug)]
enum M6502OperandExprShape<'a> {
    Implied,
    Accumulator,
    Immediate(&'a Expr),
    Direct(&'a Expr),
    DirectX(&'a Expr),
    DirectY(&'a Expr),
    IndexedIndirectX(&'a Expr),
    IndirectIndexedY(&'a Expr),
    Indirect(&'a Expr),
}

fn m6502_vm_encode_candidates_from_exprs(
    mnemonic: &str,
    operands: &[Expr],
    ctx: &dyn AssemblerContext,
) -> Result<Option<Vec<VmEncodeCandidate>>, String> {
    let Some(shape) = parse_m6502_operand_expr_shape(operands) else {
        return Ok(None);
    };
    let upper_mnemonic = mnemonic.to_ascii_uppercase();
    let mut out = Vec::new();

    match shape {
        M6502OperandExprShape::Implied => out.push(vm_candidate("implied", Vec::new())),
        M6502OperandExprShape::Accumulator => {
            out.push(vm_candidate("accumulator", Vec::new()));
        }
        M6502OperandExprShape::Immediate(expr) => {
            let value = ctx.eval_expr(expr)?;
            if !(0..=255).contains(&value) {
                return Err(format!("Immediate value {} out of range (0-255)", value));
            }
            out.push(vm_candidate("immediate", vec![vec![value as u8]]));
        }
        M6502OperandExprShape::Direct(expr) => {
            let value = ctx.eval_expr(expr)?;
            if is_m6502_branch_mnemonic(&upper_mnemonic) {
                let current = ctx.current_address() as i64 + 2;
                let offset = value - current;
                if !(-128..=127).contains(&offset) {
                    if ctx.pass() > 1 {
                        return Err(format!("Branch target out of range: offset {}", offset));
                    }
                    out.push(vm_candidate("relative", vec![vec![0]]));
                } else {
                    out.push(vm_candidate("relative", vec![vec![offset as i8 as u8]]));
                }
            } else if (0..=255).contains(&value) {
                let zp_bytes = vec![vec![value as u8]];
                let abs_bytes = vec![u16le_bytes(value as u16)];
                if expr_has_unstable_symbols(expr, ctx) {
                    out.push(vm_candidate("absolute", abs_bytes));
                    out.push(vm_candidate("zeropage", zp_bytes));
                } else {
                    out.push(vm_candidate("zeropage", zp_bytes));
                    out.push(vm_candidate("absolute", abs_bytes));
                }
            } else if (0..=65535).contains(&value) {
                out.push(vm_candidate("absolute", vec![u16le_bytes(value as u16)]));
            } else {
                return Err(format!("Address {} out of 16-bit range", value));
            }
        }
        M6502OperandExprShape::DirectX(expr) => {
            let value = ctx.eval_expr(expr)?;
            if (0..=255).contains(&value) {
                let zp_bytes = vec![vec![value as u8]];
                let abs_bytes = vec![u16le_bytes(value as u16)];
                if expr_has_unstable_symbols(expr, ctx) {
                    out.push(vm_candidate("absolutex", abs_bytes));
                    out.push(vm_candidate("zeropagex", zp_bytes));
                } else {
                    out.push(vm_candidate("zeropagex", zp_bytes));
                    out.push(vm_candidate("absolutex", abs_bytes));
                }
            } else if (0..=65535).contains(&value) {
                out.push(vm_candidate("absolutex", vec![u16le_bytes(value as u16)]));
            } else {
                return Err(format!("Address {} out of 16-bit range", value));
            }
        }
        M6502OperandExprShape::DirectY(expr) => {
            let value = ctx.eval_expr(expr)?;
            if (0..=255).contains(&value) {
                let zp_bytes = vec![vec![value as u8]];
                let abs_bytes = vec![u16le_bytes(value as u16)];
                if expr_has_unstable_symbols(expr, ctx) {
                    out.push(vm_candidate("absolutey", abs_bytes));
                    out.push(vm_candidate("zeropagey", zp_bytes));
                } else {
                    out.push(vm_candidate("zeropagey", zp_bytes));
                    out.push(vm_candidate("absolutey", abs_bytes));
                }
            } else if (0..=65535).contains(&value) {
                out.push(vm_candidate("absolutey", vec![u16le_bytes(value as u16)]));
            } else {
                return Err(format!("Address {} out of 16-bit range", value));
            }
        }
        M6502OperandExprShape::IndexedIndirectX(expr) => {
            let value = ctx.eval_expr(expr)?;
            if !(0..=255).contains(&value) {
                return Err(format!(
                    "Indexed indirect address {} out of zero page range",
                    value
                ));
            }
            out.push(vm_candidate("indexedindirectx", vec![vec![value as u8]]));
        }
        M6502OperandExprShape::IndirectIndexedY(expr) => {
            let value = ctx.eval_expr(expr)?;
            if !(0..=255).contains(&value) {
                return Err(format!(
                    "Indirect indexed address {} out of zero page range",
                    value
                ));
            }
            out.push(vm_candidate("indirectindexedy", vec![vec![value as u8]]));
        }
        M6502OperandExprShape::Indirect(expr) => {
            if !upper_mnemonic.eq_ignore_ascii_case("JMP") {
                return Ok(None);
            }
            let value = ctx.eval_expr(expr)?;
            if !(0..=65535).contains(&value) {
                return Err(format!("Indirect address {} out of 16-bit range", value));
            }
            out.push(vm_candidate("indirect", vec![u16le_bytes(value as u16)]));
        }
    }

    Ok(Some(out))
}

fn parse_m6502_operand_expr_shape(operands: &[Expr]) -> Option<M6502OperandExprShape<'_>> {
    match operands {
        [] => Some(M6502OperandExprShape::Implied),
        [single] => match single {
            Expr::Register(name, _) if name.eq_ignore_ascii_case("a") => {
                Some(M6502OperandExprShape::Accumulator)
            }
            Expr::Immediate(inner, _) => Some(M6502OperandExprShape::Immediate(inner.as_ref())),
            Expr::Indirect(inner, _) => parse_indirect_single_shape(inner),
            _ => Some(M6502OperandExprShape::Direct(single)),
        },
        [base, index] => {
            let index_name = expr_identifier(index)?;
            if index_name.eq_ignore_ascii_case("x") {
                return Some(M6502OperandExprShape::DirectX(base));
            }
            if index_name.eq_ignore_ascii_case("y") {
                if let Expr::Indirect(inner, _) = base {
                    if let Expr::Tuple(elements, _) = inner.as_ref() {
                        if elements.len() == 2
                            && expr_identifier(&elements[1])
                                .is_some_and(|name| name.eq_ignore_ascii_case("s"))
                        {
                            return None;
                        }
                    }
                    return Some(M6502OperandExprShape::IndirectIndexedY(inner.as_ref()));
                }
                return Some(M6502OperandExprShape::DirectY(base));
            }
            None
        }
        _ => None,
    }
}

fn parse_indirect_single_shape(expr: &Expr) -> Option<M6502OperandExprShape<'_>> {
    if let Expr::Tuple(elements, _) = expr {
        if elements.len() == 2 {
            let index = expr_identifier(&elements[1])?;
            if index.eq_ignore_ascii_case("x") {
                return Some(M6502OperandExprShape::IndexedIndirectX(&elements[0]));
            }
            return None;
        }
        return None;
    }
    Some(M6502OperandExprShape::Indirect(expr))
}

fn expr_identifier(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Identifier(name, _) | Expr::Register(name, _) => Some(name.as_str()),
        Expr::Unary { expr, .. } => expr_identifier(expr),
        Expr::Binary {
            op: BinaryOp::Add,
            left,
            right,
            ..
        } => expr_identifier(left).or_else(|| expr_identifier(right)),
        _ => None,
    }
}

fn vm_candidate(mode_key: &str, operand_bytes: Vec<Vec<u8>>) -> VmEncodeCandidate {
    VmEncodeCandidate {
        mode_key: mode_key.to_string(),
        operand_bytes,
    }
}

fn u16le_bytes(value: u16) -> Vec<u8> {
    vec![(value & 0xFF) as u8, (value >> 8) as u8]
}

fn is_m6502_branch_mnemonic(upper_mnemonic: &str) -> bool {
    matches!(
        upper_mnemonic,
        "BCC" | "BCS" | "BEQ" | "BNE" | "BMI" | "BPL" | "BVC" | "BVS"
    )
}

fn owner_key_parts(owner: &ScopedOwner) -> (u8, String) {
    match owner {
        ScopedOwner::Family(id) => (0u8, id.to_ascii_lowercase()),
        ScopedOwner::Cpu(id) => (1u8, id.to_ascii_lowercase()),
        ScopedOwner::Dialect(id) => (2u8, id.to_ascii_lowercase()),
    }
}

fn contains_form(map: &HashMap<String, HashSet<String>>, owner_id: &str, mnemonic: &str) -> bool {
    map.get(&owner_id.to_ascii_lowercase())
        .is_some_and(|forms| forms.contains(mnemonic))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::family::AssemblerContext;
    use crate::core::parser::Expr;
    use crate::core::registry::ModuleRegistry;
    use crate::core::tokenizer::Span;
    use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule, MOS6502Operands};
    use crate::families::mos6502::Operand;
    use crate::m65816::module::M65816CpuModule;
    use crate::m65c02::module::M65C02CpuModule;
    use crate::opthread::builder::build_hierarchy_chunks_from_registry;
    use crate::opthread::hierarchy::{CpuDescriptor, DialectDescriptor, FamilyDescriptor};
    use crate::opthread::vm::{OP_EMIT_OPERAND, OP_EMIT_U8, OP_END};
    use std::collections::HashMap;

    struct TestAssemblerContext {
        values: HashMap<String, i64>,
        finalized: HashMap<String, bool>,
        addr: u32,
        pass: u8,
    }

    impl TestAssemblerContext {
        fn new() -> Self {
            Self {
                values: HashMap::new(),
                finalized: HashMap::new(),
                addr: 0,
                pass: 2,
            }
        }
    }

    impl AssemblerContext for TestAssemblerContext {
        fn eval_expr(&self, expr: &Expr) -> Result<i64, String> {
            match expr {
                Expr::Number(text, _) => text
                    .parse::<i64>()
                    .map_err(|_| format!("invalid test number '{}'", text)),
                Expr::Identifier(name, _) | Expr::Register(name, _) => self
                    .values
                    .get(name)
                    .copied()
                    .ok_or_else(|| format!("Label not found: {}", name)),
                Expr::Immediate(inner, _) => self.eval_expr(inner),
                _ => Err("unsupported test expression".to_string()),
            }
        }

        fn symbols(&self) -> &crate::core::symbol_table::SymbolTable {
            panic!("symbols() is not used in runtime resolver tests")
        }

        fn has_symbol(&self, name: &str) -> bool {
            self.values.contains_key(name)
        }

        fn symbol_is_finalized(&self, name: &str) -> Option<bool> {
            self.finalized.get(name).copied()
        }

        fn current_address(&self) -> u32 {
            self.addr
        }

        fn pass(&self) -> u8 {
            self.pass
        }
    }

    fn sample_package() -> HierarchyPackage {
        HierarchyPackage::new(
            vec![
                FamilyDescriptor {
                    id: "intel8080".to_string(),
                    canonical_dialect: "intel".to_string(),
                },
                FamilyDescriptor {
                    id: "mos6502".to_string(),
                    canonical_dialect: "mos".to_string(),
                },
            ],
            vec![
                CpuDescriptor {
                    id: "8085".to_string(),
                    family_id: "intel8080".to_string(),
                    default_dialect: Some("intel".to_string()),
                },
                CpuDescriptor {
                    id: "z80".to_string(),
                    family_id: "intel8080".to_string(),
                    default_dialect: Some("zilog".to_string()),
                },
                CpuDescriptor {
                    id: "6502".to_string(),
                    family_id: "mos6502".to_string(),
                    default_dialect: Some("mos".to_string()),
                },
            ],
            vec![
                DialectDescriptor {
                    id: "intel".to_string(),
                    family_id: "intel8080".to_string(),
                    cpu_allow_list: None,
                },
                DialectDescriptor {
                    id: "zilog".to_string(),
                    family_id: "intel8080".to_string(),
                    cpu_allow_list: Some(vec!["z80".to_string()]),
                },
                DialectDescriptor {
                    id: "mos".to_string(),
                    family_id: "mos6502".to_string(),
                    cpu_allow_list: None,
                },
            ],
        )
        .expect("sample package should validate")
    }

    #[test]
    fn active_cpu_selection_and_resolution_work() {
        let mut bridge = HierarchyRuntimeBridge::new(sample_package());

        assert!(matches!(
            bridge.resolve_active_pipeline(),
            Err(RuntimeBridgeError::ActiveCpuNotSet)
        ));

        bridge.set_active_cpu("z80").expect("set active cpu");
        let resolved = bridge
            .resolve_active_pipeline()
            .expect("active cpu should resolve");
        assert_eq!(resolved.family_id, "intel8080");
        assert_eq!(resolved.dialect_id, "zilog");
    }

    #[test]
    fn explicit_resolve_pipeline_supports_override() {
        let bridge = HierarchyRuntimeBridge::new(sample_package());

        let resolved = bridge
            .resolve_pipeline("8085", Some("intel"))
            .expect("explicit resolve should succeed");
        assert_eq!(resolved.cpu_id, "8085");
        assert_eq!(resolved.dialect_id, "intel");
    }

    #[test]
    fn override_validation_uses_active_cpu_context() {
        let mut bridge = HierarchyRuntimeBridge::new(sample_package());
        bridge.set_active_cpu("8085").expect("set active cpu");

        let err = bridge
            .set_dialect_override(Some("zilog"))
            .expect_err("zilog should be blocked for 8085");
        assert!(matches!(
            err,
            RuntimeBridgeError::Hierarchy(HierarchyError::CpuBlockedByDialectAllowList { .. })
        ));

        bridge
            .set_dialect_override(Some("intel"))
            .expect("intel override should pass");
        assert_eq!(bridge.dialect_override(), Some("intel"));
    }

    #[test]
    fn execution_model_supports_family_and_cpu_forms() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        assert!(model
            .supports_mnemonic("m6502", None, "lda")
            .expect("resolve lda"));
        assert!(!model
            .supports_mnemonic("m6502", None, "bra")
            .expect("resolve bra"));
        assert!(model
            .supports_mnemonic("65c02", None, "bra")
            .expect("resolve bra for 65c02"));
    }

    #[test]
    fn execution_model_encodes_base_6502_instruction_via_vm() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let operands = MOS6502Operands(vec![Operand::Immediate(0x42, Span::default())]);
        let bytes = model
            .encode_instruction("m6502", None, "LDA", &operands)
            .expect("vm encode should succeed");
        assert_eq!(bytes, Some(vec![0xA9, 0x42]));
    }

    #[test]
    fn execution_model_vm_encode_supports_m65c02_cpu_tables() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let operands = MOS6502Operands(vec![Operand::Relative(2, Span::default())]);
        let bytes = model
            .encode_instruction("65c02", None, "BRA", &operands)
            .expect("vm encode should resolve");
        assert_eq!(bytes, Some(vec![0x80, 0x02]));
    }

    #[test]
    fn execution_model_encodes_m6502_instruction_from_expr_operands() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let span = Span::default();
        let operands = vec![Expr::Immediate(
            Box::new(Expr::Number("66".to_string(), span)),
            span,
        )];
        let ctx = TestAssemblerContext::new();
        let bytes = model
            .encode_instruction_from_exprs("m6502", None, "LDA", &operands, &ctx)
            .expect("vm expr encode should succeed");
        assert_eq!(bytes, Some(vec![0xA9, 0x42]));
    }

    #[test]
    fn m6502_expr_candidates_prefer_absolute_for_unstable_symbols() {
        let span = Span::default();
        let expr = Expr::Identifier("target".to_string(), span);
        let mut ctx = TestAssemblerContext::new();
        ctx.values.insert("target".to_string(), 0x10);
        ctx.finalized.insert("target".to_string(), false);
        let candidates = m6502_vm_encode_candidates_from_exprs("LDA", &[expr], &ctx)
            .expect("candidate build")
            .expect("m6502 resolver should support direct expression");
        assert_eq!(candidates[0].mode_key, "absolute");
        assert_eq!(candidates[1].mode_key, "zeropage");
    }

    #[test]
    fn execution_model_vm_encode_supports_m65c02_bit_branch_tables() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let operands = MOS6502Operands(vec![
            Operand::ZeroPage(0x12, Span::default()),
            Operand::Relative(0x05, Span::default()),
        ]);
        let bytes = model
            .encode_instruction("65c02", None, "BBR0", &operands)
            .expect("vm encode should resolve");
        assert_eq!(bytes, Some(vec![0x0F, 0x12, 0x05]));
    }

    #[test]
    fn execution_model_uses_package_tabl_programs_for_vm_encode() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let mut chunks =
            build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
        let mut patched = false;
        for program in &mut chunks.tables {
            let is_mos6502_family_owner = matches!(&program.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"));
            if is_mos6502_family_owner
                && program.mnemonic.eq_ignore_ascii_case("lda")
                && program.mode_key.eq_ignore_ascii_case("immediate")
            {
                program.program = vec![OP_EMIT_U8, 0xEA, OP_EMIT_OPERAND, 0x00, OP_END];
                patched = true;
                break;
            }
        }
        assert!(
            patched,
            "expected to patch LDA immediate VM program in TABL"
        );

        let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
        let operands = MOS6502Operands(vec![Operand::Immediate(0x42, Span::default())]);
        let bytes = model
            .encode_instruction("m6502", None, "LDA", &operands)
            .expect("vm encode should succeed")
            .expect("m6502 vm program should be available");
        assert_eq!(bytes, vec![0xEA, 0x42]);
    }

    #[test]
    fn execution_model_returns_none_when_target_has_no_tabl_programs() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let mut chunks =
            build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
        chunks.tables.clear();

        let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
        let operands = MOS6502Operands(vec![Operand::Immediate(0x42, Span::default())]);
        let bytes = model
            .encode_instruction("m6502", None, "LDA", &operands)
            .expect("vm encode should resolve");
        assert!(bytes.is_none());
    }

    #[test]
    fn execution_model_vm_encode_supports_m65816_cpu_tables() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let operands = MOS6502Operands(vec![Operand::AbsoluteLong(0x001234, Span::default())]);
        let bytes = model
            .encode_instruction("65816", None, "JSL", &operands)
            .expect("vm encode should resolve");
        assert_eq!(bytes, Some(vec![0x22, 0x34, 0x12, 0x00]));
    }
}
