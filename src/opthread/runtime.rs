// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Host/runtime bridge helpers for hierarchy-aware target selection.

use std::collections::{HashMap, HashSet};

use crate::core::family::{expr_has_unstable_symbols, AssemblerContext, FamilyHandler};
use crate::core::parser::Expr;
use crate::core::registry::{ModuleRegistry, OperandSet, VmEncodeCandidate};
use crate::families::mos6502::{AddressMode, FamilyOperand, MOS6502FamilyHandler, OperandForce};
use crate::m65816::state;
use crate::opthread::builder::{build_hierarchy_chunks_from_registry, HierarchyBuildError};
use crate::opthread::hierarchy::{
    HierarchyError, HierarchyPackage, ResolvedHierarchy, ResolvedHierarchyContext, ScopedOwner,
};
use crate::opthread::package::{HierarchyChunks, ModeSelectorDescriptor};
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
    mode_selectors: HashMap<(u8, String, String, String), Vec<ModeSelectorDescriptor>>,
}

impl HierarchyExecutionModel {
    pub fn from_registry(registry: &ModuleRegistry) -> Result<Self, RuntimeBridgeError> {
        let chunks = build_hierarchy_chunks_from_registry(registry)?;
        Self::from_chunks(chunks)
    }

    pub fn from_chunks(chunks: HierarchyChunks) -> Result<Self, RuntimeBridgeError> {
        let HierarchyChunks {
            families,
            cpus,
            dialects,
            registers: _,
            forms,
            tables,
            selectors,
        } = chunks;
        let package = HierarchyPackage::new(families, cpus, dialects)?;
        let mut vm_programs = HashMap::new();
        for entry in tables {
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
        let mut mode_selectors: HashMap<(u8, String, String, String), Vec<ModeSelectorDescriptor>> =
            HashMap::new();
        for entry in selectors {
            let (owner_tag, owner_id) = owner_key_parts(&entry.owner);
            mode_selectors
                .entry((
                    owner_tag,
                    owner_id,
                    entry.mnemonic.to_ascii_lowercase(),
                    entry.shape_key.to_ascii_lowercase(),
                ))
                .or_default()
                .push(entry);
        }
        for entries in mode_selectors.values_mut() {
            entries.sort_by_key(|entry| (entry.priority, entry.width_rank, entry.mode_key.clone()));
        }
        let mut family_forms: HashMap<String, HashSet<String>> = HashMap::new();
        let mut cpu_forms: HashMap<String, HashSet<String>> = HashMap::new();
        let mut dialect_forms: HashMap<String, HashSet<String>> = HashMap::new();
        for form in forms {
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
            mode_selectors,
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
        if !resolved.family_id.eq_ignore_ascii_case("mos6502") {
            return Ok(None);
        }
        let Some(candidates) =
            self.select_candidates_from_exprs(&resolved, mnemonic, operands, ctx)?
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

#[derive(Clone, Debug)]
struct SelectorInput<'a> {
    shape_key: String,
    expr0: Option<&'a Expr>,
    expr1: Option<&'a Expr>,
    force: Option<OperandForce>,
}

impl HierarchyExecutionModel {
    fn select_candidates_from_exprs(
        &self,
        resolved: &ResolvedHierarchy,
        mnemonic: &str,
        operands: &[Expr],
        ctx: &dyn AssemblerContext,
    ) -> Result<Option<Vec<VmEncodeCandidate>>, RuntimeBridgeError> {
        let family = MOS6502FamilyHandler::new();
        let parsed = family.parse_operands(mnemonic, operands).ok();
        let Some(input) = parsed
            .as_ref()
            .and_then(|operands| selector_input_from_family_operands(operands))
        else {
            return Ok(None);
        };

        let upper_mnemonic = mnemonic.to_ascii_uppercase();
        let lower_mnemonic = mnemonic.to_ascii_lowercase();
        let owner_order = [
            (2u8, resolved.dialect_id.as_str()),
            (1u8, resolved.cpu_id.as_str()),
            (0u8, resolved.family_id.as_str()),
        ];

        let unstable_expr = input
            .expr0
            .is_some_and(|expr| expr_has_unstable_symbols(expr, ctx));
        let mut candidates = Vec::new();
        let mut force_error: Option<String> = None;
        let mut saw_selector = false;

        for (owner_tag, owner_id) in owner_order {
            let key = (
                owner_tag,
                owner_id.to_ascii_lowercase(),
                lower_mnemonic.clone(),
                input.shape_key.clone(),
            );
            let Some(selectors) = self.mode_selectors.get(&key) else {
                continue;
            };
            saw_selector = true;

            let has_wider = selectors.iter().any(|entry| {
                entry.width_rank > 1 && self.mode_exists_for_owner(entry, owner_tag, owner_id)
            });

            for selector in selectors {
                if unstable_expr && selector.unstable_widen && has_wider {
                    continue;
                }
                match selector_to_candidate(selector, &input, &upper_mnemonic, ctx) {
                    Ok(Some(candidate)) => candidates.push(candidate),
                    Ok(None) => {}
                    Err(message) => {
                        if force_error.is_none() {
                            force_error = Some(message);
                        }
                    }
                }
            }
        }

        if !candidates.is_empty() {
            return Ok(Some(candidates));
        }

        if let Some(force) = input.force {
            // Keep legacy CPU-specific diagnostics for non-65816 targets until
            // force metadata is emitted for those CPUs.
            if !resolved.cpu_id.eq_ignore_ascii_case("65816") {
                return Ok(None);
            }
            if let Some(message) = force_error {
                return Err(RuntimeBridgeError::Resolve(message));
            }
            if !saw_selector {
                return Err(RuntimeBridgeError::Resolve(invalid_force_error(
                    force,
                    &upper_mnemonic,
                )));
            }
        }

        Ok(None)
    }

    fn mode_exists_for_owner(
        &self,
        selector: &ModeSelectorDescriptor,
        owner_tag: u8,
        owner_id: &str,
    ) -> bool {
        let key = (
            owner_tag,
            owner_id.to_ascii_lowercase(),
            selector.mnemonic.to_ascii_lowercase(),
            selector.mode_key.to_ascii_lowercase(),
        );
        self.vm_programs.contains_key(&key)
    }
}

fn selector_input_from_family_operands(operands: &[FamilyOperand]) -> Option<SelectorInput<'_>> {
    match operands {
        [] => Some(SelectorInput {
            shape_key: "implied".to_string(),
            expr0: None,
            expr1: None,
            force: None,
        }),
        [FamilyOperand::Accumulator(_)] => Some(SelectorInput {
            shape_key: "accumulator".to_string(),
            expr0: None,
            expr1: None,
            force: None,
        }),
        [FamilyOperand::Immediate(expr)] => Some(SelectorInput {
            shape_key: "immediate".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::Direct(expr)] => Some(SelectorInput {
            shape_key: "direct".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::DirectX(expr)] => Some(SelectorInput {
            shape_key: "direct_x".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::DirectY(expr)] => Some(SelectorInput {
            shape_key: "direct_y".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::IndexedIndirectX(expr) | FamilyOperand::IndirectX(expr)] => {
            Some(SelectorInput {
                shape_key: "indexed_indirect_x".to_string(),
                expr0: Some(expr),
                expr1: None,
                force: None,
            })
        }
        [FamilyOperand::IndirectIndexedY(expr)] => Some(SelectorInput {
            shape_key: "indirect_indexed_y".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::Indirect(expr)] => Some(SelectorInput {
            shape_key: "indirect".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::IndirectLong(expr)] => Some(SelectorInput {
            shape_key: "indirect_long".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::IndirectLongY(expr)] => Some(SelectorInput {
            shape_key: "indirect_long_y".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::StackRelative(expr)] => Some(SelectorInput {
            shape_key: "stack_relative".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::StackRelativeIndirectIndexedY(expr)] => Some(SelectorInput {
            shape_key: "stack_relative_indirect_y".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::BlockMove { src, dst, .. }] => Some(SelectorInput {
            shape_key: "pair_direct".to_string(),
            expr0: Some(src),
            expr1: Some(dst),
            force: None,
        }),
        [FamilyOperand::Forced { inner, force, .. }] => {
            let nested = selector_input_from_family_operands(std::slice::from_ref(inner.as_ref()))?;
            Some(SelectorInput {
                shape_key: format!("{}:force_{}", nested.shape_key, force_suffix(*force)),
                force: Some(*force),
                ..nested
            })
        }
        [FamilyOperand::Direct(first), FamilyOperand::Direct(second)] => Some(SelectorInput {
            shape_key: "pair_direct".to_string(),
            expr0: Some(first),
            expr1: Some(second),
            force: None,
        }),
        _ => None,
    }
}

fn force_suffix(force: OperandForce) -> &'static str {
    match force {
        OperandForce::DirectPage => "d",
        OperandForce::DataBank => "b",
        OperandForce::ProgramBank => "k",
        OperandForce::Long => "l",
    }
}

fn invalid_force_error(force: OperandForce, context: &str) -> String {
    format!(
        "Explicit addressing override ',{}' is not valid for {}",
        force_suffix(force),
        context
    )
}

fn bank_mismatch_error(
    address: u32,
    actual_bank: u8,
    assumed_bank: u8,
    assumed_bank_key: &str,
) -> String {
    format!(
        "Address ${address:06X} is in bank ${actual_bank:02X}, but .assume {assumed_bank_key}=${assumed_bank:02X}"
    )
}

fn bank_unknown_error(assumed_bank_key: &str, upper_mnemonic: &str) -> String {
    let mut message = format!(
        "Unable to resolve 24-bit bank because .assume {assumed_bank_key}=... is unknown; set .assume {assumed_bank_key}=$00..$FF or {assumed_bank_key}=auto"
    );
    message.push_str(
        ". If this source relied on removed stack-sequence inference, update .assume near this site",
    );
    let has_long = matches!(
        upper_mnemonic,
        "ORA" | "AND" | "EOR" | "ADC" | "STA" | "LDA" | "CMP" | "SBC" | "JML" | "JSL"
    );
    if has_long {
        message.push_str("; long-capable operands can be forced with ',l'");
    }
    message.push('.');
    message
}

fn selector_to_candidate(
    selector: &ModeSelectorDescriptor,
    input: &SelectorInput<'_>,
    upper_mnemonic: &str,
    ctx: &dyn AssemblerContext,
) -> Result<Option<VmEncodeCandidate>, String> {
    let Some(mode) = parse_mode_key(&selector.mode_key) else {
        return Ok(None);
    };
    let operand_bytes = match selector.operand_plan.as_str() {
        "none" => Vec::new(),
        "u8" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_u8(expr0, ctx).ok_or_else(|| "invalid u8 operand".to_string())?]
        }
        "u16" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_u16(expr0, ctx).ok_or_else(|| "invalid u16 operand".to_string())?]
        }
        "u24" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_u24(expr0, ctx).ok_or_else(|| "invalid u24 operand".to_string())?]
        }
        "force_l_u24" => vec![encode_expr_force_u24(
            input
                .expr0
                .ok_or_else(|| "missing force-l operand".to_string())?,
            ctx,
        )?],
        "rel8" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_rel8(expr0, ctx, 2)
                .ok_or_else(|| "invalid 8-bit relative operand".to_string())?]
        }
        "rel16" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_rel16(expr0, ctx, 3)
                .ok_or_else(|| "invalid 16-bit relative operand".to_string())?]
        }
        "pair_u8_rel8" => vec![
            encode_expr_u8(
                input
                    .expr0
                    .ok_or_else(|| "missing first operand".to_string())?,
                ctx,
            )
            .ok_or_else(|| "invalid first u8 operand".to_string())?,
            encode_expr_rel8(
                input
                    .expr1
                    .ok_or_else(|| "missing second operand".to_string())?,
                ctx,
                3,
            )
            .ok_or_else(|| "invalid relative operand".to_string())?,
        ],
        "u8u8_packed" => vec![{
            let mut packed = encode_expr_u8(
                input
                    .expr0
                    .ok_or_else(|| "missing first operand".to_string())?,
                ctx,
            )
            .ok_or_else(|| "invalid first u8 operand".to_string())?;
            packed.extend(
                encode_expr_u8(
                    input
                        .expr1
                        .ok_or_else(|| "missing second operand".to_string())?,
                    ctx,
                )
                .ok_or_else(|| "invalid second u8 operand".to_string())?,
            );
            packed
        }],
        "force_d_u8" => vec![encode_expr_force_d_u8(
            input
                .expr0
                .ok_or_else(|| "missing force-d operand".to_string())?,
            ctx,
        )?],
        "force_b_abs16_dbr" => {
            if matches!(upper_mnemonic, "JMP" | "JSR") {
                return Ok(None);
            }
            vec![encode_expr_force_abs16(
                input
                    .expr0
                    .ok_or_else(|| "missing force-b operand".to_string())?,
                false,
                OperandForce::DataBank,
                upper_mnemonic,
                ctx,
            )?]
        }
        "force_k_abs16_pbr" => {
            if !matches!(upper_mnemonic, "JMP" | "JSR") {
                return Ok(None);
            }
            vec![encode_expr_force_abs16(
                input
                    .expr0
                    .ok_or_else(|| "missing force-k operand".to_string())?,
                true,
                OperandForce::ProgramBank,
                upper_mnemonic,
                ctx,
            )?]
        }
        "imm_mx" => vec![encode_expr_m65816_immediate(
            input
                .expr0
                .ok_or_else(|| "missing immediate operand".to_string())?,
            upper_mnemonic,
            ctx,
        )
        .ok_or_else(|| "invalid immediate operand".to_string())?],
        _ => return Ok(None),
    };

    // Ensure mode-width matches generated bytes before candidate emission.
    if mode.operand_size() == 0 && !operand_bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(VmEncodeCandidate {
        mode_key: selector.mode_key.to_ascii_lowercase(),
        operand_bytes,
    }))
}

fn parse_mode_key(mode_key: &str) -> Option<AddressMode> {
    match mode_key.to_ascii_lowercase().as_str() {
        "implied" => Some(AddressMode::Implied),
        "accumulator" => Some(AddressMode::Accumulator),
        "immediate" => Some(AddressMode::Immediate),
        "zeropage" => Some(AddressMode::ZeroPage),
        "zeropagex" => Some(AddressMode::ZeroPageX),
        "zeropagey" => Some(AddressMode::ZeroPageY),
        "absolute" => Some(AddressMode::Absolute),
        "absolutex" => Some(AddressMode::AbsoluteX),
        "absolutey" => Some(AddressMode::AbsoluteY),
        "indirect" => Some(AddressMode::Indirect),
        "indexedindirectx" => Some(AddressMode::IndexedIndirectX),
        "indirectindexedy" => Some(AddressMode::IndirectIndexedY),
        "relative" => Some(AddressMode::Relative),
        "relativelong" => Some(AddressMode::RelativeLong),
        "zeropageindirect" => Some(AddressMode::ZeroPageIndirect),
        "absoluteindexedindirect" => Some(AddressMode::AbsoluteIndexedIndirect),
        "stackrelative" => Some(AddressMode::StackRelative),
        "stackrelativeindirectindexedy" => Some(AddressMode::StackRelativeIndirectIndexedY),
        "absolutelong" => Some(AddressMode::AbsoluteLong),
        "absolutelongx" => Some(AddressMode::AbsoluteLongX),
        "indirectlong" => Some(AddressMode::IndirectLong),
        "directpageindirectlong" => Some(AddressMode::DirectPageIndirectLong),
        "directpageindirectlongy" => Some(AddressMode::DirectPageIndirectLongY),
        "blockmove" => Some(AddressMode::BlockMove),
        _ => None,
    }
}

fn encode_expr_u8(expr: &Expr, ctx: &dyn AssemblerContext) -> Option<Vec<u8>> {
    let value = ctx.eval_expr(expr).ok()?;
    if (0..=255).contains(&value) {
        Some(vec![value as u8])
    } else {
        None
    }
}

fn encode_expr_u16(expr: &Expr, ctx: &dyn AssemblerContext) -> Option<Vec<u8>> {
    let value = ctx.eval_expr(expr).ok()?;
    if (0..=65535).contains(&value) {
        Some(vec![
            (value as u16 & 0xFF) as u8,
            ((value as u16 >> 8) & 0xFF) as u8,
        ])
    } else {
        None
    }
}

fn encode_expr_u24(expr: &Expr, ctx: &dyn AssemblerContext) -> Option<Vec<u8>> {
    let value = ctx.eval_expr(expr).ok()?;
    if (0..=0xFF_FFFF).contains(&value) {
        Some(vec![
            (value as u32 & 0xFF) as u8,
            ((value as u32 >> 8) & 0xFF) as u8,
            ((value as u32 >> 16) & 0xFF) as u8,
        ])
    } else {
        None
    }
}

fn encode_expr_force_d_u8(expr: &Expr, ctx: &dyn AssemblerContext) -> Result<Vec<u8>, String> {
    if ctx.pass() == 1 && expr_has_unstable_symbols(expr, ctx) {
        return Ok(vec![0]);
    }
    let value = ctx.eval_expr(expr)?;
    if (0..=255).contains(&value) {
        return Ok(vec![value as u8]);
    }
    if !(0..=0xFFFF).contains(&value) {
        return Err(format!(
            "Address {} out of 16-bit range for explicit ',d'",
            value
        ));
    }
    let absolute_value = value as u16;
    let Some(dp_offset) = direct_page_offset_for_absolute_address(absolute_value, ctx) else {
        return Err(format!(
            "Address ${absolute_value:04X} is outside the direct-page window for explicit ',d'"
        ));
    };
    Ok(vec![dp_offset])
}

fn encode_expr_force_u24(expr: &Expr, ctx: &dyn AssemblerContext) -> Result<Vec<u8>, String> {
    if ctx.pass() == 1 && expr_has_unstable_symbols(expr, ctx) {
        return Ok(vec![0, 0, 0]);
    }
    let value = ctx.eval_expr(expr)?;
    if !(0..=0xFF_FFFF).contains(&value) {
        return Err(format!(
            "Address {} out of 24-bit range for explicit ',l'",
            value
        ));
    }
    Ok(vec![
        (value as u32 & 0xFF) as u8,
        ((value as u32 >> 8) & 0xFF) as u8,
        ((value as u32 >> 16) & 0xFF) as u8,
    ])
}

fn encode_expr_force_abs16(
    expr: &Expr,
    use_program_bank: bool,
    force: OperandForce,
    upper_mnemonic: &str,
    ctx: &dyn AssemblerContext,
) -> Result<Vec<u8>, String> {
    if ctx.pass() == 1 && expr_has_unstable_symbols(expr, ctx) {
        return Ok(vec![0, 0]);
    }
    let value = ctx.eval_expr(expr)?;
    if (0..=65535).contains(&value) {
        return Ok(vec![
            (value as u16 & 0xFF) as u8,
            ((value as u16 >> 8) & 0xFF) as u8,
        ]);
    }
    if !(0..=0xFF_FFFF).contains(&value) {
        return Err(format!(
            "Address {} out of 24-bit range for explicit ',{}'",
            value,
            force_suffix(force)
        ));
    }
    let assumed_bank_key = if use_program_bank { "pbr" } else { "dbr" };
    let assumed_known = if use_program_bank {
        state::program_bank_known(ctx)
    } else {
        state::data_bank_known(ctx)
    };
    if !assumed_known {
        return Err(bank_unknown_error(assumed_bank_key, upper_mnemonic));
    }
    let assumed_bank = if use_program_bank {
        state::program_bank(ctx)
    } else {
        state::data_bank(ctx)
    };
    let absolute_bank = ((value as u32) >> 16) as u8;
    if absolute_bank != assumed_bank {
        return Err(bank_mismatch_error(
            value as u32,
            absolute_bank,
            assumed_bank,
            assumed_bank_key,
        ));
    }
    let absolute = (value as u32 & 0xFFFF) as u16;
    Ok(vec![
        (absolute & 0xFF) as u8,
        ((absolute >> 8) & 0xFF) as u8,
    ])
}

fn direct_page_offset_for_absolute_address(address: u16, ctx: &dyn AssemblerContext) -> Option<u8> {
    if !state::direct_page_known(ctx) || address <= 0x00FF {
        return None;
    }
    let dp = state::direct_page(ctx);
    let offset = address.wrapping_sub(dp);
    (offset <= 0x00FF).then_some(offset as u8)
}

fn encode_expr_rel8(expr: &Expr, ctx: &dyn AssemblerContext, instr_len: i64) -> Option<Vec<u8>> {
    let value = ctx.eval_expr(expr).ok()?;
    let current = ctx.current_address() as i64 + instr_len;
    let offset = value - current;
    if !(-128..=127).contains(&offset) {
        if ctx.pass() > 1 {
            return None;
        }
        return Some(vec![0]);
    }
    Some(vec![offset as i8 as u8])
}

fn encode_expr_rel16(expr: &Expr, ctx: &dyn AssemblerContext, instr_len: i64) -> Option<Vec<u8>> {
    let value = ctx.eval_expr(expr).ok()?;
    let current = ctx.current_address() as i64 + instr_len;
    let offset = value - current;
    if !(-32768..=32767).contains(&offset) {
        if ctx.pass() > 1 {
            return None;
        }
        return Some(vec![0, 0]);
    }
    let rel = offset as i16;
    Some(vec![
        (rel as u16 & 0xFF) as u8,
        ((rel as u16 >> 8) & 0xFF) as u8,
    ])
}

fn encode_expr_m65816_immediate(
    expr: &Expr,
    upper_mnemonic: &str,
    ctx: &dyn AssemblerContext,
) -> Option<Vec<u8>> {
    let value = ctx.eval_expr(expr).ok()?;
    let acc_imm = matches!(
        upper_mnemonic,
        "ADC" | "AND" | "BIT" | "CMP" | "EOR" | "LDA" | "ORA" | "SBC"
    );
    let idx_imm = matches!(upper_mnemonic, "CPX" | "CPY" | "LDX" | "LDY");
    if acc_imm {
        if state::accumulator_is_8bit(ctx) {
            return (0..=255).contains(&value).then(|| vec![value as u8]);
        }
        return (0..=65535).contains(&value).then(|| {
            vec![
                (value as u16 & 0xFF) as u8,
                ((value as u16 >> 8) & 0xFF) as u8,
            ]
        });
    }
    if idx_imm {
        if state::index_is_8bit(ctx) {
            return (0..=255).contains(&value).then(|| vec![value as u8]);
        }
        return (0..=65535).contains(&value).then(|| {
            vec![
                (value as u16 & 0xFF) as u8,
                ((value as u16 >> 8) & 0xFF) as u8,
            ]
        });
    }
    (0..=255).contains(&value).then(|| vec![value as u8])
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
        cpu_flags: HashMap<String, u32>,
        addr: u32,
        pass: u8,
    }

    impl TestAssemblerContext {
        fn new() -> Self {
            Self {
                values: HashMap::new(),
                finalized: HashMap::new(),
                cpu_flags: HashMap::new(),
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

        fn cpu_state_flag(&self, key: &str) -> Option<u32> {
            self.cpu_flags.get(key).copied()
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
    fn execution_model_encodes_m65c02_instruction_from_expr_operands() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let span = Span::default();
        let operands = vec![Expr::Number("4".to_string(), span)];
        let mut ctx = TestAssemblerContext::new();
        ctx.addr = 0;
        let bytes = model
            .encode_instruction_from_exprs("65c02", None, "BRA", &operands, &ctx)
            .expect("vm expr encode should succeed");
        assert_eq!(bytes, Some(vec![0x80, 0x02]));
    }

    #[test]
    fn execution_model_encodes_m65816_block_move_from_expr_operands() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let span = Span::default();
        let operands = vec![
            Expr::Number("1".to_string(), span),
            Expr::Number("2".to_string(), span),
        ];
        let ctx = TestAssemblerContext::new();
        let bytes = model
            .encode_instruction_from_exprs("65816", None, "MVN", &operands, &ctx)
            .expect("vm expr encode should succeed");
        assert_eq!(bytes, Some(vec![0x54, 0x01, 0x02]));
    }

    #[test]
    fn execution_model_encodes_m65816_forced_long_from_expr_operands() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let span = Span::default();
        let operands = vec![
            Expr::Number("1193046".to_string(), span),
            Expr::Register("l".to_string(), span),
        ];
        let ctx = TestAssemblerContext::new();
        let bytes = model
            .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
            .expect("vm expr encode should succeed");
        assert_eq!(bytes, Some(vec![0xAF, 0x56, 0x34, 0x12]));
    }

    #[test]
    fn execution_model_encodes_m65816_forced_data_bank_from_expr_operands() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let span = Span::default();
        let operands = vec![
            Expr::Number("4660".to_string(), span),
            Expr::Register("b".to_string(), span),
        ];
        let ctx = TestAssemblerContext::new();
        let bytes = model
            .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
            .expect("vm expr encode should succeed");
        assert_eq!(bytes, Some(vec![0xAD, 0x34, 0x12]));
    }

    #[test]
    fn execution_model_encodes_m65816_forced_program_bank_from_expr_operands() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let span = Span::default();
        let operands = vec![
            Expr::Number("4660".to_string(), span),
            Expr::Register("k".to_string(), span),
        ];
        let ctx = TestAssemblerContext::new();
        let bytes = model
            .encode_instruction_from_exprs("65816", None, "JMP", &operands, &ctx)
            .expect("vm expr encode should succeed");
        assert_eq!(bytes, Some(vec![0x4C, 0x34, 0x12]));
    }

    #[test]
    fn execution_model_encodes_m65816_forced_direct_page_from_expr_operands() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let span = Span::default();
        let operands = vec![
            Expr::Identifier("target".to_string(), span),
            Expr::Register("d".to_string(), span),
        ];
        let mut ctx = TestAssemblerContext::new();
        ctx.values.insert("target".to_string(), 0x20F0);
        ctx.cpu_flags
            .insert(crate::m65816::state::DIRECT_PAGE_KEY.to_string(), 0x2000);
        ctx.cpu_flags
            .insert(crate::m65816::state::DIRECT_PAGE_KNOWN_KEY.to_string(), 1);
        let bytes = model
            .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
            .expect("vm expr encode should succeed");
        assert_eq!(bytes, Some(vec![0xA5, 0xF0]));
    }

    #[test]
    fn execution_model_encodes_m65816_forced_long_unresolved_symbol_on_pass1() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let span = Span::default();
        let operands = vec![
            Expr::Identifier("target".to_string(), span),
            Expr::Register("l".to_string(), span),
        ];
        let mut ctx = TestAssemblerContext::new();
        ctx.pass = 1;
        let bytes = model
            .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
            .expect("vm expr encode should succeed");
        assert_eq!(bytes, Some(vec![0xAF, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn execution_model_reports_m65816_invalid_force_override_without_fallback() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let span = Span::default();
        let operands = vec![
            Expr::Number("1193046".to_string(), span),
            Expr::Register("k".to_string(), span),
        ];
        let ctx = TestAssemblerContext::new();
        let err = model
            .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
            .expect_err("vm runtime should reject invalid force override");
        assert_eq!(
            err.to_string(),
            "Explicit addressing override ',k' is not valid for LDA"
        );
    }

    #[test]
    fn execution_model_reports_m65816_force_data_bank_unknown() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let span = Span::default();
        let operands = vec![
            Expr::Number("1193046".to_string(), span),
            Expr::Register("b".to_string(), span),
        ];
        let mut ctx = TestAssemblerContext::new();
        ctx.cpu_flags
            .insert(crate::m65816::state::DATA_BANK_KNOWN_KEY.to_string(), 0);
        let err = model
            .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
            .expect_err("vm runtime should require known data bank");
        assert!(err.to_string().contains(".assume dbr"));
        assert!(err.to_string().contains("forced with ',l'"));
    }

    #[test]
    fn m6502_expr_candidates_prefer_absolute_for_unstable_symbols() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let resolved = model
            .resolve_pipeline("m6502", None)
            .expect("resolve m6502 pipeline");

        let span = Span::default();
        let expr = Expr::Identifier("target".to_string(), span);
        let mut ctx = TestAssemblerContext::new();
        ctx.values.insert("target".to_string(), 0x10);
        ctx.finalized.insert("target".to_string(), false);
        let candidates = model
            .select_candidates_from_exprs(&resolved, "LDA", &[expr], &ctx)
            .expect("m6502 selector candidates")
            .expect("m6502 candidates should exist");
        assert_eq!(candidates[0].mode_key, "absolute");
        assert!(candidates
            .iter()
            .all(|candidate| candidate.mode_key != "zeropage"));
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
