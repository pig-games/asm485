// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::cpu::{CpuFamily, CpuType};
use crate::core::registry::ModuleRegistry;
use crate::families::intel8080::module::Intel8080FamilyModule;
use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
use crate::i8085::module::I8085CpuModule;
use crate::m45gs02::module::M45GS02CpuModule;
use crate::m65816::module::M65816CpuModule;
use crate::m65c02::module::M65C02CpuModule;
use crate::z80::module::Z80CpuModule;

use super::surface_parser::{SurfaceLineKind, SurfaceParsedDocument};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivePipeline {
    pub cpu: CpuType,
    pub family: CpuFamily,
    pub dialect: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateTrackWarning {
    pub line_number: usize,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinePipelineState {
    pub line_number: usize,
    pub kind: SurfaceLineKind,
    pub before: ActivePipeline,
    pub after: ActivePipeline,
    pub cpu_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StateTrackerResult {
    pub line_states: Vec<LinePipelineState>,
    pub warnings: Vec<StateTrackWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateTrackError {
    UnknownInitialCpu(String),
}

impl std::fmt::Display for StateTrackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownInitialCpu(name) => write!(f, "Unknown initial CPU override: {name}"),
        }
    }
}

impl std::error::Error for StateTrackError {}

pub struct StateTracker {
    registry: ModuleRegistry,
    active_cpu: CpuType,
}

impl StateTracker {
    pub fn new(initial_cpu_override: Option<&str>) -> Result<Self, StateTrackError> {
        let registry = build_default_registry();
        let active_cpu = match initial_cpu_override {
            Some(name) => registry
                .resolve_cpu_name(name)
                .ok_or_else(|| StateTrackError::UnknownInitialCpu(name.to_string()))?,
            None => crate::i8085::module::CPU_ID,
        };
        Ok(Self {
            registry,
            active_cpu,
        })
    }

    pub fn track_document(&mut self, parsed: &SurfaceParsedDocument) -> StateTrackerResult {
        let mut result = StateTrackerResult::default();
        result.line_states.reserve(parsed.lines.len());
        for (idx, line) in parsed.lines.iter().enumerate() {
            let line_number = idx + 1;
            let before = self.resolve_active_pipeline();
            let mut cpu_changed = false;
            if line.kind == SurfaceLineKind::Directive
                && line
                    .head
                    .as_deref()
                    .is_some_and(|head| head.eq_ignore_ascii_case(".cpu"))
            {
                if let Some(cpu_name) = parse_cpu_operand_name(&line.tail) {
                    match self.registry.resolve_cpu_name(&cpu_name) {
                        Some(cpu) => {
                            if cpu != self.active_cpu {
                                self.active_cpu = cpu;
                                cpu_changed = true;
                            }
                        }
                        None => {
                            result.warnings.push(StateTrackWarning {
                                line_number,
                                message: format!(
                                    "Unknown CPU type in formatter state tracker: {cpu_name}"
                                ),
                            });
                        }
                    }
                } else {
                    result.warnings.push(StateTrackWarning {
                        line_number,
                        message: ".cpu directive missing CPU operand".to_string(),
                    });
                }
            }
            let after = self.resolve_active_pipeline();
            result.line_states.push(LinePipelineState {
                line_number,
                kind: line.kind,
                before,
                after,
                cpu_changed,
            });
        }
        result
    }

    fn resolve_active_pipeline(&self) -> ActivePipeline {
        let family = self
            .registry
            .cpu_family_id(self.active_cpu)
            .unwrap_or_else(|| CpuFamily::new("unknown"));
        let dialect = self
            .registry
            .cpu_default_dialect(self.active_cpu)
            .unwrap_or("unknown")
            .to_string();
        ActivePipeline {
            cpu: self.active_cpu,
            family,
            dialect,
        }
    }
}

fn parse_cpu_operand_name(tail: &str) -> Option<String> {
    let trimmed = tail.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let bytes = trimmed.as_bytes();
    if matches!(bytes.first(), Some(b'"' | b'\'')) {
        return parse_quoted_operand(trimmed);
    }

    let mut end = 0usize;
    while end < bytes.len() {
        let byte = bytes[end];
        if byte.is_ascii_whitespace() || byte == b',' {
            break;
        }
        end += 1;
    }
    if end == 0 {
        None
    } else {
        Some(trimmed[..end].to_string())
    }
}

fn parse_quoted_operand(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let quote = *bytes.first()?;
    let mut idx = 1usize;
    let mut escaped = false;
    while idx < bytes.len() {
        let byte = bytes[idx];
        if escaped {
            escaped = false;
            idx += 1;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            idx += 1;
            continue;
        }
        if byte == quote {
            if idx == 1 {
                return None;
            }
            return Some(input[1..idx].to_string());
        }
        idx += 1;
    }
    None
}

fn build_default_registry() -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    registry.register_family(Box::new(Intel8080FamilyModule));
    registry.register_family(Box::new(MOS6502FamilyModule));
    registry.register_cpu(Box::new(I8085CpuModule));
    registry.register_cpu(Box::new(Z80CpuModule));
    registry.register_cpu(Box::new(M6502CpuModule));
    registry.register_cpu(Box::new(M65C02CpuModule));
    registry.register_cpu(Box::new(M65816CpuModule));
    registry.register_cpu(Box::new(M45GS02CpuModule));
    registry
}

#[cfg(test)]
mod tests {
    use super::StateTracker;
    use crate::formatter::{parse_document, tokenize_source};

    #[test]
    fn tracks_mixed_cpu_blocks_in_order() {
        let source = ".cpu 8085\nnop\n.cpu z80\nld a,1\n.cpu m6502\nlda #1\n.cpu 65816\nrep #$20\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let mut tracker = StateTracker::new(None).expect("build tracker");
        let result = tracker.track_document(&parsed);

        assert!(result.warnings.is_empty());
        assert_eq!(result.line_states.len(), 8);
        assert_eq!(result.line_states[0].after.cpu.as_str(), "8085");
        assert_eq!(result.line_states[2].after.cpu.as_str(), "z80");
        assert_eq!(result.line_states[4].after.cpu.as_str(), "m6502");
        assert_eq!(result.line_states[6].after.cpu.as_str(), "65816");
        assert_eq!(result.line_states[7].after.family.as_str(), "mos6502");
        assert_eq!(result.line_states[7].after.dialect, "transparent");
    }

    #[test]
    fn unknown_cpu_warning_keeps_previous_state() {
        let source = ".cpu madeup\nnop\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let mut tracker = StateTracker::new(None).expect("build tracker");
        let result = tracker.track_document(&parsed);

        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0]
            .message
            .contains("Unknown CPU type in formatter state tracker"));
        assert_eq!(result.line_states[0].before.cpu.as_str(), "8085");
        assert_eq!(result.line_states[0].after.cpu.as_str(), "8085");
        assert_eq!(result.line_states[1].before.cpu.as_str(), "8085");
    }

    #[test]
    fn quoted_cpu_operand_is_accepted() {
        let source = ".cpu \"65c816\"\nrep #$20\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let mut tracker = StateTracker::new(None).expect("build tracker");
        let result = tracker.track_document(&parsed);

        assert!(result.warnings.is_empty());
        assert_eq!(result.line_states[0].after.cpu.as_str(), "65816");
        assert_eq!(result.line_states[1].before.cpu.as_str(), "65816");
    }

    #[test]
    fn unknown_initial_cpu_override_is_error() {
        let err = match StateTracker::new(Some("notreal")) {
            Ok(_) => panic!("must reject unknown override"),
            Err(err) => err,
        };
        assert_eq!(err.to_string(), "Unknown initial CPU override: notreal");
    }
}
