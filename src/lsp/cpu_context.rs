// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::cpu::CpuType;
use crate::core::registry::ModuleRegistry;

pub fn scan_cpu_transitions(lines: &[String], registry: &ModuleRegistry) -> Vec<(u32, CpuType)> {
    let mut out = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let line_num = (idx + 1) as u32;
        let Some(name) = parse_cpu_directive_name(line) else {
            continue;
        };
        if let Some(cpu) = registry.resolve_cpu_name(&name) {
            out.push((line_num, cpu));
        }
    }
    out
}

pub fn resolve_cpu_for_line(
    line: u32,
    transitions: &[(u32, CpuType)],
    workspace_default_cpu: Option<CpuType>,
) -> CpuType {
    let mut selected = None;
    for (transition_line, cpu) in transitions {
        if *transition_line <= line {
            selected = Some(*cpu);
        } else {
            break;
        }
    }
    selected
        .or(workspace_default_cpu)
        .unwrap_or(crate::i8085::module::CPU_ID)
}

pub fn parse_cpu_directive_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if !trimmed.to_ascii_lowercase().starts_with(".cpu") {
        return None;
    }
    let rest = trimmed.get(4..)?.trim_start();
    if rest.is_empty() {
        return None;
    }
    let token = rest
        .split(|ch: char| ch.is_whitespace() || ch == ';' || ch == ',')
        .next()
        .unwrap_or_default()
        .trim_matches('"')
        .trim_matches('\'');
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_cpu_context_prefers_nearest_prior_directive() {
        let registry = crate::build_default_registry();
        let lines = vec![
            ".cpu 6502".to_string(),
            "lda #$01".to_string(),
            ".cpu z80".to_string(),
            "ld a,1".to_string(),
        ];
        let transitions = scan_cpu_transitions(&lines, &registry);
        assert_eq!(
            resolve_cpu_for_line(2, &transitions, None),
            crate::families::mos6502::module::CPU_ID
        );
        assert_eq!(
            resolve_cpu_for_line(4, &transitions, None),
            crate::z80::module::CPU_ID
        );
    }
}
