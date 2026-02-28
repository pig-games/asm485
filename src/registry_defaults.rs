// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Shared default registry construction for assembler, VM tooling, and LSP.

use crate::core::registry::ModuleRegistry;
use crate::families::intel8080::module::Intel8080FamilyModule;
use crate::families::m6800::module::Motorola6800FamilyModule;
use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
use crate::hd6309::module::HD6309CpuModule;
use crate::i8085::module::I8085CpuModule;
use crate::m45gs02::module::M45GS02CpuModule;
use crate::m65816::module::M65816CpuModule;
use crate::m65c02::module::M65C02CpuModule;
use crate::m6809::module::M6809CpuModule;
use crate::z80::module::Z80CpuModule;

/// Build the canonical default registry used by opForge runtime surfaces.
///
/// Registration order is intentionally centralized here so assembler, VM tooling,
/// and editor integrations (LSP) resolve identical CPU/family/dialect metadata.
pub fn build_default_registry() -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    registry.register_family(Box::new(Intel8080FamilyModule));
    registry.register_family(Box::new(Motorola6800FamilyModule));
    registry.register_family(Box::new(MOS6502FamilyModule));
    registry.register_cpu(Box::new(I8085CpuModule));
    registry.register_cpu(Box::new(Z80CpuModule));
    registry.register_cpu(Box::new(M6502CpuModule));
    registry.register_cpu(Box::new(M65C02CpuModule));
    registry.register_cpu(Box::new(M65816CpuModule));
    registry.register_cpu(Box::new(M45GS02CpuModule));
    registry.register_cpu(Box::new(M6809CpuModule));
    registry.register_cpu(Box::new(HD6309CpuModule));
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::cpu::CpuType;

    #[test]
    fn default_registry_contains_expected_aliases() {
        let registry = build_default_registry();
        assert_eq!(
            registry.resolve_cpu_name("8080"),
            Some(CpuType::new("8085")),
            "8080 should resolve via alias to intel8080-family base cpu id"
        );
        assert_eq!(
            registry.resolve_cpu_name("6502"),
            Some(CpuType::new("m6502"))
        );
        assert_eq!(
            registry.resolve_cpu_name("65c816"),
            Some(CpuType::new("65816"))
        );
        assert_eq!(
            registry.resolve_cpu_name("mega65"),
            Some(CpuType::new("45gs02"))
        );
        assert!(
            registry
                .cpu_runtime_directive_ids(CpuType::new("65816"))
                .iter()
                .any(|name| name.eq_ignore_ascii_case("assume")),
            "65816 runtime directives should include assume"
        );
    }
}
