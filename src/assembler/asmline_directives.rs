// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use super::*;

impl<'a> AsmLine<'a> {
    pub(crate) fn process_directive_ast(
        &mut self,
        mnemonic: &str,
        operands: &[Expr],
    ) -> LineStatus {
        let upper = mnemonic.to_ascii_uppercase();
        let had_dot = upper.starts_with('.');
        let directive = upper.strip_prefix('.').unwrap_or(&upper);
        if !had_dot {
            return LineStatus::NothingDone;
        }
        if let Some(status) = self.route_layout_directive_ast(directive, operands) {
            return status;
        }
        if let Some(status) = self.route_metadata_directive_ast(directive, operands) {
            return status;
        }
        if let Some(status) = self.route_scope_directive_ast(directive, operands) {
            return status;
        }
        if let Some(status) = self.route_data_directive_ast(directive, operands) {
            return status;
        }
        match directive {
            "END" => LineStatus::Ok,
            _ => match self.apply_cpu_runtime_directive(directive, operands) {
                Ok(true) => LineStatus::Ok,
                Ok(false) => LineStatus::NothingDone,
                Err(message) => {
                    self.failure(LineStatus::Error, AsmErrorKind::Directive, &message, None)
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_registry() -> ModuleRegistry {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry
    }

    #[test]
    fn process_directive_ast_ignores_non_dot_mnemonics() {
        let mut symbols = SymbolTable::new();
        let registry = build_registry();
        let mut asm = AsmLine::with_cpu(
            &mut symbols,
            crate::families::mos6502::module::CPU_ID,
            &registry,
        );

        let status = asm.process_directive_ast("LDA", &[]);
        assert_eq!(status, LineStatus::NothingDone);
    }

    #[test]
    fn process_directive_ast_rejects_removed_dsection_directive() {
        let mut symbols = SymbolTable::new();
        let registry = build_registry();
        let mut asm = AsmLine::with_cpu(
            &mut symbols,
            crate::families::mos6502::module::CPU_ID,
            &registry,
        );

        let status = asm.process_directive_ast(".dsection", &[]);
        assert_eq!(status, LineStatus::Error);
        assert!(asm.error_message().contains(".dsection has been removed"));
    }
}
