// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::collections::HashMap;

use crate::core::cpu::{CpuFamily, CpuType};

use super::hooks::{
    CpuFormatterHook, DialectFormatterHook, FamilyFormatterHook, FormatterHints,
    FormatterHookContext, GlobalFormatterHook, NoopGlobalFormatterHook,
};
use super::ActivePipeline;

type DialectKey = (CpuFamily, String);

/// Resolved formatter hook chain for one active pipeline.
pub struct ResolvedFormatterHooks<'a> {
    dialect_hook: Option<&'a dyn DialectFormatterHook>,
    family_hook: Option<&'a dyn FamilyFormatterHook>,
    cpu_hook: Option<&'a dyn CpuFormatterHook>,
    global_hook: &'a dyn GlobalFormatterHook,
}

impl<'a> ResolvedFormatterHooks<'a> {
    pub fn has_dialect_hook(&self) -> bool {
        self.dialect_hook.is_some()
    }

    pub fn has_family_hook(&self) -> bool {
        self.family_hook.is_some()
    }

    pub fn has_cpu_hook(&self) -> bool {
        self.cpu_hook.is_some()
    }

    /// Apply hooks in fixed order: dialect -> family -> cpu -> global.
    pub fn apply(&self, ctx: &FormatterHookContext<'_>, hints: &mut FormatterHints) {
        if let Some(hook) = self.dialect_hook {
            hook.apply(ctx, hints);
        }
        if let Some(hook) = self.family_hook {
            hook.apply(ctx, hints);
        }
        if let Some(hook) = self.cpu_hook {
            hook.apply(ctx, hints);
        }
        self.global_hook.apply(ctx, hints);
    }
}

/// Formatter hook registry with modular family/dialect/cpu adapters.
pub struct FormatterHookRegistry {
    dialect_hooks: HashMap<DialectKey, Box<dyn DialectFormatterHook>>,
    family_hooks: HashMap<CpuFamily, Box<dyn FamilyFormatterHook>>,
    cpu_hooks: HashMap<CpuType, Box<dyn CpuFormatterHook>>,
    global_hook: Box<dyn GlobalFormatterHook>,
}

impl Default for FormatterHookRegistry {
    fn default() -> Self {
        Self::with_builtin_hooks()
    }
}

impl FormatterHookRegistry {
    pub fn empty() -> Self {
        Self {
            dialect_hooks: HashMap::new(),
            family_hooks: HashMap::new(),
            cpu_hooks: HashMap::new(),
            global_hook: Box::new(NoopGlobalFormatterHook),
        }
    }

    pub fn with_builtin_hooks() -> Self {
        let mut registry = Self::empty();
        registry.register_builtin_hooks();
        registry
    }

    pub fn register_dialect_hook(&mut self, hook: Box<dyn DialectFormatterHook>) {
        let key = (hook.family_id(), normalize_dialect_id(hook.dialect_id()));
        self.dialect_hooks.insert(key, hook);
    }

    pub fn register_family_hook(&mut self, hook: Box<dyn FamilyFormatterHook>) {
        self.family_hooks.insert(hook.family_id(), hook);
    }

    pub fn register_cpu_hook(&mut self, hook: Box<dyn CpuFormatterHook>) {
        self.cpu_hooks.insert(hook.cpu_id(), hook);
    }

    pub fn set_global_hook(&mut self, hook: Box<dyn GlobalFormatterHook>) {
        self.global_hook = hook;
    }

    pub fn resolve_for_pipeline<'a>(
        &'a self,
        pipeline: &ActivePipeline,
    ) -> ResolvedFormatterHooks<'a> {
        let dialect_key = (pipeline.family, normalize_dialect_id(&pipeline.dialect));
        ResolvedFormatterHooks {
            dialect_hook: self
                .dialect_hooks
                .get(&dialect_key)
                .map(|hook| hook.as_ref()),
            family_hook: self
                .family_hooks
                .get(&pipeline.family)
                .map(|hook| hook.as_ref()),
            cpu_hook: self.cpu_hooks.get(&pipeline.cpu).map(|hook| hook.as_ref()),
            global_hook: self.global_hook.as_ref(),
        }
    }

    fn register_builtin_hooks(&mut self) {
        self.register_dialect_hook(Box::new(
            crate::families::intel8080::formatter::Intel8080DialectFormatterHook,
        ));
        self.register_dialect_hook(Box::new(
            crate::families::intel8080::formatter::ZilogDialectFormatterHook,
        ));
        self.register_family_hook(Box::new(
            crate::families::intel8080::formatter::Intel8080FamilyFormatterHook,
        ));

        self.register_dialect_hook(Box::new(
            crate::families::mos6502::formatter::TransparentDialectFormatterHook,
        ));
        self.register_family_hook(Box::new(
            crate::families::mos6502::formatter::Mos6502FamilyFormatterHook,
        ));

        self.register_cpu_hook(Box::new(crate::i8085::formatter::I8085FormatterHook));
        self.register_cpu_hook(Box::new(crate::z80::formatter::Z80FormatterHook));
        self.register_cpu_hook(Box::new(
            crate::families::mos6502::formatter::M6502FormatterHook,
        ));
        self.register_cpu_hook(Box::new(crate::m65c02::formatter::M65C02FormatterHook));
        self.register_cpu_hook(Box::new(crate::m65816::formatter::M65816FormatterHook));
        self.register_cpu_hook(Box::new(crate::m45gs02::formatter::M45GS02FormatterHook));
    }
}

fn normalize_dialect_id(dialect: &str) -> String {
    dialect.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::FormatterHookRegistry;
    use crate::core::cpu::{CpuFamily, CpuType};
    use crate::families::intel8080::module::{DIALECT_INTEL8080, FAMILY_ID as INTEL8080_FAMILY_ID};
    use crate::families::mos6502::module::{DIALECT_TRANSPARENT, FAMILY_ID as MOS6502_FAMILY_ID};
    use crate::formatter::{
        parse_document, tokenize_source, ActivePipeline, CpuFormatterHook, DialectFormatterHook,
        FamilyFormatterHook, FormatterHints, FormatterHookContext, GlobalFormatterHook,
    };

    #[test]
    fn builtin_registry_resolves_hooks_for_all_supported_cpus() {
        let registry = FormatterHookRegistry::with_builtin_hooks();
        let pipelines = vec![
            ActivePipeline {
                cpu: crate::i8085::module::CPU_ID,
                family: INTEL8080_FAMILY_ID,
                dialect: DIALECT_INTEL8080.to_string(),
            },
            ActivePipeline {
                cpu: crate::z80::module::CPU_ID,
                family: INTEL8080_FAMILY_ID,
                dialect: "ZiLoG".to_string(),
            },
            ActivePipeline {
                cpu: crate::families::mos6502::module::CPU_ID,
                family: MOS6502_FAMILY_ID,
                dialect: DIALECT_TRANSPARENT.to_string(),
            },
            ActivePipeline {
                cpu: crate::m65c02::module::CPU_ID,
                family: MOS6502_FAMILY_ID,
                dialect: DIALECT_TRANSPARENT.to_string(),
            },
            ActivePipeline {
                cpu: crate::m65816::module::CPU_ID,
                family: MOS6502_FAMILY_ID,
                dialect: DIALECT_TRANSPARENT.to_string(),
            },
            ActivePipeline {
                cpu: crate::m45gs02::module::CPU_ID,
                family: MOS6502_FAMILY_ID,
                dialect: DIALECT_TRANSPARENT.to_string(),
            },
        ];

        let doc = tokenize_source("nop\n");
        let parsed = parse_document(&doc);
        let parsed_line = &parsed.lines[0];

        for pipeline in pipelines {
            let resolved = registry.resolve_for_pipeline(&pipeline);
            assert!(resolved.has_dialect_hook());
            assert!(resolved.has_family_hook());
            assert!(resolved.has_cpu_hook());
            let ctx = FormatterHookContext {
                line_number: 1,
                pipeline: &pipeline,
                parsed_line,
            };
            let mut hints = FormatterHints::default();
            resolved.apply(&ctx, &mut hints);
        }
    }

    #[test]
    fn hook_dispatch_order_is_dialect_family_cpu_global() {
        let family = CpuFamily::new("test-family");
        let cpu = CpuType::new("test-cpu");
        let mut registry = FormatterHookRegistry::empty();
        registry.register_dialect_hook(Box::new(TestDialectHook {
            family,
            dialect: "test",
            marker: "dialect",
        }));
        registry.register_family_hook(Box::new(TestFamilyHook {
            family,
            marker: "family",
        }));
        registry.register_cpu_hook(Box::new(TestCpuHook { cpu, marker: "cpu" }));
        registry.set_global_hook(Box::new(TestGlobalHook { marker: "global" }));

        let pipeline = ActivePipeline {
            cpu,
            family,
            dialect: "TEST".to_string(),
        };
        let doc = tokenize_source("nop\n");
        let parsed = parse_document(&doc);
        let ctx = FormatterHookContext {
            line_number: 1,
            pipeline: &pipeline,
            parsed_line: &parsed.lines[0],
        };

        let resolved = registry.resolve_for_pipeline(&pipeline);
        let mut hints = FormatterHints::default();
        resolved.apply(&ctx, &mut hints);
        assert_eq!(hints.trace, vec!["dialect", "family", "cpu", "global"]);
    }

    struct TestDialectHook {
        family: CpuFamily,
        dialect: &'static str,
        marker: &'static str,
    }

    impl DialectFormatterHook for TestDialectHook {
        fn family_id(&self) -> CpuFamily {
            self.family
        }

        fn dialect_id(&self) -> &'static str {
            self.dialect
        }

        fn apply(&self, _ctx: &FormatterHookContext<'_>, hints: &mut FormatterHints) {
            hints.push_trace(self.marker);
        }
    }

    struct TestFamilyHook {
        family: CpuFamily,
        marker: &'static str,
    }

    impl FamilyFormatterHook for TestFamilyHook {
        fn family_id(&self) -> CpuFamily {
            self.family
        }

        fn apply(&self, _ctx: &FormatterHookContext<'_>, hints: &mut FormatterHints) {
            hints.push_trace(self.marker);
        }
    }

    struct TestCpuHook {
        cpu: CpuType,
        marker: &'static str,
    }

    impl CpuFormatterHook for TestCpuHook {
        fn cpu_id(&self) -> CpuType {
            self.cpu
        }

        fn apply(&self, _ctx: &FormatterHookContext<'_>, hints: &mut FormatterHints) {
            hints.push_trace(self.marker);
        }
    }

    struct TestGlobalHook {
        marker: &'static str,
    }

    impl GlobalFormatterHook for TestGlobalHook {
        fn apply(&self, _ctx: &FormatterHookContext<'_>, hints: &mut FormatterHints) {
            hints.push_trace(self.marker);
        }
    }
}
