// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::cpu::{CpuFamily, CpuType};

use super::{ActivePipeline, SurfaceParsedLine};

/// Context passed to formatter hooks for one parsed source line.
pub struct FormatterHookContext<'a> {
    pub line_number: usize,
    pub pipeline: &'a ActivePipeline,
    pub parsed_line: &'a SurfaceParsedLine,
}

/// Hook-produced hints for later planning/rendering stages.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FormatterHints {
    pub trace: Vec<String>,
}

impl FormatterHints {
    pub fn push_trace(&mut self, marker: impl Into<String>) {
        self.trace.push(marker.into());
    }
}

/// Dialect-level formatter adapter.
pub trait DialectFormatterHook: Send + Sync {
    fn family_id(&self) -> CpuFamily;
    fn dialect_id(&self) -> &'static str;

    fn apply(&self, _ctx: &FormatterHookContext<'_>, _hints: &mut FormatterHints) {}
}

/// Family-level formatter adapter.
pub trait FamilyFormatterHook: Send + Sync {
    fn family_id(&self) -> CpuFamily;

    fn apply(&self, _ctx: &FormatterHookContext<'_>, _hints: &mut FormatterHints) {}
}

/// CPU-level formatter adapter.
pub trait CpuFormatterHook: Send + Sync {
    fn cpu_id(&self) -> CpuType;

    fn apply(&self, _ctx: &FormatterHookContext<'_>, _hints: &mut FormatterHints) {}
}

/// Global fallback formatter adapter.
pub trait GlobalFormatterHook: Send + Sync {
    fn apply(&self, _ctx: &FormatterHookContext<'_>, _hints: &mut FormatterHints) {}
}

#[derive(Debug, Default)]
pub struct NoopGlobalFormatterHook;

impl GlobalFormatterHook for NoopGlobalFormatterHook {}
