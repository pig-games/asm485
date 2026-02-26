// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Source formatter scaffolding.

mod config;
mod diagnostics;
mod engine;
mod hook_registry;
mod hooks;
mod planner;
mod renderer;
mod state_tracker;
mod surface_parser;
mod surface_tokenizer;

pub use config::FormatterConfig;
pub use diagnostics::{collect_fallback_diagnostics, FormatterDiagnostic};
pub use engine::{
    FormatMode, FormatterEngine, FormatterFileReport, FormatterOutput, FormatterRunReport,
    FormatterRunSummary,
};
pub use hook_registry::{FormatterHookRegistry, ResolvedFormatterHooks};
pub use hooks::{
    CpuFormatterHook, DialectFormatterHook, FamilyFormatterHook, FormatterHints,
    FormatterHookContext, GlobalFormatterHook, NoopGlobalFormatterHook,
};
pub use planner::{plan_document, FormatPlan, PlannedLine};
pub use renderer::render_plan;
pub use state_tracker::{
    ActivePipeline, LinePipelineState, StateTrackError, StateTrackWarning, StateTracker,
    StateTrackerResult,
};
pub use surface_parser::{
    parse_document, parse_line, SurfaceLineKind, SurfaceParsedDocument, SurfaceParsedLine,
};
pub use surface_tokenizer::{tokenize_source, LineEnding, SurfaceDocument, SurfaceLine};
