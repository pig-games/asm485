// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Source formatter scaffolding.

mod config;
mod engine;
mod surface_parser;
mod surface_tokenizer;

pub use config::FormatterConfig;
pub use engine::{FormatMode, FormatterEngine, FormatterRunSummary};
pub use surface_parser::{
    parse_document, parse_line, SurfaceLineKind, SurfaceParsedDocument, SurfaceParsedLine,
};
pub use surface_tokenizer::{tokenize_source, LineEnding, SurfaceDocument, SurfaceLine};
