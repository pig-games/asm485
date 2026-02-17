// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! opForge - Multi-CPU Assembler Library (8085/Z80/6502)
//!
//! This library is organized into:
//! - [`core`] - CPU-agnostic assembler infrastructure (reusable)
//! - [`i8085`] - Intel 8085-specific implementation
//! - [`z80`] - Zilog Z80-specific implementation
//! - [`families`] - CPU family handlers (MOS 6502, etc.)
//! - [`m65c02`] - WDC 65C02-specific extensions
//! - [`m65816`] - WDC 65816-specific extensions
//! - [`assembler`] - Main assembler entry point
//! - [`opthread`] - opThread VM/package model (in progress)

pub mod assembler;
pub mod core;
pub mod families;
pub mod i8085;
pub mod m65816;
pub mod m65c02;
pub mod opthread;
pub mod z80;

// Re-export commonly used types from core for convenience
pub use core::imagestore;
pub use core::parser;
pub use core::parser_reporter;
pub use core::preprocess;
pub use core::report;
pub use core::symbol_table;
pub use core::text_utils;
pub use core::token_value;
pub use core::tokenizer;
