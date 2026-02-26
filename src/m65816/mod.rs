// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! WDC 65C816 / 65816 CPU extension module.
//!
//! This milestone adds the CPU registration and handler skeleton so `.cpu 65816`
//! and its aliases resolve through the existing MOS 6502 family pipeline.

pub mod formatter;
mod handler;
pub mod instructions;
pub mod module;
pub mod state;

pub use handler::M65816CpuHandler;
