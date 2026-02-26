// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! WDC 65C02 CPU extension module.
//!
//! This module provides 65C02-specific functionality that extends the base
//! 6502 instruction set. The core 6502 functionality is handled by the
//! MOS6502 family handler; this module adds only the 65C02 extensions.
//!
//! # 65C02 Extensions
//!
//! ## New Instructions
//! - `BRA` - Branch Always
//! - `PHX`, `PLX` - Push/Pull X
//! - `PHY`, `PLY` - Push/Pull Y
//! - `STZ` - Store Zero
//! - `TRB`, `TSB` - Test and Reset/Set Bits
//! - `BBRn`, `BBSn` - Branch on Bit Reset/Set (n = 0-7)
//! - `RMBn`, `SMBn` - Reset/Set Memory Bit (n = 0-7)
//! - `STP`, `WAI` - Stop and Wait
//!
//! ## New Addressing Modes
//! - Zero Page Indirect: `LDA ($20)` - loads from address at $20/$21
//! - Absolute Indexed Indirect: `JMP ($1234,X)` - indexed indirect jump
//!
//! ## Extended Addressing Mode Support
//! - `BIT #imm` - Immediate mode for BIT instruction
//! - `BIT $zp,X` - Zero Page,X for BIT instruction
//! - `BIT $abs,X` - Absolute,X for BIT instruction
//! - `INC A`, `DEC A` - Accumulator mode for INC/DEC

pub mod formatter;
mod handler;
pub mod instructions;
pub mod module;

pub use handler::M65C02CpuHandler;
