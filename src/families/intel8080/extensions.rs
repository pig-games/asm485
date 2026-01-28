// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Intel 8080 family extension instruction tables.
//!
//! Re-exports CPU-specific extension tables from their respective modules.
//! Use the CPU-specific lookup functions directly for instruction lookup:
//! - `crate::i8085::extensions::lookup_extension`
//! - `crate::z80::extensions::lookup_extension`

// Re-export extension tables from CPU-specific modules
pub use crate::i8085::extensions::I8085_EXTENSION_TABLE;
pub use crate::z80::extensions::Z80_EXTENSION_TABLE;
