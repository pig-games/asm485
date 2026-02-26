// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::cpu::{CpuFamily, CpuType};
use crate::formatter::{CpuFormatterHook, DialectFormatterHook, FamilyFormatterHook};

use super::module::{CPU_ID, DIALECT_TRANSPARENT, FAMILY_ID};

pub struct TransparentDialectFormatterHook;

impl DialectFormatterHook for TransparentDialectFormatterHook {
    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn dialect_id(&self) -> &'static str {
        DIALECT_TRANSPARENT
    }
}

pub struct Mos6502FamilyFormatterHook;

impl FamilyFormatterHook for Mos6502FamilyFormatterHook {
    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }
}

pub struct M6502FormatterHook;

impl CpuFormatterHook for M6502FormatterHook {
    fn cpu_id(&self) -> CpuType {
        CPU_ID
    }
}
