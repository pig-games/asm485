// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::cpu::CpuFamily;
use crate::formatter::{DialectFormatterHook, FamilyFormatterHook};

use super::module::{DIALECT_MOTOROLA680X, FAMILY_ID};

pub struct Motorola680xDialectFormatterHook;

impl DialectFormatterHook for Motorola680xDialectFormatterHook {
    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn dialect_id(&self) -> &'static str {
        DIALECT_MOTOROLA680X
    }
}

pub struct Motorola6800FamilyFormatterHook;

impl FamilyFormatterHook for Motorola6800FamilyFormatterHook {
    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }
}
