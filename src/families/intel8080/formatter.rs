// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::cpu::CpuFamily;
use crate::formatter::{DialectFormatterHook, FamilyFormatterHook};

use super::module::{DIALECT_INTEL8080, DIALECT_ZILOG, FAMILY_ID};

pub struct Intel8080DialectFormatterHook;

impl DialectFormatterHook for Intel8080DialectFormatterHook {
    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn dialect_id(&self) -> &'static str {
        DIALECT_INTEL8080
    }
}

pub struct ZilogDialectFormatterHook;

impl DialectFormatterHook for ZilogDialectFormatterHook {
    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn dialect_id(&self) -> &'static str {
        DIALECT_ZILOG
    }
}

pub struct Intel8080FamilyFormatterHook;

impl FamilyFormatterHook for Intel8080FamilyFormatterHook {
    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }
}
