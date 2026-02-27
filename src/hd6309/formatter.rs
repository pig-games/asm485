// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::cpu::CpuType;
use crate::formatter::CpuFormatterHook;

use super::module::CPU_ID;

pub struct HD6309FormatterHook;

impl CpuFormatterHook for HD6309FormatterHook {
    fn cpu_id(&self) -> CpuType {
        CPU_ID
    }
}
