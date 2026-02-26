// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::cpu::CpuType;
use crate::formatter::CpuFormatterHook;

use super::module::CPU_ID;

pub struct M65C02FormatterHook;

impl CpuFormatterHook for M65C02FormatterHook {
    fn cpu_id(&self) -> CpuType {
        CPU_ID
    }
}
