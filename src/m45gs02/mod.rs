// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 45GS02 CPU extension module.

mod handler;
pub mod instructions;
pub mod module;

pub use handler::M45GS02CpuHandler;
