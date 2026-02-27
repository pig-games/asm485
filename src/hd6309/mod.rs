// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Hitachi HD6309 CPU extension module.

pub mod formatter;
mod handler;
pub mod instructions;
pub mod module;

pub use handler::HD6309CpuHandler;
