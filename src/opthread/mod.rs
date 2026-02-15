// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! opThread VM/package model (work in progress).

pub mod builder;
pub mod hierarchy;
pub(crate) mod intel8080_vm;
pub mod package;
pub mod rewrite;
pub mod runtime;
pub mod vm;
