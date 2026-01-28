// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Core assembler components that are CPU-agnostic.
//!
//! - [`conditional`] - Conditional assembly state machine
//! - [`scope`] - Symbol scope management
//! - [`expression`] - Expression evaluation
//! - [`listing`] - Listing file generation
//! - [`error`] - Error types and diagnostics

pub mod conditional;
pub mod error;
pub mod expression;
pub mod listing;
pub mod scope;
