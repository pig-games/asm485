// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! VM runtime/package model (work in progress).

pub mod builder;
pub mod bytecode;
pub mod hierarchy;
pub(crate) mod intel8080_vm;
pub mod native6502;
pub mod package;
pub mod rewrite;
pub(crate) mod rollout;
pub mod runtime;
pub(crate) mod token_bridge;

pub use bytecode::{execute_program, VmError, OP_EMIT_OPERAND, OP_EMIT_U8, OP_END};
pub use token_bridge::{
    editor_default_runtime_model, editor_parse_line, editor_parse_line_with_model,
    editor_tokenize_line, editor_tokenize_line_with_model,
};
