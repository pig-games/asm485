// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Conditional assembly state management.

/// Kind of conditional block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalBlockKind {
    If,
    Switch,
}

/// Conditional branch subtype for active block flow control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalSubType {
    If,
    Else,
    ElseIf,
    Switch,
    Case,
    Default,
}

/// State of a conditional assembly block.
#[derive(Debug, Clone)]
pub struct ConditionalContext {
    pub kind: ConditionalBlockKind,
    pub nest_level: u8,
    pub skip_level: u8,
    pub sub_type: ConditionalSubType,
    pub matched: bool,
    pub skipping: bool,
    pub switch_value: Option<u32>,
}

impl ConditionalContext {
    pub fn new(prev: Option<&ConditionalContext>, kind: ConditionalBlockKind) -> Self {
        let nest_level = match prev {
            Some(p) => p.nest_level.saturating_add(1),
            None => 1,
        };
        let sub_type = match kind {
            ConditionalBlockKind::If => ConditionalSubType::If,
            ConditionalBlockKind::Switch => ConditionalSubType::Switch,
        };
        Self {
            kind,
            nest_level,
            skip_level: 0,
            sub_type,
            matched: false,
            skipping: false,
            switch_value: None,
        }
    }
}

/// Stack of conditional assembly contexts.
pub struct ConditionalStack {
    stack: Vec<ConditionalContext>,
}

impl ConditionalStack {
    pub fn new() -> Self {
        Self { stack: Vec::new() }
    }

    pub fn clear(&mut self) {
        self.stack.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    pub fn last(&self) -> Option<&ConditionalContext> {
        self.stack.last()
    }

    pub fn last_mut(&mut self) -> Option<&mut ConditionalContext> {
        self.stack.last_mut()
    }

    pub fn push(&mut self, ctx: ConditionalContext) {
        self.stack.push(ctx);
    }

    pub fn pop(&mut self) -> Option<ConditionalContext> {
        self.stack.pop()
    }

    pub fn skipping(&self) -> bool {
        match self.stack.last() {
            Some(c) => c.skipping,
            None => false,
        }
    }
}

impl Default for ConditionalStack {
    fn default() -> Self {
        Self::new()
    }
}
