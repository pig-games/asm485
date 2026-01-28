// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Scope management for symbol namespacing.

/// A frame in the scope stack tracking segment count.
struct ScopeFrame {
    segment_count: usize,
}

/// Stack of scopes for qualified symbol names.
pub struct ScopeStack {
    segments: Vec<String>,
    frames: Vec<ScopeFrame>,
    anon_counter: u32,
}

impl ScopeStack {
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
            frames: Vec::new(),
            anon_counter: 0,
        }
    }

    pub fn clear(&mut self) {
        self.segments.clear();
        self.frames.clear();
        self.anon_counter = 0;
    }

    pub fn depth(&self) -> usize {
        self.segments.len()
    }

    pub fn prefix(&self, depth: usize) -> String {
        self.segments[..depth].join(".")
    }

    pub fn qualify(&self, name: &str) -> String {
        if self.segments.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", self.segments.join("."), name)
        }
    }

    pub fn push_named(&mut self, name: &str) -> Result<(), &'static str> {
        if name.is_empty() {
            return Err("Scope name cannot be empty");
        }
        let parts: Vec<&str> = name.split('.').collect();
        if parts.iter().any(|part| part.is_empty()) {
            return Err("Scope name cannot contain empty segments");
        }
        for part in &parts {
            self.segments.push((*part).to_string());
        }
        self.frames.push(ScopeFrame {
            segment_count: parts.len(),
        });
        Ok(())
    }

    pub fn push_anonymous(&mut self) {
        self.anon_counter = self.anon_counter.saturating_add(1);
        let name = format!("__scope{}", self.anon_counter);
        self.segments.push(name);
        self.frames.push(ScopeFrame { segment_count: 1 });
    }

    pub fn pop(&mut self) -> bool {
        let Some(frame) = self.frames.pop() else {
            return false;
        };
        for _ in 0..frame.segment_count {
            self.segments.pop();
        }
        true
    }
}

impl Default for ScopeStack {
    fn default() -> Self {
        Self::new()
    }
}
