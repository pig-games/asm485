// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// Shared reporting helpers used by assembler and parser reporter.

pub fn highlight_line(line: &str, column: Option<usize>, use_color: bool) -> String {
    match column {
        Some(col) if col > 0 => {
            let idx = col - 1;
            if idx >= line.len() {
                if use_color {
                    return format!("{line}\x1b[31m^\x1b[0m");
                }
                return format!("{line}^");
            }
            let (head, tail) = line.split_at(idx);
            let ch = tail.chars().next().unwrap_or(' ');
            let rest = &tail[ch.len_utf8()..];
            if use_color {
                format!("{head}\x1b[31m{ch}\x1b[0m{rest}")
            } else {
                format!("{head}{ch}{rest}")
            }
        }
        _ => line.to_string(),
    }
}
