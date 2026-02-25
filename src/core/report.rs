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
                return format!("{line}\n{}^", " ".repeat(line.len()));
            }
            let (head, tail) = line.split_at(idx);
            let ch = tail.chars().next().unwrap_or(' ');
            let rest = &tail[ch.len_utf8()..];
            if use_color {
                format!("{head}\x1b[31m{ch}\x1b[0m{rest}")
            } else {
                format!("{head}{ch}{rest}\n{}^", " ".repeat(idx))
            }
        }
        _ => line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::highlight_line;

    #[test]
    fn highlight_line_marks_requested_column() {
        let out = highlight_line("LDA #$01", Some(2), false);
        assert!(out.contains("LDA #$01"));
        assert!(out.contains(" ^"));
    }

    #[test]
    fn highlight_line_out_of_bounds_appends_marker() {
        let out = highlight_line("ABC", Some(10), false);
        assert!(out.contains("ABC"));
        assert!(out.ends_with("   ^"));
    }

    #[test]
    fn highlight_line_without_column_returns_original() {
        assert_eq!(highlight_line("NOP", None, false), "NOP");
    }
}
