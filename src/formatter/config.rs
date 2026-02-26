// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

/// Formatter settings used by the formatting engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatterConfig {
    pub preserve_line_endings: bool,
    pub preserve_final_newline: bool,
    pub label_alignment_column: usize,
    pub max_consecutive_blank_lines: usize,
}

impl Default for FormatterConfig {
    fn default() -> Self {
        Self {
            preserve_line_endings: true,
            preserve_final_newline: true,
            label_alignment_column: 12,
            max_consecutive_blank_lines: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FormatterConfig;

    #[test]
    fn default_config_matches_phase1_safe_profile_contract() {
        let cfg = FormatterConfig::default();
        assert!(cfg.preserve_line_endings);
        assert!(cfg.preserve_final_newline);
        assert_eq!(cfg.label_alignment_column, 12);
        assert_eq!(cfg.max_consecutive_blank_lines, 1);
    }
}
