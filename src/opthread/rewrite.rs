// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Deterministic dialect rewrite engine with bounded pass/growth limits.

/// One token in the dialect rewrite stream.
pub type RewriteToken = String;

/// Family/CPU/dialect context used to select compatible rewrite rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewriteContext {
    pub family_id: String,
    pub cpu_id: String,
    pub dialect_id: String,
}

/// One dialect rewrite rule: `lhs` match -> `rhs` replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewriteRule {
    pub family_id: String,
    pub dialect_id: String,
    pub cpu_allow_list: Option<Vec<String>>,
    pub lhs: Vec<RewriteToken>,
    pub rhs: Vec<RewriteToken>,
}

/// Bounded execution limits for deterministic rewrite behavior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewriteLimits {
    pub max_passes: usize,
    pub max_growth: usize,
    pub max_tokens: usize,
}

impl Default for RewriteLimits {
    fn default() -> Self {
        Self {
            max_passes: 4,
            max_growth: 64,
            max_tokens: 256,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RewriteError {
    RuleHasEmptyMatch,
    InvalidOutputToken,
    RewriteOverflow {
        passes: usize,
        max_passes: usize,
    },
    GrowthLimitExceeded {
        token_count: usize,
        base_count: usize,
        max_growth: usize,
    },
    TokenLimitExceeded {
        token_count: usize,
        max_tokens: usize,
    },
}

impl std::fmt::Display for RewriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuleHasEmptyMatch => write!(f, "rewrite rule has an empty match sequence"),
            Self::InvalidOutputToken => write!(f, "rewrite output contains invalid token"),
            Self::RewriteOverflow { passes, max_passes } => write!(
                f,
                "rewrite pass limit exceeded (passes={}, max={})",
                passes, max_passes
            ),
            Self::GrowthLimitExceeded {
                token_count,
                base_count,
                max_growth,
            } => write!(
                f,
                "rewrite growth limit exceeded (tokens={}, base={}, max_growth={})",
                token_count, base_count, max_growth
            ),
            Self::TokenLimitExceeded {
                token_count,
                max_tokens,
            } => write!(
                f,
                "rewrite token limit exceeded (tokens={}, max={})",
                token_count, max_tokens
            ),
        }
    }
}

impl std::error::Error for RewriteError {}

/// Deterministic rewrite engine:
/// - family/dialect scoped namespace
/// - optional CPU allow-list filtering
/// - leftmost-longest matching, then stable rule insertion order
pub fn rewrite_tokens(
    input: &[RewriteToken],
    context: &RewriteContext,
    rules: &[RewriteRule],
    limits: &RewriteLimits,
) -> Result<Vec<RewriteToken>, RewriteError> {
    let filtered: Vec<(usize, &RewriteRule)> = rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule_matches_context(rule, context))
        .collect();

    for (_, rule) in &filtered {
        if rule.lhs.is_empty() {
            return Err(RewriteError::RuleHasEmptyMatch);
        }
    }

    let base_count = input.len();
    let mut tokens = input.to_vec();
    for pass in 0..limits.max_passes {
        let mut cursor = 0usize;
        let mut out = Vec::with_capacity(tokens.len());
        let mut changed = false;

        while cursor < tokens.len() {
            if let Some((rule, width)) = select_match(&tokens, cursor, &filtered) {
                if rule.rhs.iter().any(|tok| tok.is_empty()) {
                    return Err(RewriteError::InvalidOutputToken);
                }
                out.extend(rule.rhs.iter().cloned());
                cursor += width;
                changed = true;
            } else {
                out.push(tokens[cursor].clone());
                cursor += 1;
            }
        }

        enforce_limits(&out, base_count, limits)?;

        if !changed {
            return Ok(out);
        }
        tokens = out;
        if pass + 1 == limits.max_passes {
            return Err(RewriteError::RewriteOverflow {
                passes: pass + 1,
                max_passes: limits.max_passes,
            });
        }
    }

    Ok(tokens)
}

fn rule_matches_context(rule: &RewriteRule, context: &RewriteContext) -> bool {
    if !rule.family_id.eq_ignore_ascii_case(&context.family_id) {
        return false;
    }
    if !rule.dialect_id.eq_ignore_ascii_case(&context.dialect_id) {
        return false;
    }
    match &rule.cpu_allow_list {
        None => true,
        Some(allow) => allow
            .iter()
            .any(|cpu| cpu.eq_ignore_ascii_case(&context.cpu_id)),
    }
}

fn select_match<'a>(
    tokens: &[RewriteToken],
    cursor: usize,
    rules: &'a [(usize, &RewriteRule)],
) -> Option<(&'a RewriteRule, usize)> {
    let mut best: Option<(usize, usize, &RewriteRule)> = None;
    for (idx, rule) in rules {
        let width = rule.lhs.len();
        if cursor + width > tokens.len() {
            continue;
        }
        if rule
            .lhs
            .iter()
            .zip(tokens[cursor..cursor + width].iter())
            .all(|(lhs, tok)| lhs.eq_ignore_ascii_case(tok))
        {
            let candidate = (width, *idx, *rule);
            best = match best {
                None => Some(candidate),
                Some((best_width, best_idx, best_rule)) => {
                    if width > best_width || (width == best_width && *idx < best_idx) {
                        Some(candidate)
                    } else {
                        Some((best_width, best_idx, best_rule))
                    }
                }
            };
        }
    }
    best.map(|(width, _, rule)| (rule, width))
}

fn enforce_limits(
    tokens: &[RewriteToken],
    base_count: usize,
    limits: &RewriteLimits,
) -> Result<(), RewriteError> {
    if tokens.len() > limits.max_tokens {
        return Err(RewriteError::TokenLimitExceeded {
            token_count: tokens.len(),
            max_tokens: limits.max_tokens,
        });
    }
    if tokens.len() > base_count.saturating_add(limits.max_growth) {
        return Err(RewriteError::GrowthLimitExceeded {
            token_count: tokens.len(),
            base_count,
            max_growth: limits.max_growth,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intel_z80() -> RewriteContext {
        RewriteContext {
            family_id: "intel8080".to_string(),
            cpu_id: "z80".to_string(),
            dialect_id: "zilog".to_string(),
        }
    }

    #[test]
    fn successful_canonical_mapping_is_deterministic() {
        let rules = vec![
            RewriteRule {
                family_id: "intel8080".to_string(),
                dialect_id: "zilog".to_string(),
                cpu_allow_list: None,
                lhs: vec![
                    "ld".to_string(),
                    "a".to_string(),
                    ",".to_string(),
                    "b".to_string(),
                ],
                rhs: vec![
                    "mov".to_string(),
                    "a".to_string(),
                    ",".to_string(),
                    "b".to_string(),
                ],
            },
            RewriteRule {
                family_id: "intel8080".to_string(),
                dialect_id: "zilog".to_string(),
                cpu_allow_list: None,
                lhs: vec!["ld".to_string()],
                rhs: vec!["mov".to_string()],
            },
        ];
        let out = rewrite_tokens(
            &[
                "ld".to_string(),
                "a".to_string(),
                ",".to_string(),
                "b".to_string(),
            ],
            &intel_z80(),
            &rules,
            &RewriteLimits::default(),
        )
        .expect("rewrite should succeed");
        assert_eq!(out, vec!["mov", "a", ",", "b"]);
    }

    #[test]
    fn mixed_family_rules_are_rejected_by_filtering() {
        let rules = vec![RewriteRule {
            family_id: "mos6502".to_string(),
            dialect_id: "zilog".to_string(),
            cpu_allow_list: None,
            lhs: vec!["ld".to_string()],
            rhs: vec!["mov".to_string()],
        }];
        let out = rewrite_tokens(
            &["ld".to_string()],
            &intel_z80(),
            &rules,
            &RewriteLimits::default(),
        )
        .expect("non-matching family should act as no-op");
        assert_eq!(out, vec!["ld"]);
    }

    #[test]
    fn cpu_allow_list_rejection_is_enforced() {
        let rules = vec![RewriteRule {
            family_id: "intel8080".to_string(),
            dialect_id: "zilog".to_string(),
            cpu_allow_list: Some(vec!["8085".to_string()]),
            lhs: vec!["ld".to_string()],
            rhs: vec!["mov".to_string()],
        }];
        let out = rewrite_tokens(
            &["ld".to_string()],
            &intel_z80(),
            &rules,
            &RewriteLimits::default(),
        )
        .expect("allow-list mismatch should act as no-op");
        assert_eq!(out, vec!["ld"]);
    }

    #[test]
    fn rewrite_overflow_is_reported() {
        let rules = vec![RewriteRule {
            family_id: "intel8080".to_string(),
            dialect_id: "zilog".to_string(),
            cpu_allow_list: None,
            lhs: vec!["ld".to_string()],
            rhs: vec!["ld".to_string(), "x".to_string()],
        }];
        let err = rewrite_tokens(
            &["ld".to_string()],
            &intel_z80(),
            &rules,
            &RewriteLimits {
                max_passes: 2,
                max_growth: 100,
                max_tokens: 100,
            },
        )
        .expect_err("pass limit should fail");
        assert!(matches!(err, RewriteError::RewriteOverflow { .. }));
    }

    #[test]
    fn invalid_rewrite_output_is_reported() {
        let rules = vec![RewriteRule {
            family_id: "intel8080".to_string(),
            dialect_id: "zilog".to_string(),
            cpu_allow_list: None,
            lhs: vec!["ld".to_string()],
            rhs: vec!["".to_string()],
        }];
        let err = rewrite_tokens(
            &["ld".to_string()],
            &intel_z80(),
            &rules,
            &RewriteLimits::default(),
        )
        .expect_err("invalid output token should fail");
        assert!(matches!(err, RewriteError::InvalidOutputToken));
    }

    #[test]
    fn empty_match_rule_is_rejected() {
        let rules = vec![RewriteRule {
            family_id: "intel8080".to_string(),
            dialect_id: "zilog".to_string(),
            cpu_allow_list: None,
            lhs: Vec::new(),
            rhs: vec!["mov".to_string()],
        }];
        let err = rewrite_tokens(
            &["ld".to_string()],
            &intel_z80(),
            &rules,
            &RewriteLimits::default(),
        )
        .expect_err("empty match should fail");
        assert!(matches!(err, RewriteError::RuleHasEmptyMatch));
    }

    #[test]
    fn growth_limit_exceeded_is_reported() {
        let rules = vec![RewriteRule {
            family_id: "intel8080".to_string(),
            dialect_id: "zilog".to_string(),
            cpu_allow_list: None,
            lhs: vec!["ld".to_string()],
            rhs: vec!["ld".to_string(), "x".to_string()],
        }];
        let err = rewrite_tokens(
            &["ld".to_string()],
            &intel_z80(),
            &rules,
            &RewriteLimits {
                max_passes: 8,
                max_growth: 1,
                max_tokens: 256,
            },
        )
        .expect_err("growth limit should fail");
        assert!(matches!(err, RewriteError::GrowthLimitExceeded { .. }));
    }

    #[test]
    fn token_limit_exceeded_is_reported() {
        let rules = vec![RewriteRule {
            family_id: "intel8080".to_string(),
            dialect_id: "zilog".to_string(),
            cpu_allow_list: None,
            lhs: vec!["ld".to_string()],
            rhs: vec!["ld".to_string(), "x".to_string()],
        }];
        let err = rewrite_tokens(
            &["ld".to_string()],
            &intel_z80(),
            &rules,
            &RewriteLimits {
                max_passes: 8,
                max_growth: 256,
                max_tokens: 1,
            },
        )
        .expect_err("token limit should fail");
        assert!(matches!(err, RewriteError::TokenLimitExceeded { .. }));
    }
}
