// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! opThread runtime rollout policy by CPU family.
//!
//! This keeps staged-enable controls explicit and testable.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FamilyRuntimeMode {
    /// Package/runtime path is the default execution mode for the family.
    Authoritative,
    /// Native path remains default; package/runtime stays staged for parity checks.
    StagedVerification,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FamilyRuntimeRollout {
    pub family_id: &'static str,
    pub runtime_mode: FamilyRuntimeMode,
    pub migration_checklist: &'static str,
}

pub(crate) const FAMILY_RUNTIME_ROLLOUT: &[FamilyRuntimeRollout] = &[
    FamilyRuntimeRollout {
        family_id: "mos6502",
        runtime_mode: FamilyRuntimeMode::Authoritative,
        migration_checklist: "phase6-mos6502-rollout-criteria",
    },
    FamilyRuntimeRollout {
        family_id: "intel8080",
        runtime_mode: FamilyRuntimeMode::Authoritative,
        migration_checklist: "phase6-intel8080-authoritative",
    },
];

pub(crate) fn family_runtime_rollout_policy(
    family_id: &str,
) -> Option<&'static FamilyRuntimeRollout> {
    FAMILY_RUNTIME_ROLLOUT
        .iter()
        .find(|entry| entry.family_id.eq_ignore_ascii_case(family_id))
}

pub(crate) fn family_runtime_mode(family_id: &str) -> FamilyRuntimeMode {
    family_runtime_rollout_policy(family_id)
        .map(|entry| entry.runtime_mode)
        .unwrap_or(FamilyRuntimeMode::StagedVerification)
}

pub(crate) fn package_runtime_default_enabled_for_family(family_id: &str) -> bool {
    matches!(
        family_runtime_mode(family_id),
        FamilyRuntimeMode::Authoritative
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FamilyExprEvalMode {
    /// Portable EXPR VM evaluation is the default for this family.
    Authoritative,
    /// Native host expression evaluation remains default for this family.
    StagedVerification,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FamilyExprEvalRollout {
    pub family_id: &'static str,
    pub expr_eval_mode: FamilyExprEvalMode,
    pub migration_checklist: &'static str,
}

pub(crate) const FAMILY_EXPR_EVAL_ROLLOUT: &[FamilyExprEvalRollout] = &[
    FamilyExprEvalRollout {
        family_id: "mos6502",
        expr_eval_mode: FamilyExprEvalMode::Authoritative,
        migration_checklist: "phase7-mos6502-expr-vm-authoritative",
    },
    FamilyExprEvalRollout {
        family_id: "intel8080",
        expr_eval_mode: FamilyExprEvalMode::Authoritative,
        migration_checklist: "phase7-intel8080-expr-vm-authoritative",
    },
];

pub(crate) fn family_expr_eval_rollout_policy(
    family_id: &str,
) -> Option<&'static FamilyExprEvalRollout> {
    FAMILY_EXPR_EVAL_ROLLOUT
        .iter()
        .find(|entry| entry.family_id.eq_ignore_ascii_case(family_id))
}

pub(crate) fn family_expr_eval_mode(family_id: &str) -> FamilyExprEvalMode {
    family_expr_eval_rollout_policy(family_id)
        .map(|entry| entry.expr_eval_mode)
        .unwrap_or(FamilyExprEvalMode::StagedVerification)
}

pub(crate) fn portable_expr_runtime_default_enabled_for_family(family_id: &str) -> bool {
    matches!(
        family_expr_eval_mode(family_id),
        FamilyExprEvalMode::Authoritative
    )
}

pub(crate) fn portable_expr_runtime_enabled_for_family(
    family_id: &str,
    opt_in_families: &[String],
    force_host_families: &[String],
) -> bool {
    if force_host_families
        .iter()
        .any(|force_host| force_host.eq_ignore_ascii_case(family_id))
    {
        return false;
    }
    portable_expr_runtime_default_enabled_for_family(family_id)
        || opt_in_families
            .iter()
            .any(|opt_in| opt_in.eq_ignore_ascii_case(family_id))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FamilyExprParserMode {
    /// Portable EXPRP parser path is the default for this family.
    Authoritative,
    /// Host parser remains default; EXPRP parser path is staged/opt-in only.
    StagedVerification,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FamilyExprParserRollout {
    pub family_id: &'static str,
    pub expr_parser_mode: FamilyExprParserMode,
    pub migration_checklist: &'static str,
}

pub(crate) const FAMILY_EXPR_PARSER_ROLLOUT: &[FamilyExprParserRollout] = &[
    FamilyExprParserRollout {
        family_id: "mos6502",
        expr_parser_mode: FamilyExprParserMode::Authoritative,
        migration_checklist: "phase8-mos6502-expr-parser-vm-authoritative",
    },
    FamilyExprParserRollout {
        family_id: "intel8080",
        expr_parser_mode: FamilyExprParserMode::Authoritative,
        migration_checklist: "phase8-intel8080-expr-parser-vm-authoritative",
    },
];

pub(crate) fn family_expr_parser_rollout_policy(
    family_id: &str,
) -> Option<&'static FamilyExprParserRollout> {
    FAMILY_EXPR_PARSER_ROLLOUT
        .iter()
        .find(|entry| entry.family_id.eq_ignore_ascii_case(family_id))
}

pub(crate) fn family_expr_parser_mode(family_id: &str) -> FamilyExprParserMode {
    family_expr_parser_rollout_policy(family_id)
        .map(|entry| entry.expr_parser_mode)
        .unwrap_or(FamilyExprParserMode::StagedVerification)
}

pub(crate) fn portable_expr_parser_runtime_default_enabled_for_family(family_id: &str) -> bool {
    matches!(
        family_expr_parser_mode(family_id),
        FamilyExprParserMode::Authoritative
    )
}

pub(crate) fn portable_expr_parser_runtime_enabled_for_family(
    family_id: &str,
    opt_in_families: &[String],
    force_host_families: &[String],
) -> bool {
    if force_host_families
        .iter()
        .any(|force_host| force_host.eq_ignore_ascii_case(family_id))
    {
        return false;
    }
    portable_expr_parser_runtime_default_enabled_for_family(family_id)
        || opt_in_families
            .iter()
            .any(|opt_in| opt_in.eq_ignore_ascii_case(family_id))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ParserCertificationChecklists {
    pub expression_parser_checklist: Option<&'static str>,
    pub instruction_parse_encode_checklist: Option<&'static str>,
}

pub(crate) fn parser_certification_checklists_for_family(
    family_id: &str,
) -> ParserCertificationChecklists {
    ParserCertificationChecklists {
        expression_parser_checklist: family_expr_parser_rollout_policy(family_id)
            .map(|entry| entry.migration_checklist),
        instruction_parse_encode_checklist: family_runtime_rollout_policy(family_id)
            .map(|entry| entry.migration_checklist),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollout_policy_marks_mos_family_as_authoritative() {
        assert_eq!(
            family_runtime_mode("mos6502"),
            FamilyRuntimeMode::Authoritative
        );
        assert!(package_runtime_default_enabled_for_family("mos6502"));
    }

    #[test]
    fn rollout_policy_marks_intel_family_as_authoritative() {
        assert_eq!(
            family_runtime_mode("intel8080"),
            FamilyRuntimeMode::Authoritative
        );
        assert!(package_runtime_default_enabled_for_family("intel8080"));
    }

    #[test]
    fn rollout_policy_defaults_unknown_family_to_staged_verification() {
        assert_eq!(
            family_runtime_mode("unknown"),
            FamilyRuntimeMode::StagedVerification
        );
        assert!(!package_runtime_default_enabled_for_family("unknown"));
    }

    #[test]
    fn rollout_policy_entries_include_migration_checklists() {
        for entry in FAMILY_RUNTIME_ROLLOUT {
            assert!(!entry.migration_checklist.trim().is_empty());
        }
    }

    #[test]
    fn expr_eval_rollout_marks_mos_family_as_authoritative() {
        assert_eq!(
            family_expr_eval_mode("mos6502"),
            FamilyExprEvalMode::Authoritative
        );
        assert!(portable_expr_runtime_default_enabled_for_family("mos6502"));
    }

    #[test]
    fn expr_eval_rollout_marks_intel_family_as_authoritative() {
        assert_eq!(
            family_expr_eval_mode("intel8080"),
            FamilyExprEvalMode::Authoritative
        );
        assert!(portable_expr_runtime_default_enabled_for_family(
            "intel8080"
        ));
    }

    #[test]
    fn expr_eval_rollout_defaults_unknown_family_to_staged_verification() {
        assert_eq!(
            family_expr_eval_mode("unknown"),
            FamilyExprEvalMode::StagedVerification
        );
        assert!(!portable_expr_runtime_default_enabled_for_family("unknown"));
    }

    #[test]
    fn expr_eval_rollout_entries_include_migration_checklists() {
        for entry in FAMILY_EXPR_EVAL_ROLLOUT {
            assert!(!entry.migration_checklist.trim().is_empty());
        }
    }

    #[test]
    fn expr_eval_rollout_opt_in_promotes_staged_family() {
        let opt_in = vec!["intel8080".to_string()];
        assert!(portable_expr_runtime_enabled_for_family(
            "intel8080",
            &opt_in,
            &[]
        ));
    }

    #[test]
    fn expr_eval_rollout_opt_in_is_case_insensitive() {
        let opt_in = vec!["Intel8080".to_string()];
        assert!(portable_expr_runtime_enabled_for_family(
            "intel8080",
            &opt_in,
            &[]
        ));
    }

    #[test]
    fn expr_eval_rollout_force_host_disables_default_enabled_family() {
        let force_host = vec!["MoS6502".to_string()];
        assert!(!portable_expr_runtime_enabled_for_family(
            "mos6502",
            &[],
            &force_host
        ));
    }

    #[test]
    fn expr_eval_rollout_force_host_overrides_opt_in() {
        let opt_in = vec!["intel8080".to_string()];
        let force_host = vec!["InTeL8080".to_string()];
        assert!(!portable_expr_runtime_enabled_for_family(
            "intel8080",
            &opt_in,
            &force_host
        ));
    }

    #[test]
    fn expr_parser_rollout_marks_mos_family_as_authoritative() {
        assert_eq!(
            family_expr_parser_mode("mos6502"),
            FamilyExprParserMode::Authoritative
        );
        assert!(portable_expr_parser_runtime_default_enabled_for_family(
            "mos6502"
        ));
    }

    #[test]
    fn expr_parser_rollout_marks_intel_family_as_authoritative() {
        assert_eq!(
            family_expr_parser_mode("intel8080"),
            FamilyExprParserMode::Authoritative
        );
        assert!(portable_expr_parser_runtime_default_enabled_for_family(
            "intel8080"
        ));
    }

    #[test]
    fn expr_parser_rollout_defaults_unknown_family_to_staged_verification() {
        assert_eq!(
            family_expr_parser_mode("unknown"),
            FamilyExprParserMode::StagedVerification
        );
        assert!(!portable_expr_parser_runtime_default_enabled_for_family(
            "unknown"
        ));
    }

    #[test]
    fn expr_parser_rollout_entries_include_migration_checklists() {
        for entry in FAMILY_EXPR_PARSER_ROLLOUT {
            assert!(!entry.migration_checklist.trim().is_empty());
        }
    }

    #[test]
    fn expr_parser_rollout_opt_in_promotes_staged_family() {
        let opt_in = vec!["intel8080".to_string()];
        assert!(portable_expr_parser_runtime_enabled_for_family(
            "intel8080",
            &opt_in,
            &[]
        ));
    }

    #[test]
    fn expr_parser_rollout_opt_in_is_case_insensitive() {
        let opt_in = vec!["Intel8080".to_string()];
        assert!(portable_expr_parser_runtime_enabled_for_family(
            "intel8080",
            &opt_in,
            &[]
        ));
    }

    #[test]
    fn expr_parser_rollout_force_host_disables_default_enabled_family() {
        let force_host = vec!["MoS6502".to_string()];
        assert!(!portable_expr_parser_runtime_enabled_for_family(
            "mos6502",
            &[],
            &force_host
        ));
    }

    #[test]
    fn expr_parser_rollout_force_host_overrides_opt_in() {
        let opt_in = vec!["intel8080".to_string()];
        let force_host = vec!["InTeL8080".to_string()];
        assert!(!portable_expr_parser_runtime_enabled_for_family(
            "intel8080",
            &opt_in,
            &force_host
        ));
    }

    #[test]
    fn parser_certification_checklists_include_expr_and_instruction_tracks() {
        let checklists = parser_certification_checklists_for_family("mos6502");
        assert_eq!(
            checklists.expression_parser_checklist,
            Some("phase8-mos6502-expr-parser-vm-authoritative")
        );
        assert_eq!(
            checklists.instruction_parse_encode_checklist,
            Some("phase6-mos6502-rollout-criteria")
        );
    }

    #[test]
    fn parser_certification_checklists_default_to_none_for_unknown_family() {
        let checklists = parser_certification_checklists_for_family("unknown");
        assert_eq!(checklists.expression_parser_checklist, None);
        assert_eq!(checklists.instruction_parse_encode_checklist, None);
    }
}
