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
}
