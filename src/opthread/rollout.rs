// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! opThread runtime rollout policy by CPU family.
//!
//! This keeps staged-enable controls explicit and testable.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FamilyRuntimeRollout {
    pub family_id: &'static str,
    pub default_runtime_enabled: bool,
    pub migration_checklist: &'static str,
}

pub(crate) const FAMILY_RUNTIME_ROLLOUT: &[FamilyRuntimeRollout] = &[
    FamilyRuntimeRollout {
        family_id: "mos6502",
        default_runtime_enabled: true,
        migration_checklist: "phase6-mos6502-rollout-criteria",
    },
    FamilyRuntimeRollout {
        family_id: "intel8080",
        default_runtime_enabled: false,
        migration_checklist: "phase6-intel8080-pilot-staged",
    },
];

pub(crate) fn family_runtime_rollout_policy(
    family_id: &str,
) -> Option<&'static FamilyRuntimeRollout> {
    FAMILY_RUNTIME_ROLLOUT
        .iter()
        .find(|entry| entry.family_id.eq_ignore_ascii_case(family_id))
}

pub(crate) fn package_runtime_default_enabled_for_family(family_id: &str) -> bool {
    family_runtime_rollout_policy(family_id)
        .map(|entry| entry.default_runtime_enabled)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollout_policy_defaults_mos_family_to_enabled() {
        assert!(package_runtime_default_enabled_for_family("mos6502"));
    }

    #[test]
    fn rollout_policy_keeps_intel_family_staged() {
        assert!(!package_runtime_default_enabled_for_family("intel8080"));
    }

    #[test]
    fn rollout_policy_defaults_unknown_family_to_disabled() {
        assert!(!package_runtime_default_enabled_for_family("unknown"));
    }

    #[test]
    fn rollout_policy_entries_include_migration_checklists() {
        for entry in FAMILY_RUNTIME_ROLLOUT {
            assert!(!entry.migration_checklist.trim().is_empty());
        }
    }
}
