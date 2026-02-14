// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Family/CPU/Dialect hierarchy schema and resolver for opThread packages.
//!
//! This module mirrors opForge registry semantics for pipeline selection:
//! explicit dialect override, then CPU default dialect, then family canonical.

use std::collections::{HashMap, HashSet};

/// Normalized, case-insensitive identifier key used for package lookups.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NormalizedId(String);

impl NormalizedId {
    pub fn new(raw: &str) -> Self {
        Self(raw.to_ascii_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Family descriptor from package metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyDescriptor {
    pub id: String,
    pub canonical_dialect: String,
}

/// CPU descriptor from package metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuDescriptor {
    pub id: String,
    pub family_id: String,
    pub default_dialect: Option<String>,
}

/// Dialect descriptor from package metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialectDescriptor {
    pub id: String,
    pub family_id: String,
    pub cpu_allow_list: Option<Vec<String>>,
}

/// Ownership model for scoped `REGS` and `FORM` entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopedOwner {
    Family(String),
    Cpu(String),
    Dialect(String),
}

/// Register descriptor with explicit scope ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedRegisterDescriptor {
    pub owner: ScopedOwner,
    pub id: String,
}

/// Form descriptor with explicit scope ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedFormDescriptor {
    pub owner: ScopedOwner,
    pub mnemonic: String,
}

/// Fully-resolved hierarchy context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedHierarchy {
    pub family_id: String,
    pub cpu_id: String,
    pub dialect_id: String,
}

/// Hierarchy errors used by validator and resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HierarchyError {
    DuplicateFamilyId {
        family_id: String,
    },
    DuplicateCpuId {
        cpu_id: String,
    },
    DuplicateDialectId {
        family_id: String,
        dialect_id: String,
    },
    MissingCpu {
        cpu_id: String,
    },
    MissingFamilyForCpu {
        cpu_id: String,
        family_id: String,
    },
    MissingDialectRef {
        owner_kind: &'static str,
        owner_id: String,
        dialect_id: String,
    },
    CrossFamilyDialectSelection {
        owner_kind: &'static str,
        owner_id: String,
        owner_family_id: String,
        dialect_id: String,
        dialect_family_id: String,
    },
    UnknownCpuInDialectAllowList {
        dialect_id: String,
        family_id: String,
        cpu_id: String,
    },
    CpuBlockedByDialectAllowList {
        cpu_id: String,
        dialect_id: String,
    },
}

impl std::fmt::Display for HierarchyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateFamilyId { family_id } => {
                write!(f, "duplicate family id '{}'", family_id)
            }
            Self::DuplicateCpuId { cpu_id } => write!(f, "duplicate cpu id '{}'", cpu_id),
            Self::DuplicateDialectId {
                family_id,
                dialect_id,
            } => write!(
                f,
                "duplicate dialect '{}' in family '{}'",
                dialect_id, family_id
            ),
            Self::MissingCpu { cpu_id } => write!(f, "unknown cpu '{}'", cpu_id),
            Self::MissingFamilyForCpu { cpu_id, family_id } => write!(
                f,
                "cpu '{}' references missing family '{}'",
                cpu_id, family_id
            ),
            Self::MissingDialectRef {
                owner_kind,
                owner_id,
                dialect_id,
            } => write!(
                f,
                "{} '{}' references missing dialect '{}'",
                owner_kind, owner_id, dialect_id
            ),
            Self::CrossFamilyDialectSelection {
                owner_kind,
                owner_id,
                owner_family_id,
                dialect_id,
                dialect_family_id,
            } => write!(
                f,
                "{} '{}' in family '{}' cannot select dialect '{}' from family '{}'",
                owner_kind, owner_id, owner_family_id, dialect_id, dialect_family_id
            ),
            Self::UnknownCpuInDialectAllowList {
                dialect_id,
                family_id,
                cpu_id,
            } => write!(
                f,
                "dialect '{}' in family '{}' has unknown cpu '{}' in allow-list",
                dialect_id, family_id, cpu_id
            ),
            Self::CpuBlockedByDialectAllowList { cpu_id, dialect_id } => write!(
                f,
                "cpu '{}' is not compatible with dialect '{}'",
                cpu_id, dialect_id
            ),
        }
    }
}

impl std::error::Error for HierarchyError {}

/// Validated hierarchy package view with case-insensitive lookup keys.
#[derive(Debug)]
pub struct HierarchyPackage {
    families: HashMap<NormalizedId, FamilyDescriptor>,
    cpus: HashMap<NormalizedId, CpuDescriptor>,
    dialects: HashMap<(NormalizedId, NormalizedId), DialectDescriptor>,
    dialect_families: HashMap<NormalizedId, HashSet<NormalizedId>>,
}

impl HierarchyPackage {
    pub fn new(
        families: Vec<FamilyDescriptor>,
        cpus: Vec<CpuDescriptor>,
        dialects: Vec<DialectDescriptor>,
    ) -> Result<Self, HierarchyError> {
        let mut family_map = HashMap::new();
        for family in families {
            let key = NormalizedId::new(&family.id);
            if family_map.contains_key(&key) {
                return Err(HierarchyError::DuplicateFamilyId {
                    family_id: family.id,
                });
            }
            family_map.insert(key, family);
        }

        let mut dialect_map = HashMap::new();
        let mut dialect_families: HashMap<NormalizedId, HashSet<NormalizedId>> = HashMap::new();
        for dialect in dialects {
            let family_key = NormalizedId::new(&dialect.family_id);
            let dialect_key = NormalizedId::new(&dialect.id);

            let composite = (family_key.clone(), dialect_key.clone());
            if dialect_map.contains_key(&composite) {
                return Err(HierarchyError::DuplicateDialectId {
                    family_id: dialect.family_id,
                    dialect_id: dialect.id,
                });
            }

            dialect_families
                .entry(dialect_key)
                .or_default()
                .insert(family_key);
            dialect_map.insert(composite, dialect);
        }

        let mut cpu_map = HashMap::new();
        for cpu in cpus {
            let cpu_key = NormalizedId::new(&cpu.id);
            if cpu_map.contains_key(&cpu_key) {
                return Err(HierarchyError::DuplicateCpuId { cpu_id: cpu.id });
            }
            cpu_map.insert(cpu_key, cpu);
        }

        let package = Self {
            families: family_map,
            cpus: cpu_map,
            dialects: dialect_map,
            dialect_families,
        };

        package.validate_cross_references()?;
        Ok(package)
    }

    pub fn resolve_pipeline(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<ResolvedHierarchy, HierarchyError> {
        let cpu_key = NormalizedId::new(cpu_id);
        let cpu = self
            .cpus
            .get(&cpu_key)
            .ok_or_else(|| HierarchyError::MissingCpu {
                cpu_id: cpu_id.to_string(),
            })?;

        let family_key = NormalizedId::new(&cpu.family_id);
        let family =
            self.families
                .get(&family_key)
                .ok_or_else(|| HierarchyError::MissingFamilyForCpu {
                    cpu_id: cpu.id.clone(),
                    family_id: cpu.family_id.clone(),
                })?;

        let selected = if let Some(override_id) = dialect_override {
            match self.lookup_dialect(&family_key, override_id) {
                Some(dialect) => dialect,
                None => {
                    if let Some(other_family) =
                        self.find_cross_family_dialect(&family_key, &NormalizedId::new(override_id))
                    {
                        return Err(HierarchyError::CrossFamilyDialectSelection {
                            owner_kind: "cpu",
                            owner_id: cpu.id.clone(),
                            owner_family_id: cpu.family_id.clone(),
                            dialect_id: override_id.to_string(),
                            dialect_family_id: other_family,
                        });
                    }
                    return Err(HierarchyError::MissingDialectRef {
                        owner_kind: "dialect override",
                        owner_id: cpu.id.clone(),
                        dialect_id: override_id.to_string(),
                    });
                }
            }
        } else if let Some(default_dialect) = cpu.default_dialect.as_deref() {
            self.lookup_dialect(&family_key, default_dialect)
                .ok_or_else(|| HierarchyError::MissingDialectRef {
                    owner_kind: "cpu default dialect",
                    owner_id: cpu.id.clone(),
                    dialect_id: default_dialect.to_string(),
                })?
        } else {
            self.lookup_dialect(&family_key, &family.canonical_dialect)
                .ok_or_else(|| HierarchyError::MissingDialectRef {
                    owner_kind: "family canonical dialect",
                    owner_id: family.id.clone(),
                    dialect_id: family.canonical_dialect.clone(),
                })?
        };

        if !self.dialect_allows_cpu(selected, &cpu_key) {
            return Err(HierarchyError::CpuBlockedByDialectAllowList {
                cpu_id: cpu.id.clone(),
                dialect_id: selected.id.clone(),
            });
        }

        Ok(ResolvedHierarchy {
            family_id: family.id.clone(),
            cpu_id: cpu.id.clone(),
            dialect_id: selected.id.clone(),
        })
    }

    fn validate_cross_references(&self) -> Result<(), HierarchyError> {
        for cpu in self.cpus.values() {
            let family_key = NormalizedId::new(&cpu.family_id);
            if !self.families.contains_key(&family_key) {
                return Err(HierarchyError::MissingFamilyForCpu {
                    cpu_id: cpu.id.clone(),
                    family_id: cpu.family_id.clone(),
                });
            }
            if let Some(default_dialect) = cpu.default_dialect.as_deref() {
                self.validate_dialect_ref(
                    "cpu default dialect",
                    &cpu.id,
                    &cpu.family_id,
                    default_dialect,
                )?;
            }
        }

        for family in self.families.values() {
            self.validate_dialect_ref(
                "family canonical dialect",
                &family.id,
                &family.id,
                &family.canonical_dialect,
            )?;
        }

        for dialect in self.dialects.values() {
            if let Some(allow_list) = dialect.cpu_allow_list.as_deref() {
                for cpu_id in allow_list {
                    let cpu_key = NormalizedId::new(cpu_id);
                    let Some(cpu) = self.cpus.get(&cpu_key) else {
                        return Err(HierarchyError::UnknownCpuInDialectAllowList {
                            dialect_id: dialect.id.clone(),
                            family_id: dialect.family_id.clone(),
                            cpu_id: cpu_id.clone(),
                        });
                    };
                    if !NormalizedId::new(&cpu.family_id).eq(&NormalizedId::new(&dialect.family_id))
                    {
                        return Err(HierarchyError::CrossFamilyDialectSelection {
                            owner_kind: "dialect allow-list",
                            owner_id: dialect.id.clone(),
                            owner_family_id: dialect.family_id.clone(),
                            dialect_id: dialect.id.clone(),
                            dialect_family_id: cpu.family_id.clone(),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_dialect_ref(
        &self,
        owner_kind: &'static str,
        owner_id: &str,
        owner_family_id: &str,
        dialect_id: &str,
    ) -> Result<(), HierarchyError> {
        let family_key = NormalizedId::new(owner_family_id);
        let dialect_key = NormalizedId::new(dialect_id);
        if self
            .dialects
            .contains_key(&(family_key.clone(), dialect_key.clone()))
        {
            return Ok(());
        }

        if let Some(other_family) = self.find_cross_family_dialect(&family_key, &dialect_key) {
            return Err(HierarchyError::CrossFamilyDialectSelection {
                owner_kind,
                owner_id: owner_id.to_string(),
                owner_family_id: owner_family_id.to_string(),
                dialect_id: dialect_id.to_string(),
                dialect_family_id: other_family,
            });
        }

        Err(HierarchyError::MissingDialectRef {
            owner_kind,
            owner_id: owner_id.to_string(),
            dialect_id: dialect_id.to_string(),
        })
    }

    fn lookup_dialect(
        &self,
        family_key: &NormalizedId,
        dialect_id: &str,
    ) -> Option<&DialectDescriptor> {
        let dialect_key = NormalizedId::new(dialect_id);
        self.dialects
            .get(&(family_key.clone(), dialect_key))
            .map(|dialect| dialect as _)
    }

    fn find_cross_family_dialect(
        &self,
        owner_family: &NormalizedId,
        dialect_key: &NormalizedId,
    ) -> Option<String> {
        let families = self.dialect_families.get(dialect_key)?;
        families
            .iter()
            .find(|candidate| *candidate != owner_family)
            .and_then(|candidate| {
                self.families
                    .get(candidate)
                    .map(|family| family.id.clone())
                    .or_else(|| Some(candidate.as_str().to_string()))
            })
    }

    fn dialect_allows_cpu(&self, dialect: &DialectDescriptor, cpu_key: &NormalizedId) -> bool {
        match dialect.cpu_allow_list.as_deref() {
            None => true,
            Some(allow_list) => allow_list
                .iter()
                .any(|cpu| NormalizedId::new(cpu) == *cpu_key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_family() -> FamilyDescriptor {
        FamilyDescriptor {
            id: "intel8080".to_string(),
            canonical_dialect: "intel".to_string(),
        }
    }

    fn base_cpu() -> CpuDescriptor {
        CpuDescriptor {
            id: "8085".to_string(),
            family_id: "intel8080".to_string(),
            default_dialect: Some("intel".to_string()),
        }
    }

    fn base_dialect() -> DialectDescriptor {
        DialectDescriptor {
            id: "intel".to_string(),
            family_id: "intel8080".to_string(),
            cpu_allow_list: None,
        }
    }

    #[test]
    fn resolve_pipeline_prefers_explicit_override() {
        let package = HierarchyPackage::new(
            vec![base_family()],
            vec![base_cpu()],
            vec![
                base_dialect(),
                DialectDescriptor {
                    id: "alt".to_string(),
                    family_id: "intel8080".to_string(),
                    cpu_allow_list: None,
                },
            ],
        )
        .expect("package should validate");

        let resolved = package
            .resolve_pipeline("8085", Some("ALT"))
            .expect("override should resolve");

        assert_eq!(resolved.family_id, "intel8080");
        assert_eq!(resolved.cpu_id, "8085");
        assert_eq!(resolved.dialect_id, "alt");
    }

    #[test]
    fn resolve_pipeline_uses_cpu_default_then_family_canonical() {
        let package =
            HierarchyPackage::new(vec![base_family()], vec![base_cpu()], vec![base_dialect()])
                .expect("package should validate");

        let resolved = package
            .resolve_pipeline("8085", None)
            .expect("cpu default should resolve");
        assert_eq!(resolved.dialect_id, "intel");

        let package_no_default = HierarchyPackage::new(
            vec![base_family()],
            vec![CpuDescriptor {
                default_dialect: None,
                ..base_cpu()
            }],
            vec![base_dialect()],
        )
        .expect("package should validate");

        let resolved = package_no_default
            .resolve_pipeline("8085", None)
            .expect("family canonical should resolve");
        assert_eq!(resolved.dialect_id, "intel");
    }

    #[test]
    fn resolve_pipeline_rejects_cross_family_override() {
        let package = HierarchyPackage::new(
            vec![
                FamilyDescriptor {
                    id: "intel8080".to_string(),
                    canonical_dialect: "intel".to_string(),
                },
                FamilyDescriptor {
                    id: "mos6502".to_string(),
                    canonical_dialect: "default6502".to_string(),
                },
            ],
            vec![base_cpu()],
            vec![
                base_dialect(),
                DialectDescriptor {
                    id: "default6502".to_string(),
                    family_id: "mos6502".to_string(),
                    cpu_allow_list: None,
                },
            ],
        )
        .expect("package should validate");

        let err = package
            .resolve_pipeline("8085", Some("default6502"))
            .expect_err("cross-family override should fail");
        assert!(matches!(
            err,
            HierarchyError::CrossFamilyDialectSelection { .. }
        ));
    }

    #[test]
    fn validate_rejects_missing_family_for_cpu() {
        let err = HierarchyPackage::new(
            vec![base_family()],
            vec![CpuDescriptor {
                id: "ghost".to_string(),
                family_id: "missing".to_string(),
                default_dialect: None,
            }],
            vec![base_dialect()],
        )
        .expect_err("missing family should fail validation");

        assert!(matches!(err, HierarchyError::MissingFamilyForCpu { .. }));
    }

    #[test]
    fn validate_rejects_missing_dialect_ref() {
        let err = HierarchyPackage::new(
            vec![base_family()],
            vec![CpuDescriptor {
                default_dialect: Some("unknown".to_string()),
                ..base_cpu()
            }],
            vec![base_dialect()],
        )
        .expect_err("missing dialect should fail validation");

        assert!(matches!(err, HierarchyError::MissingDialectRef { .. }));
    }

    #[test]
    fn validate_rejects_cross_family_dialect_ref() {
        let err = HierarchyPackage::new(
            vec![
                FamilyDescriptor {
                    id: "intel8080".to_string(),
                    canonical_dialect: "intel".to_string(),
                },
                FamilyDescriptor {
                    id: "mos6502".to_string(),
                    canonical_dialect: "default6502".to_string(),
                },
            ],
            vec![CpuDescriptor {
                id: "bad".to_string(),
                family_id: "intel8080".to_string(),
                default_dialect: Some("default6502".to_string()),
            }],
            vec![
                DialectDescriptor {
                    id: "intel".to_string(),
                    family_id: "intel8080".to_string(),
                    cpu_allow_list: None,
                },
                DialectDescriptor {
                    id: "default6502".to_string(),
                    family_id: "mos6502".to_string(),
                    cpu_allow_list: None,
                },
            ],
        )
        .expect_err("cross-family dialect should fail validation");

        assert!(matches!(
            err,
            HierarchyError::CrossFamilyDialectSelection { .. }
        ));
    }

    #[test]
    fn resolve_pipeline_rejects_cpu_blocked_by_allow_list() {
        let package = HierarchyPackage::new(
            vec![base_family()],
            vec![
                CpuDescriptor {
                    id: "8085".to_string(),
                    family_id: "intel8080".to_string(),
                    default_dialect: Some("intel".to_string()),
                },
                CpuDescriptor {
                    id: "z80".to_string(),
                    family_id: "intel8080".to_string(),
                    default_dialect: Some("zilog".to_string()),
                },
            ],
            vec![
                DialectDescriptor {
                    id: "intel".to_string(),
                    family_id: "intel8080".to_string(),
                    cpu_allow_list: None,
                },
                DialectDescriptor {
                    id: "zilog".to_string(),
                    family_id: "intel8080".to_string(),
                    cpu_allow_list: Some(vec!["z80".to_string()]),
                },
            ],
        )
        .expect("package should validate");

        let err = package
            .resolve_pipeline("8085", Some("zilog"))
            .expect_err("8085 should be blocked by allow-list");
        assert!(matches!(
            err,
            HierarchyError::CpuBlockedByDialectAllowList { .. }
        ));
    }

    #[test]
    fn id_lookup_is_case_insensitive() {
        let package =
            HierarchyPackage::new(vec![base_family()], vec![base_cpu()], vec![base_dialect()])
                .expect("package should validate");

        let resolved = package
            .resolve_pipeline("8085", Some("InTeL"))
            .expect("mixed-case dialect should resolve");
        assert_eq!(resolved.dialect_id, "intel");
    }
}
