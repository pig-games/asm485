// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::collections::{HashMap, HashSet};

use crate::core::cpu::CpuType;
use crate::core::registry::ModuleRegistry;
use crate::vm::builder::build_hierarchy_chunks_from_registry;

#[derive(Debug, Clone, Default)]
pub struct CpuCapabilityView {
    pub family_id: String,
    pub dialect_id: String,
    pub mnemonics: Vec<String>,
    pub registers: Vec<String>,
    pub runtime_directives: Vec<String>,
    pub mnemonic_owner: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct CapabilitySnapshot {
    pub cpu_name_aliases: Vec<String>,
    pub family_ids: Vec<String>,
    pub cpu_ids: Vec<String>,
    pub dialect_ids: Vec<String>,
    pub directive_keywords: Vec<String>,
    pub cpu_views: HashMap<String, CpuCapabilityView>,
}

impl CapabilitySnapshot {
    pub fn from_registry(registry: &ModuleRegistry) -> Self {
        let cpu_name_aliases = registry.cpu_name_list();
        let family_ids = registry
            .family_ids()
            .into_iter()
            .map(|f| f.as_str().to_string())
            .collect();
        let cpu_ids = registry
            .cpu_ids()
            .into_iter()
            .map(|c| c.as_str().to_string())
            .collect();

        let mut dialect_ids = HashSet::new();
        for family in registry.family_ids() {
            for dialect in registry.dialect_ids_for_family(family) {
                dialect_ids.insert(dialect);
            }
        }
        let dialect_ids = {
            let mut items: Vec<String> = dialect_ids.into_iter().collect();
            items.sort();
            items
        };

        let mut snapshot = Self {
            cpu_name_aliases,
            family_ids,
            cpu_ids,
            dialect_ids,
            ..Self::default()
        };

        for cpu in registry.cpu_ids() {
            let cpu_key = cpu.as_str().to_string();
            if let Some(view) = cpu_capability_view(registry, cpu) {
                snapshot.cpu_views.insert(cpu_key, view);
            }
        }

        snapshot.directive_keywords = collect_global_directives(&snapshot.cpu_views);

        // Build hierarchy chunks once to keep discovery aligned with runtime
        // package metadata without hard-coded lists.
        let _ = build_hierarchy_chunks_from_registry(registry);
        snapshot
    }

    pub fn view_for_cpu(&self, cpu: CpuType) -> Option<&CpuCapabilityView> {
        self.cpu_views.get(cpu.as_str())
    }
}

fn cpu_capability_view(registry: &ModuleRegistry, cpu: CpuType) -> Option<CpuCapabilityView> {
    let pipeline = registry.resolve_pipeline(cpu, None).ok()?;
    let family = pipeline.family_id;
    let dialect_id = pipeline.dialect_id.to_ascii_lowercase();
    let family_id = family.as_str().to_string();

    let mut mnemonic_owner = HashMap::new();
    let mut mnemonics = Vec::new();

    for mnemonic in registry.dialect_form_mnemonics(family, &dialect_id) {
        let key = mnemonic.to_ascii_lowercase();
        if !mnemonics
            .iter()
            .any(|m: &String| m.eq_ignore_ascii_case(&key))
        {
            mnemonics.push(key.clone());
        }
        mnemonic_owner.insert(key, format!("dialect:{dialect_id}"));
    }
    for mnemonic in registry.cpu_form_mnemonics(cpu) {
        let key = mnemonic.to_ascii_lowercase();
        if !mnemonics
            .iter()
            .any(|m: &String| m.eq_ignore_ascii_case(&key))
        {
            mnemonics.push(key.clone());
        }
        mnemonic_owner
            .entry(key)
            .or_insert_with(|| format!("cpu:{}", cpu.as_str().to_ascii_lowercase()));
    }
    for mnemonic in registry.family_form_mnemonics(family) {
        let key = mnemonic.to_ascii_lowercase();
        if !mnemonics
            .iter()
            .any(|m: &String| m.eq_ignore_ascii_case(&key))
        {
            mnemonics.push(key.clone());
        }
        mnemonic_owner
            .entry(key)
            .or_insert_with(|| format!("family:{family_id}"));
    }
    mnemonics.sort();

    let mut registers = registry.cpu_register_ids(cpu);
    registers.extend(registry.family_register_ids(family));
    registers.sort_by_key(|name| name.to_ascii_lowercase());
    registers.dedup_by(|left, right| left.eq_ignore_ascii_case(right));

    let mut runtime_directives: Vec<String> = registry
        .cpu_runtime_directive_ids(cpu)
        .into_iter()
        .map(|name| format!(".{}", name.to_ascii_lowercase()))
        .collect();
    runtime_directives.sort();
    runtime_directives.dedup();

    Some(CpuCapabilityView {
        family_id,
        dialect_id,
        mnemonics,
        registers,
        runtime_directives,
        mnemonic_owner,
    })
}

fn collect_global_directives(cpu_views: &HashMap<String, CpuCapabilityView>) -> Vec<String> {
    let mut out = vec![
        ".cpu".to_string(),
        ".if".to_string(),
        ".endif".to_string(),
        ".module".to_string(),
        ".endmodule".to_string(),
        ".use".to_string(),
        ".namespace".to_string(),
        ".endnamespace".to_string(),
        ".macro".to_string(),
        ".endmacro".to_string(),
        ".section".to_string(),
        ".endsection".to_string(),
        ".org".to_string(),
    ];
    for view in cpu_views.values() {
        out.extend(view.runtime_directives.iter().cloned());
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_snapshot_contains_runtime_directives() {
        let registry = crate::build_default_registry();
        let snapshot = CapabilitySnapshot::from_registry(&registry);
        let cpu = registry
            .resolve_cpu_name("65816")
            .expect("65816 cpu must resolve");
        let view = snapshot
            .view_for_cpu(cpu)
            .expect("snapshot should contain 65816 view");
        assert!(view
            .runtime_directives
            .iter()
            .any(|name| name.eq_ignore_ascii_case(".assume")));
    }
}
