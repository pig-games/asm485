use super::*;

impl HierarchyExecutionModel {
    pub(super) fn interned_id(&self, value_lower: &str) -> Option<u32> {
        self.interned_ids.get(value_lower).copied()
    }

    pub(super) fn scoped_owner_lookup_order(
        &self,
        resolved: &ResolvedHierarchy,
    ) -> [(u8, Option<u32>); 3] {
        let dialect_id = resolved.dialect_id.to_ascii_lowercase();
        let cpu_id = resolved.cpu_id.to_ascii_lowercase();
        let family_id = resolved.family_id.to_ascii_lowercase();
        [
            (2u8, self.interned_id(&dialect_id)),
            (1u8, self.interned_id(&cpu_id)),
            (0u8, self.interned_id(&family_id)),
        ]
    }

    pub(super) fn lookup_scoped<'a, T>(
        &self,
        map: &'a HashMap<(u8, u32), T>,
        resolved: &ResolvedHierarchy,
    ) -> Option<&'a T> {
        for (owner_tag, owner_id) in self.scoped_owner_lookup_order(resolved) {
            let Some(owner_id) = owner_id else {
                continue;
            };
            if let Some(value) = map.get(&(owner_tag, owner_id)) {
                return Some(value);
            }
        }
        None
    }

    pub(super) fn encode_candidates(
        &self,
        resolved: &ResolvedHierarchy,
        mnemonic: &str,
        candidates: &[VmEncodeCandidate],
    ) -> Result<Option<Vec<u8>>, RuntimeBridgeError> {
        let normalized_mnemonic = mnemonic.to_ascii_lowercase();
        let Some(mnemonic_id) = self.interned_id(&normalized_mnemonic) else {
            return Ok(None);
        };
        let owner_order = self.scoped_owner_lookup_order(resolved);

        for candidate in candidates {
            let mode_key = candidate.mode_key.to_ascii_lowercase();
            let Some(mode_id) = self.interned_id(&mode_key) else {
                continue;
            };
            let operand_views: Vec<&[u8]> =
                candidate.operand_bytes.iter().map(Vec::as_slice).collect();
            for (owner_tag, owner_id) in owner_order {
                let Some(owner_id) = owner_id else {
                    continue;
                };
                let key = (owner_tag, owner_id, mnemonic_id, mode_id);
                if let Some(program) = self.vm_programs.get(&key) {
                    self.enforce_vm_program_budget(program.len())?;
                    return execute_program(program, operand_views.as_slice())
                        .map(Some)
                        .map_err(Into::into);
                }
            }
        }
        Ok(None)
    }

    pub(super) fn enforce_candidate_budget(
        &self,
        candidates: &[VmEncodeCandidate],
    ) -> Result<(), RuntimeBridgeError> {
        if candidates.len() > self.budget_limits.max_candidate_count {
            return Err(Self::budget_error(
                "candidate_count",
                self.budget_limits.max_candidate_count,
                candidates.len(),
            ));
        }
        for candidate in candidates {
            if candidate.operand_bytes.len() > self.budget_limits.max_operand_count_per_candidate {
                return Err(Self::budget_error(
                    "operand_count_per_candidate",
                    self.budget_limits.max_operand_count_per_candidate,
                    candidate.operand_bytes.len(),
                ));
            }
            for operand_bytes in &candidate.operand_bytes {
                if operand_bytes.len() > self.budget_limits.max_operand_bytes_per_operand {
                    return Err(Self::budget_error(
                        "operand_bytes_per_operand",
                        self.budget_limits.max_operand_bytes_per_operand,
                        operand_bytes.len(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn enforce_vm_program_budget(
        &self,
        program_len: usize,
    ) -> Result<(), RuntimeBridgeError> {
        if program_len > self.budget_limits.max_vm_program_bytes {
            return Err(Self::budget_error(
                "vm_program_bytes",
                self.budget_limits.max_vm_program_bytes,
                program_len,
            ));
        }
        Ok(())
    }

    pub(super) fn budget_error(name: &str, limit: usize, observed: usize) -> RuntimeBridgeError {
        RuntimeBridgeError::Resolve(format!(
            "opThread runtime budget exceeded ({name}): observed {observed}, limit {limit}"
        ))
    }
}
