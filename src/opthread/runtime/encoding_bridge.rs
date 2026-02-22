use super::*;

impl HierarchyExecutionModel {
    pub fn encode_instruction(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        mnemonic: &str,
        operands: &dyn OperandSet,
    ) -> Result<Option<Vec<u8>>, RuntimeBridgeError> {
        let candidates = operands.vm_encode_candidates();
        let adapter = OperandSetInstructionAdapter {
            cpu_id,
            dialect_override,
            mnemonic,
            candidates: candidates.as_slice(),
        };
        self.encode_portable_instruction(&adapter)
    }

    pub fn encode_portable_instruction(
        &self,
        request: &dyn PortableInstructionAdapter,
    ) -> Result<Option<Vec<u8>>, RuntimeBridgeError> {
        let resolved = self
            .bridge
            .resolve_pipeline(request.cpu_id(), request.dialect_override())?;
        let candidates = request.vm_encode_candidates();
        if candidates.is_empty() {
            return Ok(None);
        }
        self.enforce_candidate_budget(candidates)?;
        self.encode_candidates(&resolved, request.mnemonic(), candidates)
    }

    pub fn encode_instruction_from_exprs(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        mnemonic: &str,
        operands: &[Expr],
        ctx: &dyn AssemblerContext,
    ) -> Result<Option<Vec<u8>>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        let Some(resolver) = self
            .expr_resolvers
            .get(&resolved.family_id.to_ascii_lowercase())
        else {
            return Ok(None);
        };
        let Some(candidates) = resolver
            .resolver
            .resolve_candidates(self, &resolved, mnemonic, operands, ctx)?
        else {
            return Ok(None);
        };
        self.enforce_candidate_budget(&candidates)?;
        match self.encode_candidates(&resolved, mnemonic, &candidates)? {
            Some(bytes) => Ok(Some(bytes)),
            None => {
                let upper = mnemonic.to_ascii_uppercase();
                let fallback = format!("missing opThread VM program for {}", upper);
                let message = self.diag_message(
                    DIAG_OPTHREAD_MISSING_VM_PROGRAM,
                    fallback.as_str(),
                    &[("mnemonic", upper.as_str())],
                );
                Err(RuntimeBridgeError::Resolve(message))
            }
        }
    }

    pub fn supports_expr_resolution_for_family(&self, family_id: &str) -> bool {
        self.expr_resolvers
            .contains_key(&family_id.to_ascii_lowercase())
    }

    pub(crate) fn expr_resolution_is_strict_for_family(&self, family_id: &str) -> bool {
        self.expr_resolvers
            .get(&family_id.to_ascii_lowercase())
            .map(|entry| entry.strict)
            .unwrap_or(false)
    }

    pub(crate) fn defer_native_diagnostics_on_expr_none(&self, family_id: &str) -> bool {
        self.expr_resolvers
            .get(&family_id.to_ascii_lowercase())
            .map(|entry| entry.defer_native_diagnostics_on_none)
            .unwrap_or(false)
    }

    pub(crate) fn selector_gate_only_expr_runtime_for_cpu(&self, cpu_id: &str) -> bool {
        self.selector_gate_only_expr_runtime_cpus
            .contains(&cpu_id.to_ascii_lowercase())
    }

    pub fn register_expr_resolver_for_family(
        &mut self,
        family_id: &str,
        resolver: ExprResolverFn,
    ) -> Option<Box<dyn FamilyExprResolver>> {
        self.register_expr_resolver_for_family_with_strict_mode(family_id, resolver, true)
    }

    pub fn register_family_expr_resolver(
        &mut self,
        resolver: Box<dyn FamilyExprResolver>,
    ) -> Option<Box<dyn FamilyExprResolver>> {
        self.register_family_expr_resolver_with_strict_mode(resolver, true)
    }

    fn register_expr_resolver_for_family_with_strict_mode(
        &mut self,
        family_id: &str,
        resolver: ExprResolverFn,
        strict: bool,
    ) -> Option<Box<dyn FamilyExprResolver>> {
        let key = family_id.to_ascii_lowercase();
        self.expr_resolvers
            .insert(
                key.clone(),
                ExprResolverEntry {
                    resolver: Box::new(FnFamilyExprResolver {
                        family_id: key,
                        resolver,
                    }),
                    strict,
                    defer_native_diagnostics_on_none: false,
                },
            )
            .map(|entry| entry.resolver)
    }

    fn register_family_expr_resolver_with_strict_mode(
        &mut self,
        resolver: Box<dyn FamilyExprResolver>,
        strict: bool,
    ) -> Option<Box<dyn FamilyExprResolver>> {
        let key = resolver.family_id().to_ascii_lowercase();
        self.expr_resolvers
            .insert(
                key,
                ExprResolverEntry {
                    resolver,
                    strict,
                    defer_native_diagnostics_on_none: false,
                },
            )
            .map(|entry| entry.resolver)
    }
}
