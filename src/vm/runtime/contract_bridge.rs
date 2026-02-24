use super::*;

impl HierarchyExecutionModel {
    pub(super) fn parser_contract_for_resolved(
        &self,
        resolved: &ResolvedHierarchy,
    ) -> Option<&RuntimeParserContract> {
        self.lookup_scoped(&self.parser_contracts, resolved)
    }

    pub(super) fn parser_vm_program_for_resolved(
        &self,
        resolved: &ResolvedHierarchy,
    ) -> Option<&RuntimeParserVmProgram> {
        self.lookup_scoped(&self.parser_vm_programs, resolved)
    }

    pub(super) fn expr_contract_for_resolved(
        &self,
        resolved: &ResolvedHierarchy,
    ) -> Option<&RuntimeExprContract> {
        self.lookup_scoped(&self.expr_contracts, resolved)
    }

    pub(super) fn expr_parser_contract_for_resolved(
        &self,
        resolved: &ResolvedHierarchy,
    ) -> Option<&RuntimeExprParserContract> {
        self.lookup_scoped(&self.expr_parser_contracts, resolved)
    }

    pub(super) fn ensure_parser_contract_compatible_for_assembler(
        &self,
        contract: &RuntimeParserContract,
    ) -> Result<(), RuntimeBridgeError> {
        self.ensure_parser_diagnostic_map_compatible_for_assembler(contract)?;
        let error_code = parser_contract_error_code(contract);
        if contract.max_ast_nodes_per_line == 0 {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: parser contract max_ast_nodes_per_line must be > 0",
                error_code
            )));
        }
        if contract.opcode_version != PARSER_VM_OPCODE_VERSION_V1 {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: unsupported parser contract opcode version {}",
                error_code, contract.opcode_version
            )));
        }
        if !contract
            .grammar_id
            .eq_ignore_ascii_case(PARSER_GRAMMAR_ID_LINE_V1)
        {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: unsupported parser grammar id '{}'",
                error_code, contract.grammar_id
            )));
        }
        if !contract
            .ast_schema_id
            .eq_ignore_ascii_case(PARSER_AST_SCHEMA_ID_LINE_V1)
        {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: unsupported parser AST schema id '{}'",
                error_code, contract.ast_schema_id
            )));
        }
        Ok(())
    }

    fn ensure_parser_diagnostic_map_compatible_for_assembler(
        &self,
        contract: &RuntimeParserContract,
    ) -> Result<(), RuntimeBridgeError> {
        let error_code = parser_contract_error_code(contract);
        for (field_name, value) in [
            (
                "unexpected_token",
                contract.diagnostics.unexpected_token.as_str(),
            ),
            (
                "expected_expression",
                contract.diagnostics.expected_expression.as_str(),
            ),
            (
                "expected_operand",
                contract.diagnostics.expected_operand.as_str(),
            ),
            (
                "invalid_statement",
                contract.diagnostics.invalid_statement.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(RuntimeBridgeError::Resolve(format!(
                    "{}: missing parser contract diagnostic mapping for '{}'",
                    error_code, field_name
                )));
            }
            self.ensure_diag_code_declared_in_package_catalog(
                error_code,
                "parser contract",
                value,
            )?;
        }
        Ok(())
    }

    pub(super) fn ensure_expr_parser_contract_compatible_for_assembler(
        &self,
        contract: &RuntimeExprParserContract,
    ) -> Result<(), RuntimeBridgeError> {
        let error_code = if contract
            .diagnostics
            .invalid_expression_program
            .trim()
            .is_empty()
        {
            "vm-runtime"
        } else {
            contract.diagnostics.invalid_expression_program.as_str()
        };

        if contract.opcode_version != EXPR_PARSER_VM_OPCODE_VERSION_V1 {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: unsupported expression parser contract opcode version {}",
                error_code, contract.opcode_version
            )));
        }

        if contract
            .diagnostics
            .invalid_expression_program
            .trim()
            .is_empty()
        {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: missing diagnostics.invalid_expression_program code",
                error_code
            )));
        }

        self.ensure_diag_code_declared_in_package_catalog(
            error_code,
            "expression parser contract diagnostics.invalid_expression_program",
            contract.diagnostics.invalid_expression_program.as_str(),
        )
    }

    pub(super) fn ensure_diag_code_declared_in_package_catalog(
        &self,
        error_code: &str,
        context: &str,
        code: &str,
    ) -> Result<(), RuntimeBridgeError> {
        if self.diag_templates.contains_key(&code.to_ascii_lowercase()) {
            return Ok(());
        }
        Err(RuntimeBridgeError::Resolve(format!(
            "{}: {} diagnostic code '{}' is not declared in package DIAG catalog",
            error_code, context, code
        )))
    }
}
