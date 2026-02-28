# opForge LSP Acceptance Traceability (Spec v0.1)

Source spec: `dev-docs/NextSteps/lsp/opforge_language_server_spec_v0_1.md`

## Scenario Mapping

- [x] CPU flow-sensitive context
  Tests:
  `tests/lsp_client_integration.rs::completion_uses_nearest_prior_cpu_context`
  `src/lsp/session.rs::tests::completion_tracks_nearest_prior_cpu_directive`

- [x] Alias correctness (`8080`, `6502`, `65c816`, `mega65`)
  Tests:
  `src/registry_defaults.rs::tests::default_registry_contains_expected_aliases`
  `src/lsp/cpu_context.rs::tests::resolve_cpu_context_prefers_nearest_prior_directive`

- [ ] Dialect correctness and compatibility/fixit behavior parity
  Current coverage:
  existing assembler/runtime tests in `src/assembler/tests.rs`, `src/vm/*`
  Follow-up:
  add explicit LSP integration lane asserting dialect-specific completion/diagnostics across z80/intel8080.

- [x] Validation cadence
  Tests:
  `tests/lsp_client_integration.rs::debounce_blocks_rapid_revalidation_but_allows_later_changes`
  `tests/lsp_client_integration.rs::on_save_forces_validation_even_when_change_is_debounced`

- [ ] Validation cancellation (`newest document version wins`)
  Status:
  partial only; stale-result drop is currently guarded in-session but no true concurrent validation execution lane.
  Follow-up:
  introduce async validation worker + cancellation token, then add integration test with slow validator.

- [x] Unsaved overlay correctness (path remap + dependency diagnostics)
  Tests:
  `tests/lsp_client_integration.rs::overlay_remaps_dependency_diagnostics_to_original_uri`

- [x] Definition coverage (local/imported/workspace deterministic resolution)
  Tests:
  `tests/lsp_client_integration.rs::definition_resolves_local_symbol_declaration`
  `tests/lsp_client_integration.rs::definition_returns_deterministic_multi_results_for_module_targets`

- [x] Code action correctness (`machine-applicable` preferred, `maybe-incorrect` non-preferred)
  Tests:
  `tests/lsp_client_integration.rs::code_actions_mark_machine_applicable_as_preferred`
  `src/lsp/code_actions.rs::tests::machine_applicable_fixits_are_preferred`

- [x] Diagnostics deduplication key behavior
  Tests:
  `tests/lsp_client_integration.rs::diagnostics_are_deduplicated_by_stable_key`
  `src/lsp/diagnostics.rs::tests::dedup_uses_stable_tuple_key`

## PR Checklist Template

- [ ] `cargo test --test lsp_client_integration`
- [ ] `cargo test -q`
- [ ] `cargo clippy -- -D warnings`
- [ ] Verify traceability matrix above has no open required scenario for this PR scope.
