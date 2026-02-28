# RELEASE NOTES v0.10.0

## Added

- New `opforge-lsp` binary for editor integration over Language Server Protocol (LSP 3.17).
- New `src/lsp/` architecture modules:
  - protocol/session/config orchestration
  - CPU context resolver based on nearest prior `.cpu`
  - registry-driven completion and hover
  - definition and document symbol providers
  - diagnostic publishing and quick-fix code actions
  - CLI validation runner wiring
- New public shared registry constructor:
  - `build_default_registry()`
  - used by assembler, VM tooling, and LSP surfaces to keep CPU/family/dialect registration parity.
- New VM editor-safe public bridge exports:
  - `vm::editor_default_runtime_model`
  - `vm::editor_parse_line`
  - `vm::editor_parse_line_with_model`
  - `vm::editor_tokenize_line`
  - `vm::editor_tokenize_line_with_model`
- New runtime-directive introspection metadata via registry (`cpu_runtime_directive_ids`) with 65816 coverage (`.assume`, width/state directives).
- New VS Code reference client scaffold under `clients/vscode`.

## Changed

- Consolidated duplicated default registry wiring into a single reusable constructor.
- VM token bridge default model now uses canonical shared registry wiring.

## Compatibility

- Existing `opforge` CLI behavior remains unchanged.
