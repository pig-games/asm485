# opForge v0.9.5 Release Notes

## Scope

This release completes the ranges/lists/repetition feature rollout and strengthens VM-only/runtime-package delivery and CI quality-gate coverage.

## Highlights

- Completed ranges/lists/repetition implementation including typed struct literals and repetition semantics across assembler, formatter, and LSP surfaces.
- Added explicit VM runtime package sourcing controls (`--opcpu-package` / `OPFORGE_OPCPU_PACKAGE`) and documented VM-only package-source modes.
- Added VM-only build matrix validation to quality gates (`embedded`, `artifact`, `unbundled`, `unbundled+artifact`).
- Hardened LSP concurrent validation behavior to avoid overlay workspace collisions.
- Promoted release process hygiene with quality-gate and release-binary workflow hardening.

## Added

- VM runtime package-source selection and override plumbing for `.opcpu` loading.
- Make targets for VM package-source validation and build/profile combo smoke coverage:
  - `make test-vm-opcpu-modes`
  - `make test-build-profile-matrix`
  - `make test-build-combo-smoke`
- Documentation and examples for ranges/lists/repetition, scoped repetition, and struct literal usage patterns.

## Changed

- VM-only mode now uses the VM runtime/package path as the authoritative instruction pipeline (host instruction pipeline compiled out for VM-only feature combinations).
- Build-profile reporting is aligned across `--help`, `--version`, and listing outputs.
- Module/include discovery paths in VM-only/bootstrap scenarios were corrected for parent-relative resolution.
- README VM rollout status now explicitly includes `motorola6800` (`m6809`, `hd6309`) as authoritative.

## Fixed

- LSP concurrent validation now prevents stale overlay workspace collisions when multiple validation requests overlap.
- VM-only bootstrap/module discovery fallback behavior now resolves deterministic package/runtime expectations.

## Validation

Release validation covers both standard and VM-only combinations:

- `cargo fmt --all --check`
- `cargo clippy -- -D warnings`
- `cargo audit`
- `cargo test --locked`
- `make test-vm-opcpu-modes`
- `make test-build-profile-matrix`
- `make test-build-combo-smoke`

## Upgrade Notes

- No breaking CLI flag removals were introduced.
- VM-only deployments can now choose explicit package source strategy (embedded, artifact, unbundled) with deterministic failure behavior when package requirements are not met.
- For release automation, keep using one release-notes file per tag and do not edit previously tagged release-notes files.
