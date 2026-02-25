# opForge v0.9.3 Release Notes

## Scope

This release covers changes after v0.9.2, with a focused delivery around
45GS02 VM/runtime packaging, deterministic VM artifact generation, and
VM-native reference coverage.

## Highlights

- 45GS02 VM hierarchy package support is now productionized:
  - prefixed VM program emission for Q-mode sugar forms (`NEG NEG`)
  - flat-memory `,Z` VM emission path (`NOP` prefix + mapped base opcode flow)
  - selector/runtime support for 45GS02 `IndirectIndexedZ` and
    `DirectPageIndirectLongZ` forms
- Deterministic package artifact workflow added:
  - new binary: `src/bin/build_vm_45gs02_package.rs`
  - new Make target: `build-vm-45gs02-package`
  - artifact path contract: `target/vm/45gs02_hierarchy.opcpu`
- VM coverage and parity expanded for 45GS02:
  - runtime encode coverage for plain, Q-prefix, flat-memory, and relfar behavior
  - VM-focused baseline reference added:
    `examples/vm/reference/m45gs02_vm_baseline.tsv`

## Added

- `examples/vm/reference/m45gs02_vm_baseline.tsv`
- `src/bin/build_vm_45gs02_package.rs`
- VM baseline/reference test for 45GS02 in `src/assembler/tests.rs`

## Changed

- VM builder emits 45GS02-prefixed programs/selectors from registry-driven
  hierarchy generation.
- Runtime selector bridge + selector encoding recognize 45GS02 `,Z` forms.
- Phase plan documentation now marks the VM golden/reference follow-up complete
  for the Phase 12 45GS02 VM package track.

## Validation

Validated with full release gate:

- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo audit`
- `cargo test`

## Upgrade Notes

- Crate version is now `0.9.3`.
- README release-notes link now targets `RELEASE_NOTES_v0.9.3.md`.
