# Implementation Plan: Generalized Family/CPU Interfaces + Registry

Date: 2026-01-29

## Context Summary (Current State)
- This plan is guided by the architecture reference in [docs/multi-cpu-architecture.md](docs/multi-cpu-architecture.md), which is the leading document for design intent and layering decisions.
- CPU selection is hard-coded in the assembler pipeline with per-family branches in [src/assembler/mod.rs](src/assembler/mod.rs).
- CPU identity, family mapping, and dialect selection are defined as enums in [src/core/cpu.rs](src/core/cpu.rs).
- Family/CPU handler traits exist but are not composed via a registry in [src/core/family.rs](src/core/family.rs).
- Intel 8080 dialect mapping is implemented directly in the family module and used ad-hoc in the assembler in [src/families/intel8080/dialect.rs](src/families/intel8080/dialect.rs).
- MOS 6502 family and CPU extensions are implemented, but are wired manually in [src/families/mos6502](src/families/mos6502) and [src/m65c02](src/m65c02).

## Goals
- Introduce a generalized module registry that binds CPU families, CPUs, and dialects into a single pipeline.
- Standardize family and CPU module interfaces while keeping existing handler traits intact.
- Eliminate hard-coded CPU branching in the assembler in favor of registry-driven selection.
- Make dialect selection explicit and reusable across families.

## Non-Goals
- Redesign instruction tables or operand structures.
- Implement new CPU families beyond those already supported.
- Change listing/hex output formats.

## Proposed Interfaces
The interfaces are intentionally narrow: they **do not expose instruction tables**. They only expose functions for resolving, parsing, and encoding, keeping table formats private to each family/CPU module as described in the leading architecture document [docs/multi-cpu-architecture.md](docs/multi-cpu-architecture.md).

### New Module Traits
Define these in a new registry module (e.g., [src/core/registry.rs](src/core/registry.rs)):

- `FamilyModule`
  - `fn family_id(&self) -> CpuFamily`
  - `fn canonical_dialect(&self) -> &'static str`
  - `fn dialects(&self) -> &'static [Box<dyn DialectModule>]`
  - `fn handler(&self) -> Box<dyn FamilyHandler>` (or a factory closure returning a family handler)

- `CpuModule`
  - `fn cpu_id(&self) -> CpuType`
  - `fn family_id(&self) -> CpuFamily`
  - `fn default_dialect(&self) -> &'static str`
  - `fn handler(&self) -> Box<dyn CpuHandler>` (or factory)
  - `fn validator(&self) -> Option<Box<dyn CpuValidator>>` (optional, can be a stub initially)

- `DialectModule`
  - `fn dialect_id(&self) -> &'static str`
  - `fn family_id(&self) -> CpuFamily`
  - `fn map(&self, mnemonic: &str, operands: &[<FamilyHandler as FamilyHandler>::FamilyOperand]) -> Option<(String, Vec<<FamilyHandler as FamilyHandler>::FamilyOperand>)>`
  - Start with Intel 8080 dialect mapping; provide a transparent dialect that returns the input unchanged.

### Registry
- `ModuleRegistry` maintains:
  - `HashMap<CpuFamily, Box<dyn FamilyModule>>`
  - `HashMap<CpuType, Box<dyn CpuModule>>`
  - `HashMap<(CpuFamily, String), Box<dyn DialectModule>>`
- `fn resolve_pipeline(cpu: CpuType, dialect_override: Option<&str>) -> ResolvedPipeline`
  - Returns instantiated family handler, cpu handler, and dialect module.

## Implementation Plan
### Phase 1: Add Registry Core
- [x] Create [src/core/registry.rs](src/core/registry.rs) with:
  - Trait definitions and `ModuleRegistry` implementation.
  - `ResolvedPipeline` struct containing `family_handler`, `cpu_handler`, and `dialect_module`.
- [x] Re-export registry types from [src/core/mod.rs](src/core/mod.rs).

### Phase 2: Register Existing Families
- [x] Add Intel 8080 family module:
  - New file (e.g., [src/families/intel8080/registry.rs](src/families/intel8080/registry.rs)).
  - Wrap existing `Intel8080FamilyHandler` as a `FamilyModule`.
  - Create dialect modules:
    - `Intel8080Dialect` (identity mapping).
    - `ZilogDialect` (wraps `map_zilog_to_canonical` from [src/families/intel8080/dialect.rs](src/families/intel8080/dialect.rs)).
- [x] Add MOS 6502 family module:
  - New file (e.g., [src/families/mos6502/registry.rs](src/families/mos6502/registry.rs)).
  - Provide a transparent dialect module.

### Phase 3: Register Existing CPUs
- [x] Add CPU modules:
  - 8085 in [src/i8085/registry.rs](src/i8085/registry.rs).
  - Z80 in [src/z80/registry.rs](src/z80/registry.rs).
  - 6502 in [src/families/mos6502/registry.rs](src/families/mos6502/registry.rs) or a new [src/m6502/registry.rs](src/m6502/registry.rs).
  - 65C02 in [src/m65c02/registry.rs](src/m65c02/registry.rs).
- [x] Each CPU module should return its existing handler type and default dialect string.

### Phase 4: Integrate Registry into Assembler
- [x] Add a registry instance to `Assembler` and initialize it in `Assembler::new`.
- [x] Replace the hard-coded branching in `process_instruction_ast` with a registry-driven flow:
  - Fetch `ResolvedPipeline` based on `self.cpu` and optional dialect override.
  - Family parse → dialect mapping → CPU resolve → family encode → CPU encode.
- [x] Replace `CpuType::is_register_fn()` usage in parsing with the family handler’s `is_register()` (or a registry-provided register checker).
- [x] Remove `process_instruction_intel8080` and `process_instruction_6502` once the generic pipeline covers both paths.

### Phase 5: Dialect Selection Rules
- [ ] Implement `dialect_override` in CLI/assembler config (optional; default to CPU module’s dialect).
- [ ] Update `.cpu` directive handling to refresh the pipeline using registry resolution.
- [ ] Ensure a family’s canonical dialect is used when no CPU-specific dialect is provided.

### Phase 6: Validation & Documentation
- [ ] Add minimal `CpuValidator` trait stubs (if needed) and wire in at least one validation step (e.g., addressing mode constraints for 6502).
- [ ] Update [docs/multi-cpu-architecture.md](docs/multi-cpu-architecture.md) to reflect the concrete registry design.

## Acceptance Criteria
- All existing CPUs assemble correctly without any hard-coded CPU branching in the assembler.
- Dialect mapping for Intel 8080 family is handled through a registered dialect module.
- The registry can enumerate all CPUs/families and resolve the correct pipeline for `.cpu` changes.
- Existing examples still pass `make reference-test` after the refactor.

## Risk Notes
- Dialect mapping currently operates on `FamilyOperand`; ensure the registry dialect interface uses the same operand type to avoid rewriting parser logic.
- The parser’s register classification must remain compatible with family register sets, especially for Z80-only registers.

## Suggested Test Runs
- `cargo clippy -- -D warnings`
- `cargo test --lib`
- `make reference-test`
