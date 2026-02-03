# Plan: Implement `.dsection` and `.section`

Date: 2026-02-03

## Goals
- Add minimal, spec-aligned support for `.dsection`, `.section`, and `.endsection`.
- Keep current assembler pipeline (two-pass) working without introducing a full linker.
- Prepare data structures for future relocation and placement work.

## References (core docs)
- Sections & relocation: [docs/NextSteps/core/opforge_sections_and_relocation_v0_2a.md](docs/NextSteps/core/opforge_sections_and_relocation_v0_2a.md)
- Core spec: [docs/NextSteps/core/opforge_core_spec_v0_3b.md](docs/NextSteps/core/opforge_core_spec_v0_3b.md)
- Executable mental model: [docs/NextSteps/core/opforge_executable_mental_model_v0_2b.md](docs/NextSteps/core/opforge_executable_mental_model_v0_2b.md)
- Family/CPU/Dialect packs: [docs/NextSteps/core/opforge_family_cpu_dialect_and_encoding_v0_2b.md](docs/NextSteps/core/opforge_family_cpu_dialect_and_encoding_v0_2b.md)

## Phase 1 — Spec decisions for minimal support
- [x] Keep `.dsection` attribute-free for now.
- [x] Define `.dsection` as both the section declaration and the **injection point** for that section’s emitted bytes.
- [x] Treat `.org`/`.align` as general directives that set the address for whatever follows, including injected `.dsection` output.
- [x] Add `.align` as a general directive (not a `.dsection` attribute), matching 64tass behavior.
- [ ] Define selection semantics:
  - `.dsection <name>` declares section metadata (no emission).
  - `.section <name>` selects current emission target (push stack).
  - `.endsection` restores previous section (pop stack).
- [ ] Define error behavior:
  - `.section` on undeclared section → error.
  - `.endsection` without `.section` → error.
  - Leaving a section open at EOF → error.

## Phase 2 — Data model and state
- [x] Add section metadata struct and registry in assembler core (likely in [src/assembler/mod.rs](src/assembler/mod.rs)):
  - `SectionDecl { name }`.
  - `SectionState { decl, pc: u16, bytes: Vec<u8> }`.
- [x] Track `current_section` and a `section_stack` in `AsmLine`/`Assembler`.
- [x] Add helper to resolve current PC per section for `$` and `.org`.

## Phase 3 — Directive parsing & validation
- [x] Implement `.dsection <name>` (no attributes).
- [x] Implement `.section <name>`/`.endsection` with nesting support.
- [x] Implement `.align <N>` as a general directive (affects the current section’s PC).
- [ ] Emit diagnostics for:
  - unknown/duplicate section declarations,
  - selecting an undeclared section,
  - dangling open section at EOF.

## Phase 4 — Emission changes
- [x] Redirect byte emission to the current section buffer instead of the global `ImageStore`.
- [x] Pass1 should advance section-local PCs and sizes.
- [x] Pass2 should emit to section buffers and then map to `ImageStore`:
  - For Phase 1, inject section bytes at the current address when `.dsection` is encountered.
  - If no `.org` has been set before an injected `.dsection`, emit a diagnostic (“section has no placement”).

## Phase 5 — Listing output
- [x] Update listing to show section context (optional): section name or start.
- [x] Ensure listing addresses reflect section-local PCs or absolute placement (document behavior).

## Phase 6 — Tests & examples
- [ ] Unit tests (in [src/assembler/mod.rs](src/assembler/mod.rs)):
  - `.dsection` declares without emission.
  - `.section` selects, `.endsection` restores.
  - [x] missing `.endsection` errors.
  - `.section` unknown name errors.
- [x] Example(s) and reference outputs in `examples/` and `examples/reference/`.

## Phase 7 — Documentation updates
- [x] Update [docs/NextSteps/core/opforge_core_spec_v0_3b.md](docs/NextSteps/core/opforge_core_spec_v0_3b.md) with concrete `.dsection/.section/.endsection` syntax and current limitations.
- [x] Add a short section in [docs/opForge-reference-manual.md](docs/opForge-reference-manual.md) describing the new directives and constraints.

## Out of scope (future)
- Relocation records and link-time placement.
- Non-fixed placement and region packing.
- `addrspace` and section flags enforcement.
- CPU/dialect-defined section behavior.
