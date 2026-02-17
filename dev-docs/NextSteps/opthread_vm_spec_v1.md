# opThread VM Unified Specification (v1.0)

Status: active canonical spec  
Last updated: 2026-02-17

## 1. Purpose

This document is the single normative specification for opThread VM integration in opForge.  
It defines the architecture boundary, package/runtime contracts, deterministic behavior requirements, and retro-native constraints.

## 2. Scope

### 2.1 In scope
- Hierarchy package (`*.opcpu`) contract for family/cpu/dialect-owned runtime data.
- Tokenizer VM and parser VM contract expectations.
- Runtime resolution precedence and strictness rules.
- VM/host split needed for retro-native portability.
- Deterministic/bounded execution requirements.

### 2.2 Out of scope (for this spec version)
- Full VM replacement of macro/preprocessor/project orchestration.
- Full VM execution of all high-level directives and linker orchestration.
- UI/CLI behavior details unrelated to VM contracts.

## 3. Architecture Boundary (Canonical)

### 3.1 VM-authoritative hot path
- Assembler-owned tokenization.
- Parser VM dispatch for line-level statement envelope parsing.
- Expression parse/eval path used by assembler hot loop (target state in active plan).
- Mode selection and instruction emission via package/runtime VM contracts.

### 3.2 Host-authoritative orchestration path
- Preprocessor and macro expansion orchestration.
- Module/import graph resolution.
- Symbol/lifecycle orchestration not in per-line hot loop.
- Listing/map/output file generation and filesystem interaction.

## 4. Hierarchy and Resolution Contracts

### 4.1 Ownership model
Runtime-resolved data is owner-scoped:
- Family owner
- CPU owner
- Dialect owner

### 4.2 Precedence (normative)
For owner-scoped runtime data, precedence is:
1. `dialect`
2. `cpu`
3. `family`

### 4.3 Active pipeline resolution
CPU + optional dialect override resolves to one active pipeline:
- `family_id`
- `cpu_id`
- `dialect_id`

All tokenizer/parser/encoding lookups are anchored to this resolved pipeline.

## 5. Package Contract (Normative, v1 line)

### 5.1 Required runtime-level capability
Package must contain hierarchy data sufficient to resolve:
- Families (`FAMS`)
- CPUs (`CPUS`)
- Dialects (`DIAL`)
- Forms/selectors/tables for runtime instruction path (`FORM`, `MSEL`, `TABL`)

### 5.2 VM-related chunks
- Token policy hints: `TOKS`
- Tokenizer VM programs: `TKVM`
- Parser contract descriptors: `PARS`
- Parser VM programs: `PRVM`

### 5.3 Version fields (normative)
- Tokenizer VM opcode version field.
- Parser VM opcode version field.
- Parser grammar id and AST schema id in parser contract.

Unknown or mismatched opcode versions are hard errors, not fallback signals.

## 6. Tokenizer Contract

### 6.1 Input/output model
Tokenizer runtime returns portable tokens with explicit spans:
- stable token kind/value mapping
- `line`, `col_start`, `col_end`

### 6.2 Strictness
For authoritative families in assembler-owned paths:
- no implicit host tokenizer fallback
- invalid opcode/program/state/empty-noncomment output are hard errors

### 6.3 Determinism and limits
Tokenizer execution must be bounded and deterministic by configured limits:
- max steps per line
- max tokens per line
- max lexeme bytes
- max errors per line

## 7. Parser Contract

### 7.1 Parser descriptor contract (`PARS`)
Contract includes:
- `grammar_id`
- `ast_schema_id`
- parser opcode version
- max AST nodes per line
- parser diagnostic code map

### 7.2 Parser VM program contract (`PRVM`)
Parser VM program is opcode-versioned and owner-scoped.  
Invalid opcode/program shape is a hard parse error.

### 7.3 Current required opcode behavior
Current parser bridge expects statement-envelope parsing via parser VM program flow.  
Duplicate envelope execution, missing operands for diag opcodes, or missing AST emission are hard errors.

## 8. Expression Contract Direction

Portable AST expression representation exists and must remain contract-stable.  
Active direction is to remove host parser expression parsing from assembler hot path and route expression parse/eval through VM-authoritative contract paths.

## 9. Diagnostics Contract

Diagnostics are package-addressable and deterministic:
- Runtime errors map to stable diagnostic code slots.
- Errors include span information where applicable.
- Runtime contract failures are explicit errors, never silent fallback indicators.

## 10. Retro-Native Requirements

For constrained native targets (including Ultimate64-class environments):
- bounded runtime memory usage on hot paths
- deterministic execution and diagnostics across repeated runs
- explicit ABI-safe payloads with fixed semantics
- no hidden host parser/tokenizer dependencies in VM-authoritative paths

## 11. Compliance Criteria

Implementation is compliant with this spec when:
- assembler hot path is VM-authoritative for tokenizer + parser VM dispatch + encode path
- precedence and strictness rules are enforced
- runtime limits are enforced with deterministic failures
- contracts are versioned and validated at runtime
- host orchestration boundary remains explicit and non-ambiguous

## 12. Supersession

This document supersedes prior fragmented opThread spec documents in `dev-docs/NextSteps`.

