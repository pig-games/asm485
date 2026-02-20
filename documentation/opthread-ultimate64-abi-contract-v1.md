<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# opThread Ultimate64 ABI Contract (v1)

Status: active  
Last updated: 2026-02-17

## 1. Scope

This document defines the host/native ABI boundary for consuming opThread hierarchy packages (`*.opcpu`) in Ultimate64-class constrained runtimes.

Forward note: a CPU/family-independent contract container (`*.opcore`) is planned. `.opcore` follows the same constrained-runtime ABI principles defined here (endianness/width rules, TOC traversal, ownership independence, deterministic error codes), with its own container magic/versioning as specified when introduced.

Goals:
- fixed byte-order and numeric-width rules
- deterministic ownership semantics at load/runtime boundaries
- stable error-code expectations for integration/debug tooling

## 2. Binary Container Contract

### 2.1 Endianness and integer widths

- All integer fields in `*.opcpu` are little-endian.
- `u16` is used for container versioning and endian marker fields.
- `u32` is used for counts, offsets, lengths, and bounded numeric runtime descriptors.

No big-endian variant is defined for v1.

### 2.2 Header layout (12 bytes)

Bytes are fixed as:

1. `0..4`: ASCII magic `OPCP`
2. `4..6`: `version` (`u16`, little-endian), currently `0x0001`
3. `6..8`: `endian_marker` (`u16`, little-endian), fixed marker `0x1234`
4. `8..10`: TOC entry count (`u16`, little-endian)
5. `10..12`: reserved/padding bytes

### 2.3 TOC entry layout (12 bytes per entry)

1. `0..4`: chunk tag (`[u8; 4]`, ASCII)
2. `4..8`: payload offset (`u32`, little-endian)
3. `8..12`: payload length (`u32`, little-endian)

TOC payloads are emitted contiguously (next offset equals previous `offset + length`).

### 2.4 `.opcore` expression-contract payload expectations

When loading `.opcore` for expression services, v1 integrations should expect owner-scoped chunk descriptors with the same precedence model already used by `.opcpu` (`dialect -> cpu -> family`):

- `EXPR`: expression evaluator contract (opcode version + budgets + diagnostic map).
- `EXPP`: expression-parser contract (opcode version + parser-diagnostic map).

`EXPP` is currently compatibility-oriented: it validates parser-side contract/versioning for optional runtime entrypoints while host parser semantics remain the baseline implementation.

## 3. Runtime Ownership Contract

### 3.1 Input package ownership

- Caller owns the raw package byte buffer passed to runtime/model loading.
- Runtime decoding must copy/own all required fields and program bytes.
- After `HierarchyExecutionModel::from_package_bytes(..)` returns success, caller may reuse/free/mutate its original buffer without affecting runtime behavior.

### 3.2 Runtime object ownership

- Runtime-owned decoded contracts/programs are immutable from the native caller perspective.
- Tokenization/parsing/encode operations return fresh value objects and do not expose borrowed pointers into caller-provided package memory.

## 4. Error-Code Expectations

### 4.1 Package decode/validation

- Package codec failures are surfaced as `OPCxxx` category errors (for example bad endian marker).
- These codes identify container/format failures before runtime VM execution.

### 4.2 Runtime contract diagnostics

- Tokenizer VM diagnostic slots use stable codes `ott001..ott006`.
- Parser contract/VM diagnostic slots use stable codes `otp001..otp004`.
- Runtime resolve/mode errors use `OTR001..OTR004` catalog codes where mapped through package diagnostics.
- Expression evaluator contract diagnostics use stable `ope00x` codes (for invalid opcode, stack underflow/depth, unknown symbol, eval failure, unsupported feature, budget exceeded, invalid program).
- Expression parser contract diagnostics (`EXPP`) must map to stable cataloged codes; in v1 this is commonly bridged through the parser namespace (`otp...`) to preserve deterministic envelopes.

## 5. Conformance Expectations for Native Integrators

Native integrations should validate:

1. Header and TOC fields are interpreted strictly little-endian.
2. Chunk payload traversal follows declared TOC offsets/lengths exactly.
3. Runtime does not retain borrowed pointers to caller package buffers.
4. Diagnostic/error handling preserves stable code namespaces (`OPC`, `OTR`, `ott`, `otp`).
5. Expression contract loading preserves deterministic diagnostics for `EXPR`/`EXPP` (`ope...` and cataloged parser-compatible codes).

## 6. Host-Side Conformance Coverage

The Rust host includes ABI-oriented conformance tests for this contract, including:

- little-endian header checks
- contiguous TOC payload layout checks
- diagnostic catalog coverage for parser/tokenizer/runtime code namespaces
- runtime ownership independence after loading from package bytes
- 6502-native harness envelope smoke flow (`load_package -> set_pipeline -> tokenize/parse/encode`)
- fixture-backed failure namespace shakeout through harness boundary (`OPC`, `OTR`, `ott`, `otp`)
- wire-payload smoke flow over byte interfaces (`set_pipeline`, `tokenize_line`, `parse_line`, `encode_instruction`, `last_error`)

Reference C64/VICE host scaffold (opForge assembly) for external-native integration bring-up:
- `examples/opthread/c64/native6502_harness.asm`
