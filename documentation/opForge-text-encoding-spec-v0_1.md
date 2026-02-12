# opForge Text Encoding Specification (v0.1 Draft)

Date: 2026-02-12

## Summary

This document specifies configurable text encodings for string data in opForge, starting with:

- `ascii`
- `petscii`

The design is inspired by 64tass encoding support, especially `.enc` and text-oriented directives, while staying aligned with opForge's current directive model and "one coherent data directive" direction.

## Goals

- Allow text in data directives (for example `.byte "hello", 0`) to be encoded via a selected encoding.
- Support built-in `ascii` and `petscii`.
- Make adding future encodings straightforward in core code.
- Keep behavior deterministic across the two-pass assembler pipeline.
- Preserve current opForge ergonomics for mixed numeric/string data lists.

## Non-Goals (v0.1)

- Runtime/user-defined encoding files (`.enc file,offset` style from 64tass).
- In-source encoding-definition directives (`.cdef`/`.edef`/`.tdef`) in first release.
- Full Unicode text pipeline.
- Automatic CPU-based default encoding changes.
- Replacing existing numeric data directives.

## 64tass Reference and Takeaways

Reference: [64tass directives](https://tass64.sourceforge.net/#d_enc)

Key relevant behavior in 64tass:

- `.enc` selects active encoding.
- `.enc` accepts an expression (string name or encoding object), not only bare identifiers.
- `.encode` / `.endencode` provide scoped encoding areas and encoding-object creation.
- `.text`/`.null`/`.ptext` are explicit text emit directives with encoding semantics.
- `.byte` string handling is intentionally distinct from text directives.

What opForge should copy:

- A first-class encoding selector directive (`.enc` style behavior).
- Explicit text helper directives are useful for readability and source-porting.
- Scoped encoding override is useful (`.encode`-like), but can be a later phase.

What opForge should *not* copy exactly:

- Splitting `.byte` into "raw string bytes" while `.text` does encoded text.

Reason: opForge already treats `.byte` string operands as core data syntax, and users reasonably expect `.byte "hello"` to honor the current text encoding.

## Proposal: `.byte` vs `.text/.null/.ptext`

### Recommendation

- Keep `.byte`/`.db` as the primary mixed data directives.
- Make string operands in `.byte`/`.db` use the active encoding.
- Add `.text`, `.null`, `.ptext` as convenience directives (not as a separate encoding semantic layer).

### Rationale

- Matches current opForge style: one directive can mix numeric literals and strings.
- Avoids surprising split-brain behavior between `.byte` and `.text`.
- Minimizes migration friction for existing opForge examples that already use `.byte "..."`.
- Still offers 64tass-friendly source readability via optional text directives.

## User-Facing Spec

## 1. Encoding selection directive

### Syntax

```asm
.encoding <name>
.enc <name>        ; alias
```

`<name>` may be identifier or string (case-insensitive).

Notes:

- For 64tass-style compatibility, parser acceptance should allow an expression here, then validate that the resolved value is a known encoding name/object.
- Bare identifiers and quoted names both work.

### Built-ins

- `ascii` (default)
- `petscii`

### Scope

- Encoding state is module-scoped.
- On `.module`, active encoding resets to default (`ascii`).
- Changes persist until changed again or `.endmodule`.
- Directives inside skipped conditional branches do not apply (same behavior as other state-changing directives).

## 2. Data directives

### `.byte` / `.db`

- Numeric operands: unchanged behavior.
- String operands: each byte from the parsed string literal is transformed through the active encoding table before emission.

Example:

```asm
.enc petscii
.byte "hello", 0
```

## 3. Text convenience directives (recommended additions)

### `.text`

Emit encoded text bytes from string operands.

```asm
.text "hello"
```

Equivalent to `.byte "hello"` (string-only form).

### `.null`

Emit encoded text bytes and append `0`.

```asm
.null "hello"      ; emits encoded h,e,l,l,o,0
```

### `.ptext`

Emit 1-byte length prefix followed by encoded text bytes.

```asm
.ptext "hello"     ; emits 5,<encoded bytes...>
```

Rules:

- Length is encoded byte count after text conversion.
- Error if encoded length > 255.

Compatibility note:

- 64tass errors for `.null` when the source text already contains a zero byte.
- opForge follows 64tass strict behavior: `.null` errors when encoded input already contains a zero byte.

## 4. String expressions

Single- and two-character string expressions are encoded with the active encoding before numeric folding:

- one byte string: value = byte
- two byte string: value = `(first << 8) | second` (unchanged word-folding rule)

Errors:

- character not representable in active encoding
- multi-character strings in scalar expression contexts remain errors (existing behavior)

## 5. Diagnostics

New directive/expression diagnostics:

- Unknown encoding name (show known values).
- Character byte not representable in active encoding (include encoding name).
- `.ptext` overflow (>255 encoded bytes).
- `.null` source contains zero byte after encoding.
- Missing operand/invalid operand types for `.encoding`/`.enc`/`.text`/`.null`/`.ptext`.

## 6. Compatibility

- Default encoding is `ascii`, so existing sources remain behaviorally stable unless they switch encoding.
- Numeric-only `.byte`/`.word`/`.long` behavior is unchanged.
- Existing `.byte "ASCII text"` remains byte-identical under default settings.
- Deliberate divergence from 64tass: opForge `.byte` string operands are encoding-aware for all lengths (64tass prefers `.text` for multi-character text).

## Core Architecture Fit

This belongs in assembler core (not CPU family/dialect layers), because it is CPU-agnostic data/literal behavior.

Suggested core component:

- New module: `src/core/text_encoding.rs`

Suggested structures:

- `TextEncodingId` (enum for built-ins + extensible name key)
- `TextEncodingRegistry` (name -> encoder)
- `TextEncoder` trait or table-backed encoder interface
- `encode_bytes(encoding, input) -> Result<Vec<u8>, EncodingError>`

Assembler integration points:

- Store active encoding in `AsmLine` state.
- Parse `.encoding`/`.enc` and update state in `src/assembler/asmline_directives.rs`.
- Apply encoding in `store_arg_list_ast` and string-expression evaluation paths in `src/assembler/mod.rs`.

## Implementation Plan

## Phase 1: Core encoding infrastructure

- Add `src/core/text_encoding.rs`.
- Implement built-in `ascii` and `petscii`.
- Implement registry lookup and encoding errors.
- Add unit tests for mapping and unknown encoding behavior.

## Phase 2: Assembler state + directive wiring

- Add active encoding field(s) to assembler line state in `src/assembler/mod.rs`.
- Reset encoding at module entry, restore at module exit.
- Add `.encoding` + `.enc` handling in `src/assembler/asmline_directives.rs`.
- Validate directive syntax and error messages.

## Phase 3: Apply encoding to emission/evaluation

- Update `.byte`/`.db` string emission path (`store_arg_list_ast`) to encode text bytes.
- Update string-expression folding path (`eval_expr_ast`) to use encoded bytes.
- Ensure no change for numeric operands and non-string expressions.

## Phase 4: Convenience directives

- Add `.text`, `.null`, `.ptext` directives in `src/assembler/asmline_directives.rs`.
- Reuse common encoded-string emission helper.
- Add `.ptext` length overflow validation.

## Phase 5: Tests, examples, docs

- Add assembler tests in `src/assembler/tests.rs` for:
  - `.enc ascii` + `.byte` strings.
  - `.enc petscii` + `.byte` strings.
  - module-scoped encoding reset behavior.
  - expression folding with encoded `'A'`/`"AB"`.
  - unknown encoding and unrepresentable character diagnostics.
  - `.text`/`.null`/`.ptext` behavior.
- Add examples and reference outputs in `examples/` and `examples/reference/`.
- Update manual sections:
  - `documentation/opForge-reference-manual.md` strings + data directives.
  - directive quick-reference tables.

## Suggested rollout order

1. Ship Phase 1-3 first (`.encoding`/`.enc` + `.byte` behavior).
2. Ship Phase 4 (`.text`/`.null`/`.ptext`) as additive compatibility/ergonomics.
3. Then update examples/manual/reference fixtures together.
4. Optional later phase: `.encode` / `.endencode`, then encoding-definition directives.

## Open decisions to confirm before implementation

- Should `ascii` reject bytes `>= 0x80` (strict) or pass through unchanged?
- Should `.ptext` eventually support explicit width variants (`.ptext16`) or stay 8-bit only?
- Should future custom encodings be code-only (Rust registration) or file-defined (64tass-style tables)?
